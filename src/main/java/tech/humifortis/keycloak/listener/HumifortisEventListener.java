package tech.humifortis.keycloak.listener;

import java.util.Set;

import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;

import tech.humifortis.keycloak.client.SaasClient;
import tech.humifortis.keycloak.client.SaasConfig;
import tech.humifortis.keycloak.mapper.EventMapper;
import tech.humifortis.keycloak.model.HumifortisEvent;

/**
 * Keycloak event listener that forwards security events to the Humifortis API.
 *
 * <h3>Feedback flow (risk-based authentication)</h3>
 * <p>
 * HumifortisRiskAuthenticator fires a {@link EventType#CUSTOM_REQUIRED_ACTION_ERROR}
 * event with {@code error="humifortis_risk_decision"} immediately after
 * evaluating risk. This listener catches that specific event type+error
 * combination and emits the appropriate Humifortis feedback event.
 *
 * <p>This is more reliable than reading event.getDetails() on the terminal
 * LOGIN/LOGIN_ERROR event because the flow-context EventBuilder is discarded
 * by Keycloak before the terminal event is fired.
 *
 * <h3>Feedback event_type mapping</h3>
 * <ul>
 *   <li>CUSTOM_REQUIRED_ACTION_ERROR + "humifortis_risk_decision" + ACTION=ALLOW → auth_decision_allow</li>
 *   <li>CUSTOM_REQUIRED_ACTION_ERROR + "humifortis_risk_decision" + BLOCKED=true  → auth_decision_block</li>
 *   <li>CUSTOM_REQUIRED_ACTION_ERROR + "humifortis_risk_decision" + other action  → auth_decision_evaluated</li>
 * </ul>
 */
public class HumifortisEventListener implements EventListenerProvider {

    private static final Logger logger =
            Logger.getLogger(HumifortisEventListener.class);

    // Must match HumifortisRiskAuthenticator constants exactly.
    private static final String DETAIL_RISK_ACTION  = "HUMIFORTIS_RISK_ACTION";
    private static final String DETAIL_RISK_SCORE   = "HUMIFORTIS_RISK_SCORE";
    private static final String DETAIL_RISK_LEVEL   = "HUMIFORTIS_RISK_LEVEL";
    private static final String DETAIL_RISK_REASON  = "HUMIFORTIS_RISK_REASON";
    private static final String DETAIL_RISK_BLOCKED = "HUMIFORTIS_RISK_BLOCKED";

    // Sentinel that identifies our risk-decision event among all CUSTOM_REQUIRED_ACTION_ERROR events.
    private static final String RISK_EVENT_ERROR = "humifortis_risk_decision";

    private static final Set<EventType> MONITORED_EVENTS = Set.of(
            EventType.LOGIN,
            EventType.LOGIN_ERROR,
            EventType.LOGOUT,
            EventType.REGISTER,
            EventType.UPDATE_PASSWORD,
            EventType.UPDATE_EMAIL,
            EventType.RESET_PASSWORD,
            EventType.RESET_PASSWORD_ERROR,
            EventType.CODE_TO_TOKEN_ERROR,
            EventType.REFRESH_TOKEN_ERROR,
            EventType.REMOVE_TOTP,
            EventType.UPDATE_TOTP,
            EventType.IMPERSONATE,
            EventType.GRANT_CONSENT,
            EventType.REVOKE_GRANT,
            EventType.DELETE_ACCOUNT
    );

    private final SaasClient  saasClient;
    private final EventMapper eventMapper;

    public HumifortisEventListener() {
        try {
            SaasConfig config = new SaasConfig();
            this.saasClient  = new SaasClient(config);
            this.eventMapper = new EventMapper();
            logger.info("[HumifortisEventListener] Initialized");
        } catch (Exception e) {
            logger.error("[HumifortisEventListener] Failed to initialize", e);
            throw new RuntimeException("Failed to initialize Humifortis Event Listener", e);
        }
    }

    @Override
    public void onEvent(Event event) {
        logger.debugf("[HumifortisEventListener] Received event: type=%s error=%s realm=%s user=%s",
                event.getType(), event.getError(), event.getRealmId(), event.getUserId());

        // ── Path A: risk decision feedback event (fired by authenticator) ────
        if (isRiskDecisionEvent(event)) {
            emitFeedback(event);
            // Do not forward this synthetic event as a standard security event.
            return;
        }

        // ── Path B: standard security event ─────────────────────────────────
        if (MONITORED_EVENTS.contains(event.getType())) {
            try {
                HumifortisEvent humiEvent = eventMapper.fromKeycloakEvent(event);
                sendAsync(humiEvent, event.getType().name());
            } catch (Exception e) {
                logger.errorf("[HumifortisEventListener] Error mapping/sending event %s: %s",
                        event.getType(), e.getMessage());
            }
        } else {
            logger.debugf("[HumifortisEventListener] Skipping unmonitored event: %s",
                    event.getType());
        }
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean includeRepresentation) {
        try {
            HumifortisEvent humiEvent = eventMapper.fromKeycloakAdminEvent(adminEvent);
            sendAsync(humiEvent, "admin:" + adminEvent.getOperationType());
        } catch (Exception e) {
            logger.errorf("[HumifortisEventListener] Error processing admin event: %s",
                    e.getMessage());
        }
    }

    @Override
    public void close() {}

    // ── Feedback path ─────────────────────────────────────────────────────────

    /**
     * Returns true when the event is the dedicated risk-decision event fired
     * by HumifortisRiskAuthenticator — identified by type + error sentinel.
     */
    private boolean isRiskDecisionEvent(Event event) {
        return event.getType() == EventType.CUSTOM_REQUIRED_ACTION_ERROR
                && RISK_EVENT_ERROR.equals(event.getError());
    }

    /**
     * Reads risk details from the event and emits the appropriate Humifortis
     * feedback event. The details are present because HumifortisRiskAuthenticator
     * set them on this exact EventBuilder before calling .error(), which
     * dispatched it synchronously to this listener.
     */
    private void emitFeedback(Event event) {
        try {
            String riskAction = detail(event, DETAIL_RISK_ACTION);
            String riskScore  = detail(event, DETAIL_RISK_SCORE);
            String riskLevel  = detail(event, DETAIL_RISK_LEVEL);
            String riskReason = detail(event, DETAIL_RISK_REASON);
            String blocked    = detail(event, DETAIL_RISK_BLOCKED);

            if (riskAction == null) {
                logger.warnf("[HumifortisEventListener] Risk decision event missing " +
                        "HUMIFORTIS_RISK_ACTION detail — skipping feedback.");
                return;
            }

            String feedbackType = resolveFeedbackType(riskAction, blocked);

            logger.infof("[HumifortisEventListener] Emitting feedback: " +
                            "feedbackType=%s action=%s score=%s level=%s blocked=%s",
                    feedbackType, riskAction, riskScore, riskLevel, blocked);

            HumifortisEvent feedback = eventMapper.fromFeedback(
                    event, feedbackType,
                    riskScore, riskLevel, riskAction, riskReason);
            sendAsync(feedback, feedbackType);

        } catch (Exception e) {
            logger.warnf("[HumifortisEventListener] Error emitting feedback event: %s",
                    e.getMessage());
        }
    }

    /**
     * Maps the risk action + block flag to a Humifortis feedback event_type.
     *
     *   action=ALLOW              → auth_decision_allow
     *   BLOCKED=true              → auth_decision_block
     *   any other action          → auth_decision_evaluated
     */
    private String resolveFeedbackType(String riskAction, String blocked) {
        if ("ALLOW".equalsIgnoreCase(riskAction)) {
            return "auth_decision_allow";
        }
        if ("true".equalsIgnoreCase(blocked)) {
            return "auth_decision_block";
        }
        return "auth_decision_evaluated";
    }

    // ── Shared helpers ────────────────────────────────────────────────────────

    private void sendAsync(HumifortisEvent event, String label) {
        saasClient.sendEventAsync(event)
                .exceptionally(ex -> {
                    logger.warnf("[HumifortisEventListener] Failed to send [%s]: %s",
                            label, ex.getMessage());
                    return null;
                });
    }

    private String detail(Event event, String key) {
        if (event.getDetails() == null) return null;
        String v = event.getDetails().get(key);
        return (v != null && !v.isBlank()) ? v : null;
    }
}
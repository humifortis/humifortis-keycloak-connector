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

public class HumifortisEventListener implements EventListenerProvider {
    private static final Logger logger =
            Logger.getLogger(HumifortisEventListener.class);

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
            logger.info("Humifortis Event Listener initialized");
        } catch (Exception e) {
            logger.error("Failed to initialize Humifortis Event Listener", e);
            throw new RuntimeException(
                    "Failed to initialize Humifortis Event Listener", e);
        }
    }

    @Override
    public void onEvent(Event event) {
        logger.debugf("Event: type=%s realm=%s user=%s",
                event.getType(), event.getRealmId(), event.getUserId());

        if (!MONITORED_EVENTS.contains(event.getType())) {
            logger.debugf("Received unmonitored event: %s", event.getType());
            //return;
        }

        // 1. Send the standard security event
        try {
            HumifortisEvent humiEvent = eventMapper.fromKeycloakEvent(event);
            sendAsync(humiEvent, event.getType().name());
        } catch (Exception e) {
            logger.errorf("Error mapping/sending event %s: %s",
                    event.getType(), e.getMessage());
        }

        // 2. Send feedback event if risk decision data is present
        // Data is written into event details by the authenticator
        // using context.getEvent().detail(key, value) before flow ends.
        try {
            String riskAction = detail(event, "HUMIFORTIS_RISK_ACTION");
            if (riskAction == null) return; // no risk evaluation for this event

            String riskScore  = detail(event, "HUMIFORTIS_RISK_SCORE");
            String riskLevel  = detail(event, "HUMIFORTIS_RISK_LEVEL");
            String riskReason = detail(event, "HUMIFORTIS_RISK_REASON");

            String feedbackType;
            if (event.getType() == EventType.LOGIN) {
                feedbackType = "auth_decision_allow";
            } else if (event.getType() == EventType.LOGIN_ERROR
                    && "access_denied".equals(event.getError())
                    && "true".equalsIgnoreCase(
                            detail(event, "HUMIFORTIS_RISK_BLOCKED"))) {
                feedbackType = "auth_decision_block";
            } else {
                feedbackType = "auth_decision_evaluated";
            }

            HumifortisEvent feedback = eventMapper.fromFeedback(
                    event, feedbackType,
                    riskScore, riskLevel, riskAction, riskReason);
            sendAsync(feedback, feedbackType);

        } catch (Exception e) {
            logger.warnf("Error emitting feedback event: %s", e.getMessage());
        }
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean includeRepresentation) {
        try {
            HumifortisEvent humiEvent =
                    eventMapper.fromKeycloakAdminEvent(adminEvent);
            sendAsync(humiEvent, "admin:" + adminEvent.getOperationType());
        } catch (Exception e) {
            logger.errorf("Error processing admin event: %s", e.getMessage());
        }
    }

    @Override
    public void close() {}

    // ----------------------------------------------------------------
    // Single send path — all event types use this
    // ----------------------------------------------------------------

    private void sendAsync(HumifortisEvent event, String label) {
        saasClient.sendEventAsync(event)
                .exceptionally(ex -> {
                    logger.warnf("Failed to send [%s]: %s",
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
package tech.humifortis.keycloak.listener;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Set;

import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;

import tech.humifortis.keycloak.client.SaasClient;
import tech.humifortis.keycloak.client.SaasConfig;
import tech.humifortis.keycloak.mapper.EventMapper;
import tech.humifortis.keycloak.model.HumifortisEvent;

/**
 * Humifortis Event Listener — LEAN connector.
 *
 * Design principle: extract ONLY what requires Keycloak session access.
 * Heavy computation (GeoIP, UA parsing, device_id) is done server-side
 * in humifortis-core's Enricher.
 *
 * This connector extracts:
 *   - Raw IP address (from HTTP connection)
 *   - Raw User-Agent (from HTTP headers)
 *   - Session ID
 *   - User roles, MFA status, account age (from Keycloak UserModel)
 *   - Active session count
 *   - Identity provider
 *
 * NOT done here (moved to server):
 *   - MaxMind GeoIP lookup
 *   - User-Agent parsing
 *   - device_id computation
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

    private final SaasClient     saasClient;
    private final EventMapper    eventMapper;
    private final KeycloakSession session;

    public HumifortisEventListener(KeycloakSession session) {
        try {
            SaasConfig config = new SaasConfig();
            this.saasClient  = new SaasClient(config);
            this.eventMapper = new EventMapper();
            this.session     = session;
            logger.info("[HumifortisEventListener] Initialized (lean mode — server-side enrichment)");
        } catch (Exception e) {
            logger.error("[HumifortisEventListener] Failed to initialize", e);
            throw new RuntimeException("Failed to initialize Humifortis Event Listener", e);
        }
    }

    // ── Entry points ──────────────────────────────────────────────────────────

    @Override
    public void onEvent(Event event) {
        logger.debugf("[HumifortisEventListener] Received event: type=%s error=%s realm=%s user=%s",
                event.getType(), event.getError(), event.getRealmId(), event.getUserId());

        // Path A: risk decision feedback event (fired by authenticator)
        if (isRiskDecisionEvent(event)) {
            emitFeedback(event);
            return;
        }

        // Path B: standard security event
        if (MONITORED_EVENTS.contains(event.getType())) {
            try {
                enrichEvent(event);
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

    // ══════════════════════════════════════════════════════════════════════════
    // ENRICHMENT — Only extracts data that REQUIRES Keycloak session access.
    // GeoIP, UA parsing, and device_id are handled SERVER-SIDE by humifortis-core.
    // ══════════════════════════════════════════════════════════════════════════

    private void enrichEvent(Event event) {
        if (event.getDetails() == null) return;

        // Step 1 — Raw IP (only accessible here via Keycloak connection)
        try {
            String remoteIp = session.getContext().getConnection().getRemoteAddr();
            if (remoteIp != null && !remoteIp.isBlank()) {
                event.getDetails().put("ip", remoteIp);
            }
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] IP extraction failed: %s", e.getMessage());
        }

        // Step 2 — Raw User-Agent (only accessible here via HTTP headers)
        try {
            String ua = session.getContext().getRequestHeaders().getHeaderString("User-Agent");
            if (ua != null && !ua.isBlank()) {
                event.getDetails().put("user_agent", ua);
            }
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] UA extraction failed: %s", e.getMessage());
        }

        // Step 3 — Session ID
        try {
            String sessionId = event.getSessionId();
            if (sessionId != null && !sessionId.isBlank()) {
                event.getDetails().put("session_id", sessionId);
            }
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] session_id extraction failed: %s", e.getMessage());
        }

        // Step 4 — Account age (requires UserModel)
        try {
            String userId = event.getUserId();
            if (userId != null && !userId.isBlank()) {
                RealmModel realm = session.getContext().getRealm();
                UserModel user = session.users().getUserById(realm, userId);
                if (user != null && user.getCreatedTimestamp() != null) {
                    long ageDays = ChronoUnit.DAYS.between(
                            Instant.ofEpochMilli(user.getCreatedTimestamp()), Instant.now());
                    event.getDetails().put("account_age_days", String.valueOf(ageDays));
                }
            }
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] account_age_days failed: %s", e.getMessage());
        }

        // Step 5 — Roles (requires UserModel + RoleModel)
        try {
            String userId = event.getUserId();
            if (userId != null && !userId.isBlank()) {
                RealmModel realm = session.getContext().getRealm();
                UserModel user = session.users().getUserById(realm, userId);
                if (user != null) {
                    List<String> roleNames = user.getRoleMappingsStream()
                            .map(RoleModel::getName)
                            .toList();
                    if (!roleNames.isEmpty()) {
                        event.getDetails().put("user_roles", String.join(",", roleNames));
                    }
                }
            }
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] roles extraction failed: %s", e.getMessage());
        }

        // Step 6 — MFA enrolled (requires credential manager)
        try {
            String userId = event.getUserId();
            if (userId != null && !userId.isBlank()) {
                RealmModel realm = session.getContext().getRealm();
                UserModel user = session.users().getUserById(realm, userId);
                if (user != null) {
                    boolean hasMfa = user.credentialManager()
                            .getStoredCredentialsStream()
                            .anyMatch(cred -> "otp".equals(cred.getType())
                                    || "webauthn".equals(cred.getType())
                                    || "webauthn-passwordless".equals(cred.getType()));
                    event.getDetails().put("mfa_enrolled", String.valueOf(hasMfa));
                }
            }
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] mfa_enrolled failed: %s", e.getMessage());
        }

        // Step 7 — Active session count (requires session provider)
        try {
            String userId = event.getUserId();
            if (userId != null && !userId.isBlank()) {
                RealmModel realm = session.getContext().getRealm();
                UserModel user = session.users().getUserById(realm, userId);
                if (user != null) {
                    long sessionCount = session.sessions()
                            .getUserSessionsStream(realm, user)
                            .count();
                    event.getDetails().put("active_session_count", String.valueOf(sessionCount));
                }
            }
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] session_count failed: %s", e.getMessage());
        }

        // Step 8 — Identity provider
        try {
            String idp = event.getDetails().get("identity_provider");
            if (idp == null || idp.isBlank()) {
                event.getDetails().put("identity_provider", "local");
            }
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] identity_provider failed: %s", e.getMessage());
        }
    }

    // ── Feedback path ─────────────────────────────────────────────────────────

    private boolean isRiskDecisionEvent(Event event) {
        return event.getType() == EventType.CUSTOM_REQUIRED_ACTION_ERROR
                && RISK_EVENT_ERROR.equals(event.getError());
    }

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

            enrichFeedbackMetadata(feedback, event);
            sendAsync(feedback, feedbackType);

        } catch (Exception e) {
            logger.warnf("[HumifortisEventListener] Error emitting feedback event: %s",
                    e.getMessage());
        }
    }

    private String resolveFeedbackType(String riskAction, String blocked) {
        if ("ALLOW".equalsIgnoreCase(riskAction))
            return "auth_decision_allow";
        if ("true".equalsIgnoreCase(blocked)
                || "DENY".equalsIgnoreCase(riskAction)
                || "LOCK_ACCOUNT".equalsIgnoreCase(riskAction))
            return "auth_decision_block";
        if ("REQUIRE_MFA".equalsIgnoreCase(riskAction)
                || "REQUIRE_WEBAUTHN".equalsIgnoreCase(riskAction)
                || "REQUIRE_EMAIL_OTP".equalsIgnoreCase(riskAction))
            return "auth_decision_mfa";
        return "auth_decision_evaluated";
    }

    private void enrichFeedbackMetadata(HumifortisEvent feedback, Event event) {
        if (event.getDetails() == null) return;
        putDetailIfPresent(feedback, event, "playbook_rule");
        putDetailIfPresent(feedback, event, "enforced_action");
        putDetailIfPresent(feedback, event, "derived_signals");
        putDetailIfPresent(feedback, event, "all_actions");
        putDetailIfPresent(feedback, event, "device_is_new");
        putDetailIfPresent(feedback, event, "device_is_trusted");
        putDetailIfPresent(feedback, event, "risk_score_numeric");
    }

    private void putDetailIfPresent(HumifortisEvent humiEvent, Event event, String key) {
        String value = event.getDetails().get(key);
        if (value != null && !value.isBlank()) {
            humiEvent.addMetadata(key, value);
        }
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
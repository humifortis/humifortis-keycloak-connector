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
import org.keycloak.models.UserSessionModel;

import tech.humifortis.keycloak.client.SaasClient;
import tech.humifortis.keycloak.client.SaasConfig;
import tech.humifortis.keycloak.mapper.EventMapper;
import tech.humifortis.keycloak.model.HumifortisEvent;
import tech.humifortis.keycloak.auth.HumifortisDeviceCollectorAuthenticator;

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
 *   - GeoIP lookup (moved to humifortis-core — raw IP is forwarded as-is)
 *   - User-Agent parsing (moved to humifortis-core)
 *   - device_id computation (handled by HumifortisDeviceCollectorAuthenticator + FingerprintJS)
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

    /**
     * Sentinel stamped by HumifortisRiskAuthenticator when MFA is enforced.
     * Present in event.getDetails() (via context.getEvent().detail()) AND
     * in authSession.getAuthNote() — whichever survives the Keycloak flow variant.
     */
    private static final String DETAIL_MFA_ENFORCED = "HUMIFORTIS_MFA_ENFORCED";

    /**
     * Verified-Unblock challenge id — stamped by HumifortisRiskAuthenticator (dual-source:
     * event detail + auth session note). Echoed into auth_mfa_success so humifortis-core
     * can bind the MFA to the admin-initiated challenge and clear the block.
     */
    private static final String DETAIL_CHALLENGE_ID = "HUMIFORTIS_CHALLENGE_ID";

    // Sentinel that identifies our risk-decision event among all CUSTOM_REQUIRED_ACTION_ERROR events.
    private static final String RISK_EVENT_ERROR = "humifortis_risk_decision";

    /**
     * Session note stamped after the first auth_login_success is emitted for a given user session.
     * Prevents duplicate auth_login_success events when Keycloak fires EventType.LOGIN multiple times
     * within the same SSO session (account-console client + account client = 2 LOGIN events, 1 session).
     */
    private static final String NOTE_LOGIN_EMITTED = "HUMIFORTIS_LOGIN_EMITTED";

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
    /** Set to true when SaasClient/SaasConfig init failed — all onEvent() calls are no-ops. */
    private final boolean        disabled;

    public HumifortisEventListener(KeycloakSession session) {
        this.session = session;
        SaasClient  client  = null;
        EventMapper mapper  = null;
        boolean     isDisabled = false;
        try {
            SaasConfig config = new SaasConfig();
            client  = new SaasClient(config);
            mapper  = new EventMapper();
            logger.info("[HumifortisEventListener] Initialized (lean mode — server-side enrichment)");
        } catch (Exception e) {
            logger.errorf("[HumifortisEventListener] Init failed — listener disabled for this request: %s",
                    e.getMessage());
            isDisabled = true;
        }
        this.saasClient  = client;
        this.eventMapper = mapper;
        this.disabled    = isDisabled;
    }

    // ── Entry points ──────────────────────────────────────────────────────────

    @Override
    public void onEvent(Event event) {
        if (disabled) return;  // init failed — skip silently

        logger.debugf("[HumifortisEventListener] Received event: type=%s error=%s realm=%s user=%s",
                event.getType(), event.getError(), event.getRealmId(), event.getUserId());

        // Path 0: deferred session revocation — safe post-LOGIN timing (session is now fully established)
        if (event.getType() == EventType.LOGIN && event.getSessionId() != null) {
            handleDeferredSessionRevocation(event);
        }

        // Path 0b: deduplicate auth_login_success.
        // Keycloak fires EventType.LOGIN once per client in the same SSO session
        // (e.g., account-console + account = 2 LOGIN events, same sessionId).
        // We stamp a note on the UserSession after the first one; subsequent LOGINs are silent SSO grants.
        if (event.getType() == EventType.LOGIN && event.getSessionId() != null) {
            try {
                RealmModel realm = session.getContext().getRealm();
                if (realm == null) realm = session.realms().getRealm(event.getRealmId());
                if (realm != null) {
                    var userSession = session.sessions().getUserSession(realm, event.getSessionId());
                    if (userSession != null) {
                        if ("true".equals(userSession.getNote(NOTE_LOGIN_EMITTED))) {
                            logger.debugf("[HumifortisEventListener] Skipping duplicate auth_login_success " +
                                    "(session=%s) — SSO silent grant", event.getSessionId());
                            return;
                        }
                        userSession.setNote(NOTE_LOGIN_EMITTED, "true");
                    }
                }
            } catch (Exception e) {
                logger.debugf("[HumifortisEventListener] Login dedup check failed (non-blocking): %s",
                        e.getMessage());
            }
        }

        // Path A: risk decision feedback event (fired by authenticator)
        if (isRiskDecisionEvent(event)) {
            emitFeedback(event);
            return;
        }

        // Path B: standard security event
        if (MONITORED_EVENTS.contains(event.getType())) {
            try {
                enrichEvent(event);

                // MFA interception: when a LOGIN event concludes an MFA-enforced flow,
                // emit auth_mfa_success FIRST (δ=−15) then auth_login_success (δ=0).
                // Dual-source check: event detail (set by authenticator) OR authNote (fallback).
                if (event.getType() == EventType.LOGIN && isMfaEnforced(event)) {
                    String challengeId = resolveChallengeId(event);
                    HumifortisEvent mfaEvent = eventMapper.fromMfaSuccess(event, challengeId);
                    sendAsync(mfaEvent, "auth_mfa_success");
                    logger.debugf("[HumifortisEventListener] Emitted auth_mfa_success before auth_login_success" +
                            " (user=%s flow_id=%s challenge_id=%s)", event.getUserId(), mfaEvent.getFlowId(),
                            challengeId != null ? challengeId : "none");
                }

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
        if (disabled) return;
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

        // Step 3b — flow_id: authentication session identifier (groups all events of one auth attempt).
        // Priority: authSessionId → code_id (OIDC) → sessionId (post-auth fallback).
        // Pulled from the AuthenticationSessionModel when available — more reliable than event details
        // because it is set before the flow completes and survives session transitions.
        try {
            var as = session.getContext().getAuthenticationSession();
            String flowId = null;
            // From auth session (most reliable during an active flow)
            if (as != null) {
                String authSessionParentId = as.getParentSession() != null
                        ? as.getParentSession().getId() : null;
                if (authSessionParentId != null && !authSessionParentId.isBlank()) {
                    flowId = authSessionParentId;
                }
            }
            // Fallback: event details (authSessionId key set by some Keycloak versions)
            if (flowId == null) {
                String fromDetails = event.getDetails().get("authSessionId");
                if (fromDetails != null && !fromDetails.isBlank()) flowId = fromDetails;
            }
            // Fallback: OIDC code_id
            if (flowId == null) {
                String codeId = event.getDetails().get("code_id");
                if (codeId != null && !codeId.isBlank()) flowId = codeId;
            }
            // Fallback: sessionId (post-auth, session already established)
            if (flowId == null && event.getSessionId() != null && !event.getSessionId().isBlank()) {
                flowId = event.getSessionId();
            }
            if (flowId != null) {
                event.getDetails().put("authSessionId", flowId);
            } else {
                logger.warnf("[HumifortisEventListener] flow_id could not be extracted for event type=%s user=%s",
                        event.getType(), event.getUserId());
            }
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] flow_id extraction failed: %s", e.getMessage());
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
                    // Also add email_verified and mfa_methods here for consistency
                    event.getDetails().put("email_verified", String.valueOf(user.isEmailVerified()));
                    List<String> methods = new java.util.ArrayList<>();
                    user.credentialManager().getStoredCredentialsStream().forEach(c -> {
                        switch (c.getType()) {
                            case "otp"                   -> methods.add("TOTP");
                            case "webauthn"              -> methods.add("WEBAUTHN");
                            case "webauthn-passwordless" -> methods.add("WEBAUTHN_PASSWORDLESS");
                        }
                    });
                    if (!methods.isEmpty()) {
                        event.getDetails().put("mfa_methods", String.join(",", methods));
                    }
                } else if (user == null) {
                    logger.debugf("[HumifortisEventListener] account_age_days: user not found for userId=%s", userId);
                } else {
                    logger.debugf("[HumifortisEventListener] account_age_days: createdTimestamp is null for userId=%s", userId);
                }
            }
        } catch (Exception e) {
            logger.warnf("[HumifortisEventListener] account_age_days failed: %s", e.getMessage());
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

        // Step 9 — Device signals (pushed into event details by HumifortisDeviceCollectorAuthenticator
        // via context.getEvent().detail(). If the event was fired post-flow and the detail is missing,
        // we fall back to the AuthNote — which may still be accessible depending on Keycloak version.
        // Each field is evaluated independently — a missing value for one does not block the others.)
        try {
            var as = session.getContext().getAuthenticationSession();
            // STABLE
            mergeDeviceDetail(event, as, "device_id",          HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_ID);
            mergeDeviceDetail(event, as, "device_signals",     HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_SIGNALS);
            // CONTEXTUAL
            mergeDeviceDetail(event, as, "device_tz",          HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_TZ);
            mergeDeviceDetail(event, as, "device_screen",      HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_SCREEN);
            mergeDeviceDetail(event, as, "device_lang",        HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_LANG);
            mergeDeviceDetail(event, as, "device_color_depth", HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_COLOR_DEPTH);
            // HARDWARE
            mergeDeviceDetail(event, as, "device_cpu_cores",   HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_CPU_CORES);
            mergeDeviceDetail(event, as, "device_memory_gb",   HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_MEMORY_GB);
            mergeDeviceDetail(event, as, "device_touch",       HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_TOUCH);
            mergeDeviceDetail(event, as, "device_platform",    HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_PLATFORM);
            mergeDeviceDetail(event, as, "device_connection",  HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_CONNECTION);
            // BEHAVIORAL
            mergeDeviceDetail(event, as, "device_load_ms",     HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_LOAD_MS);
            // v2.2 PASSIVE DISCRIMINATORS
            mergeDeviceDetail(event, as, "device_touch_points",   HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_TOUCH_POINTS);
            mergeDeviceDetail(event, as, "device_orientation",    HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_ORIENTATION);
            mergeDeviceDetail(event, as, "device_hash_perf_ms",   HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_HASH_PERF_MS);
            // v2.3 MATH / FPU
            mergeDeviceDetail(event, as, "device_math_hash",        HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_MATH_HASH);
            mergeDeviceDetail(event, as, "device_fpu_class",        HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_FPU_CLASS);
            mergeDeviceDetail(event, as, "device_math_anomaly",     HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_MATH_ANOMALY);
            mergeDeviceDetail(event, as, "device_math_exec_ms",     HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_MATH_EXEC_MS);
            mergeDeviceDetail(event, as, "device_math_consistency", HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_MATH_CONSISTENCY);
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] device signals enrichment failed: %s", e.getMessage());
        }
    }

    // ── Feedback path ─────────────────────────────────────────────────────────

    private boolean isRiskDecisionEvent(Event event) {
        return event.getType() == EventType.CUSTOM_REQUIRED_ACTION_ERROR
                && RISK_EVENT_ERROR.equals(event.getError());
    }

    /**
     * Returns true when MFA was enforced by the risk engine during this authentication flow.
     *
     * <p>Dual-source check (ordered by reliability):
     * <ol>
     *   <li>event detail — set via {@code context.getEvent().detail()} in HumifortisRiskAuthenticator</li>
     *   <li>auth session note — set via {@code authSession.setAuthNote()} (survives flow transitions)</li>
     * </ol>
     */
    private boolean isMfaEnforced(Event event) {
        // Source 1: event detail (set during authentication, may be present on the LOGIN event)
        if (event.getDetails() != null) {
            String v = event.getDetails().get(DETAIL_MFA_ENFORCED);
            if ("true".equalsIgnoreCase(v)) return true;
        }
        // Source 2: auth session note (more reliable — survives Keycloak MFA sub-flow)
        try {
            var as = session.getContext().getAuthenticationSession();
            if (as != null) {
                String v = as.getAuthNote(DETAIL_MFA_ENFORCED);
                if ("true".equalsIgnoreCase(v)) return true;
            }
        } catch (Exception ignored) {}
        return false;
    }

    /**
     * Resolves the Verified-Unblock challenge id bound to this login (dual-source,
     * mirroring {@link #isMfaEnforced}). Returns null when no admin verification
     * window drove this MFA (i.e. a normal risk-based MFA).
     */
    private String resolveChallengeId(Event event) {
        // Source 1: event detail (stamped on the LOGIN event by the authenticator)
        if (event.getDetails() != null) {
            String v = event.getDetails().get(DETAIL_CHALLENGE_ID);
            if (v != null && !v.isBlank()) return v;
        }
        // Source 2: auth session note (survives the Keycloak MFA sub-flow)
        try {
            var as = session.getContext().getAuthenticationSession();
            if (as != null) {
                String v = as.getAuthNote(DETAIL_CHALLENGE_ID);
                if (v != null && !v.isBlank()) return v;
            }
        } catch (Exception ignored) {}
        return null;
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
        // Risk decision context
        putDetailIfPresent(feedback, event, "playbook_rule");
        putDetailIfPresent(feedback, event, "enforced_action");
        putDetailIfPresent(feedback, event, "derived_signals");
        putDetailIfPresent(feedback, event, "all_actions");
        putDetailIfPresent(feedback, event, "device_is_new");
        putDetailIfPresent(feedback, event, "device_is_trusted");
        putDetailIfPresent(feedback, event, "risk_score_numeric");
        // Full device context — server correlates risk decisions with device fingerprints
        // STABLE
        putDetailIfPresent(feedback, event, "device_id");
        // CONTEXTUAL
        putDetailIfPresent(feedback, event, "device_tz");
        putDetailIfPresent(feedback, event, "device_screen");
        putDetailIfPresent(feedback, event, "device_lang");
        putDetailIfPresent(feedback, event, "device_color_depth");
        // HARDWARE
        putDetailIfPresent(feedback, event, "device_cpu_cores");
        putDetailIfPresent(feedback, event, "device_memory_gb");
        putDetailIfPresent(feedback, event, "device_touch");
        putDetailIfPresent(feedback, event, "device_platform");
        putDetailIfPresent(feedback, event, "device_connection");
        // BEHAVIORAL
        putDetailIfPresent(feedback, event, "device_load_ms");
        // v2.3 Math/FPU
        putDetailIfPresent(feedback, event, "device_math_hash");
        putDetailIfPresent(feedback, event, "device_fpu_class");
        putDetailIfPresent(feedback, event, "device_math_anomaly");
        putDetailIfPresent(feedback, event, "device_math_exec_ms");
        putDetailIfPresent(feedback, event, "device_math_consistency");
        // IDENTITY — account age, email verification, MFA methods
        // These require UserModel lookup — not available in event.getDetails() for feedback events
        try {
            String userId = event.getUserId();
            if (userId != null && !userId.isBlank()) {
                RealmModel realm = session.getContext().getRealm();
                UserModel user = session.users().getUserById(realm, userId);
                if (user != null) {
                    // account_age_days
                    if (user.getCreatedTimestamp() != null) {
                        long ageDays = java.time.temporal.ChronoUnit.DAYS.between(
                                java.time.Instant.ofEpochMilli(user.getCreatedTimestamp()),
                                java.time.Instant.now());
                        feedback.addMetadata("account_age_days", String.valueOf(ageDays));
                    }
                    // email_verified
                    feedback.addMetadata("email_verified", String.valueOf(user.isEmailVerified()));
                    // mfa_methods — comma-separated enrolled methods
                    java.util.List<String> methods = new java.util.ArrayList<>();
                    user.credentialManager().getStoredCredentialsStream().forEach(c -> {
                        switch (c.getType()) {
                            case "otp"                   -> methods.add("TOTP");
                            case "webauthn"              -> methods.add("WEBAUTHN");
                            case "webauthn-passwordless" -> methods.add("WEBAUTHN_PASSWORDLESS");
                        }
                    });
                    if (!methods.isEmpty()) {
                        feedback.addMetadata("mfa_methods", String.join(",", methods));
                    }
                }
            }
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] identity enrichment in feedback failed: %s",
                    e.getMessage());
        }
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

    /** Copies an AuthNote value into the event details map if the note is present and non-blank. */
    private void putAuthNote(Event event,
                             org.keycloak.sessions.AuthenticationSessionModel as,
                             String noteKey, String detailKey) {
        try {
            String value = as.getAuthNote(noteKey);
            if (value != null && !value.isBlank()) {
                event.getDetails().put(detailKey, value);
            }
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] putAuthNote(%s) failed: %s", noteKey, e.getMessage());
        }
    }

    /**
     * Merges a device signal into event details.
     * Priority: event detail (set by DeviceCollector during the flow) → AuthNote fallback.
     * Each field is evaluated independently so a missing detail for one field
     * does not prevent other fields from being populated.
     */
    private void mergeDeviceDetail(Event event,
                                   org.keycloak.sessions.AuthenticationSessionModel as,
                                   String detailKey, String noteKey) {
        try {
            String existing = event.getDetails().get(detailKey);
            if (existing != null && !existing.isBlank()) return; // already present from DeviceCollector
            if (as == null) return;
            String fromNote = as.getAuthNote(noteKey);
            if (fromNote != null && !fromNote.isBlank()) {
                event.getDetails().put(detailKey, fromNote);
            }
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] mergeDeviceDetail(%s) failed: %s", detailKey, e.getMessage());
        }
    }

    // ── Deferred session revocation ────────────────────────────────────────────

    /**
     * Handles REVOKE_OTHER_SESSIONS that was deferred from the authenticator via
     * {@code AuthenticationSessionModel.setUserSessionNote("HUMIFORTIS_REVOKE_SESSIONS","true")}.
     *
     * <p>Called on LOGIN event — the new user session is fully established and its ID is known,
     * so we can correctly exclude it while revoking all other (older) sessions.
     */
    private void handleDeferredSessionRevocation(Event event) {
        try {
            String sessionId = event.getSessionId();
            String realmId   = event.getRealmId();
            if (sessionId == null || realmId == null) return;

            RealmModel realm = session.realms().getRealm(realmId);
            if (realm == null) return;

            UserSessionModel currentSession = session.sessions().getUserSession(realm, sessionId);
            if (currentSession == null) return;

            String flag = currentSession.getNote("HUMIFORTIS_REVOKE_SESSIONS");
            if (!"true".equals(flag)) return;

            // Clear flag first — idempotency
            currentSession.removeNote("HUMIFORTIS_REVOKE_SESSIONS");

            String userId = event.getUserId();
            if (userId == null) return;
            UserModel user = session.users().getUserById(realm, userId);
            if (user == null) return;

            long count = session.sessions().getUserSessionsStream(realm, user)
                    .filter(s -> !s.getId().equals(sessionId))
                    .peek(s -> {
                        session.sessions().removeUserSession(realm, s);
                        logger.debugf("[HumifortisEventListener] Revoked old session %s for user=%s",
                                s.getId(), user.getUsername());
                    })
                    .count();

            if (count > 0) {
                logger.infof("[HumifortisEventListener] REVOKE_OTHER_SESSIONS: revoked %d old session(s) " +
                        "for user=%s, kept new session=%s", count, user.getUsername(), sessionId);
            }
        } catch (Exception e) {
            logger.warnf("[HumifortisEventListener] handleDeferredSessionRevocation failed (non-blocking): %s",
                    e.getMessage());
        }
    }
}

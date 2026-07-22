package tech.humifortis.keycloak.mapper;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;

import tech.humifortis.keycloak.model.HumifortisEvent;

public class EventMapper {

    // ----------------------------------------------------------------
    // User event → HumifortisEvent
    // ----------------------------------------------------------------

    public HumifortisEvent fromKeycloakEvent(Event event) {
        HumifortisEvent humiEvent = new HumifortisEvent();

        String realmId = event.getRealmId() != null ? event.getRealmId() : "unknown";
        String userId  = event.getUserId()  != null ? event.getUserId()  : detailOrFallback(event.getDetails(), "userId", null);
        if (userId == null || userId.isBlank()) {
            userId = detailOrFallback(event.getDetails(), "username", "anonymous");
        }
        humiEvent.setEntityId(String.format("user:keycloak:%s:%s", realmId, userId));
        humiEvent.setEntityType("user");
        humiEvent.setTimestamp(Instant.ofEpochMilli(event.getTime()).toString());
        humiEvent.setEventType(mapEventType(event.getType()));
        humiEvent.setSource("keycloak");
        // Propagate Keycloak's native event UUID — used by core for idempotent deduplication.
        if (event.getId() != null) {
            humiEvent.setEventId(event.getId());
        }

        addCommonMetadata(humiEvent, realmId, event.getClientId(),
                event.getIpAddress(), event.getSessionId(), event.getError());
        addContextMetadata(humiEvent, event.getDetails());

        // flow_id — mandatory for auth events (groups all events of one authentication attempt).
        // Priority: authSessionId → code_id (OIDC) → sessionId (post-auth fallback)
        String flowId = extractFlowId(event.getDetails(), event.getSessionId());
        humiEvent.setFlowId(flowId);

        return humiEvent;
    }

    // ----------------------------------------------------------------
    // Admin event → HumifortisEvent
    // ----------------------------------------------------------------

    public HumifortisEvent fromKeycloakAdminEvent(AdminEvent adminEvent) {
        HumifortisEvent humiEvent = new HumifortisEvent();

        String realmId = adminEvent.getRealmId() != null ? adminEvent.getRealmId() : "unknown";
        String adminId = adminEvent.getAuthDetails() != null
            && adminEvent.getAuthDetails().getUserId() != null
            ? adminEvent.getAuthDetails().getUserId()
            : "admin";

        humiEvent.setEntityId(String.format("user:keycloak:%s:%s", realmId, adminId));
        humiEvent.setEntityType("user");
        humiEvent.setTimestamp(Instant.ofEpochMilli(adminEvent.getTime()).toString());
        humiEvent.setSource("keycloak-admin");

        // Triage event_type from resource_type + operation + path
        String resourceType = adminEvent.getResourceType() != null
                ? adminEvent.getResourceType().name() : "UNKNOWN";
        String resourcePath = adminEvent.getResourcePath() != null
                ? adminEvent.getResourcePath() : "";
        OperationType op = adminEvent.getOperationType();

        humiEvent.setEventType(mapAdminEventType(resourceType, op, resourcePath));

        // Propagate Keycloak's native admin event UUID.
        if (adminEvent.getId() != null) {
            humiEvent.setEventId(adminEvent.getId());
        }

        // resource block: what was touched
        humiEvent.addResource("resource_type", resourceType);
        humiEvent.addResource("operation",     op != null ? op.name() : "UNKNOWN");
        humiEvent.addResource("resource_path", resourcePath);

        // admin identity context
        if (adminEvent.getAuthDetails() != null) {
            String clientId  = adminEvent.getAuthDetails().getClientId();
            String ipAddress = adminEvent.getAuthDetails().getIpAddress();
            addCommonMetadata(humiEvent, realmId, clientId, ipAddress, null,
                    adminEvent.getError());
        } else {
            humiEvent.addMetadata("realm", realmId);
        }

        if (adminEvent.getError() != null) {
            humiEvent.addMetadata("error", adminEvent.getError());
        }

        return humiEvent;
    }

    // ----------------------------------------------------------------
    // Feedback event → HumifortisEvent
    // Same data model contract as all other events.
    // ----------------------------------------------------------------

    /**
     * Synthetic auth_mfa_success event derived from a LOGIN event where MFA was enforced.
     *
     * <p>Emitted BEFORE auth_login_success so the MFA score delta (−15) is applied first.
     * auth_login_success has delta=0, so order is score-safe regardless.
     *
     * <p>The event_id is a stable UUID v3 derived from the login event ID so retries
     * never produce duplicates in humifortis-core.
     *
     * @param loginEvent the Keycloak LOGIN event that concluded the MFA flow
     * @param challengeId optional Verified-Unblock challenge id to bind this MFA to
     *                    (null/blank for a normal risk-based MFA)
     */
    public HumifortisEvent fromMfaSuccess(Event loginEvent, String challengeId) {
        HumifortisEvent e = new HumifortisEvent();

        String realmId = loginEvent.getRealmId() != null ? loginEvent.getRealmId() : "unknown";
        String userId  = loginEvent.getUserId() != null
                ? loginEvent.getUserId()
                : detailOrFallback(loginEvent.getDetails(), "userId", "anonymous");

        e.setEntityId(String.format("user:keycloak:%s:%s", realmId, userId));
        e.setEntityType("user");
        e.setTimestamp(Instant.ofEpochMilli(loginEvent.getTime()).toString());
        e.setEventType("auth_mfa_success");
        e.setSource("keycloak-rba");

        // Stable deterministic UUID — same login event always yields the same mfa_success ID.
        if (loginEvent.getId() != null) {
            e.setEventId(UUID.nameUUIDFromBytes(
                    (loginEvent.getId() + ":auth_mfa_success").getBytes()
            ).toString());
        }

        // flow_id — must match the login event so both events stay in the same flow group.
        String flowId = extractFlowId(loginEvent.getDetails(), loginEvent.getSessionId());
        e.setFlowId(flowId);

        addCommonMetadata(e, realmId, loginEvent.getClientId(),
                loginEvent.getIpAddress(), loginEvent.getSessionId(), null);
        addContextMetadata(e, loginEvent.getDetails());

        // Verified-Unblock binding: echo the challenge id + a fresh MFA timestamp so
        // humifortis-core can (a) match challenge_id and (b) verify mfa_ts > challenge_created_at
        // before clearing the block. Both are required for a challenge-bound unblock.
        String mfaTimestamp = Instant.ofEpochMilli(loginEvent.getTime()).toString();
        e.addMetadata("mfa_timestamp", mfaTimestamp);
        if (challengeId != null && !challengeId.isBlank()) {
            e.addMetadata("challenge_id", challengeId);
        }

        return e;
    }

    /** Backward-compatible overload — normal risk-based MFA with no challenge binding. */
    public HumifortisEvent fromMfaSuccess(Event loginEvent) {
        return fromMfaSuccess(loginEvent, null);
    }

    // ----------------------------------------------------------------
    // Feedback event → HumifortisEvent

    public HumifortisEvent fromFeedback(
            Event originEvent,
            String feedbackEventType,
            String riskScore,
            String riskLevel,
            String riskAction,
            String riskReason) {

        HumifortisEvent humiEvent = new HumifortisEvent();

        String realmId = originEvent.getRealmId() != null
                ? originEvent.getRealmId() : "unknown";
        // Prefer userId; fallback to username only if userId is missing
        String userId = originEvent.getUserId();
        if (userId == null || userId.isBlank()) {
            userId = detailOrFallback(originEvent.getDetails(), "userId", null);
        }
        if (userId == null || userId.isBlank()) {
            userId = detailOrFallback(originEvent.getDetails(), "username", "anonymous");
        }

        humiEvent.setEntityId(
            String.format("user:keycloak:%s:%s", realmId, userId));
        humiEvent.setEntityType("user");
        humiEvent.setTimestamp(
                Instant.ofEpochMilli(originEvent.getTime()).toString());
        humiEvent.setEventType(feedbackEventType);
        humiEvent.setSource("keycloak-rba");
        // Feedback events are synthetic (created by the connector, not directly by Keycloak),
        // so we derive a stable UUID v3 from the origin event ID + feedback type.
        // Same input → same UUID → safe to retry without double-processing.
        if (originEvent.getId() != null) {
            String feedbackId = UUID.nameUUIDFromBytes(
                (originEvent.getId() + ":" + feedbackEventType).getBytes()
            ).toString();
            humiEvent.setEventId(feedbackId);
        }

        addCommonMetadata(humiEvent, realmId, originEvent.getClientId(),
                originEvent.getIpAddress(), originEvent.getSessionId(), null);
        addContextMetadata(humiEvent, originEvent.getDetails());

        // flow_id — propagate from origin event so feedback stays in the same flow group
        String flowId = extractFlowId(originEvent.getDetails(), originEvent.getSessionId());
        humiEvent.setFlowId(flowId);

        // Risk decision context
        humiEvent.addMetadata("risk_score",  riskScore);
        humiEvent.addMetadata("risk_level",  riskLevel);
        humiEvent.addMetadata("risk_action", riskAction);
        humiEvent.addMetadata("risk_reason", riskReason);
        humiEvent.addMetadata("origin_keycloak_event",
                originEvent.getType() != null
                        ? originEvent.getType().name() : "UNKNOWN");

        return humiEvent;
    }

    // ----------------------------------------------------------------
    // Admin event type triage
    // ----------------------------------------------------------------

    private String mapAdminEventType(
            String resourceType, OperationType op, String path) {

        String p = path.toLowerCase();
        String o = op != null ? op.name() : "";

        return switch (resourceType) {
            case "USER" -> {
                if (p.contains("reset-password"))     yield "reset_password";
                if (p.contains("impersonation"))      yield "impersonate";
                if (p.contains("credentials") && "DELETE".equals(o)) yield "mfa_token_deleted";
                if (p.contains("credentials"))        yield "mfa_token_enrolled";
                if (p.contains("role-mappings") && "CREATE".equals(o)) yield "role_assigned";
                if (p.contains("role-mappings") && "DELETE".equals(o)) yield "role_revoked";
                if (p.contains("sessions")  && "DELETE".equals(o))     yield "session_clean_logout";
                if ("DELETE".equals(o))               yield "delete_account";
                if ("UPDATE".equals(o))               yield "update_credential";
                yield "admin_user_action";
            }
            case "CLIENT" -> {
                if ("CREATE".equals(o)) yield "grant_consent";
                yield "admin_client_action";
            }
            case "REALM"               -> "realm_modified";
            case "AUTHENTICATION_FLOW" -> "auth_flow_modified";
            case "IDENTITY_PROVIDER"   -> "idp_modified";
            default -> "admin_" + o.toLowerCase() + "_" + resourceType.toLowerCase();
        };
    }

    // ----------------------------------------------------------------
    // User event type mapping
    // ----------------------------------------------------------------

    private String mapEventType(EventType eventType) {
        return switch (eventType) {
            case LOGIN                  -> "auth_login_success";
            case LOGIN_ERROR            -> "auth_login_failed";
            case LOGOUT                 -> "session_clean_logout";
            case REGISTER               -> "auth_register";
            case UPDATE_PASSWORD        -> "update_credential";
            case UPDATE_EMAIL           -> "update_email";
            case VERIFY_EMAIL           -> "auth_email_verify";
            case RESET_PASSWORD         -> "reset_password";
            case RESET_PASSWORD_ERROR   -> "reset_password_error";
            case CODE_TO_TOKEN          -> "auth_token_exchange";
            case CODE_TO_TOKEN_ERROR    -> "auth_token_exchange_failed";
            case REFRESH_TOKEN          -> "auth_token_refresh";
            case REFRESH_TOKEN_ERROR    -> "auth_token_refresh_failed";
            case INTROSPECT_TOKEN       -> "auth_token_introspect";
            case INTROSPECT_TOKEN_ERROR -> "auth_token_introspect_failed";
            case REVOKE_GRANT           -> "revoke_grant";
            case UPDATE_TOTP            -> "mfa_token_enrolled";
            case REMOVE_TOTP            -> "mfa_token_deleted";
            case SEND_VERIFY_EMAIL      -> "auth_verify_email_sent";
            case SEND_RESET_PASSWORD    -> "auth_reset_password_sent";
            case DELETE_ACCOUNT         -> "delete_account";
            case IMPERSONATE            -> "impersonate";
            case GRANT_CONSENT          -> "grant_consent";
            case REVOKE_GRANT_ERROR     -> "revoke_grant_error";
            default -> "auth_" + eventType.name().toLowerCase();
        };
    }

    // ----------------------------------------------------------------
    // Shared helpers
    // ----------------------------------------------------------------

    private void addCommonMetadata(
            HumifortisEvent humiEvent,
            String realm,
            String clientId,
            String ipAddress,
            String sessionId,
            String error) {

        humiEvent.addMetadata("realm", realm);
        if (clientId   != null) humiEvent.addMetadata("client_id",  clientId);
        if (ipAddress  != null) humiEvent.addMetadata("ip",         ipAddress);
        if (sessionId  != null) humiEvent.addMetadata("session_id", sessionId);
        if (error      != null) humiEvent.addMetadata("error",      error);
    }

    private void addContextMetadata(
            HumifortisEvent humiEvent,
            Map<String, String> details) {

        if (details == null || details.isEmpty()) return;

        // Identity context
        putIfPresent(humiEvent, details, "username");
        putIfPresent(humiEvent, details, "email");

        // Network/device context
        putIfPresent(humiEvent, details, "user_agent");
        putIfPresent(humiEvent, details, "remember_me");

        // Device fingerprint — collected by HumifortisDeviceCollectorAuthenticator
        // device_signals (raw JSON) is intentionally excluded here: too large for the event payload,
        // it is sent directly to /evaluate by HumifortisRiskEvaluator.
        putIfPresent(humiEvent, details, "device_id");
        putIfPresent(humiEvent, details, "device_tz");
        putIfPresent(humiEvent, details, "device_screen");
        putIfPresent(humiEvent, details, "device_lang");
        putIfPresent(humiEvent, details, "device_color_depth");
        putIfPresent(humiEvent, details, "device_cpu_cores");
        putIfPresent(humiEvent, details, "device_memory_gb");
        putIfPresent(humiEvent, details, "device_touch");
        putIfPresent(humiEvent, details, "device_platform");
        putIfPresent(humiEvent, details, "device_connection");
        putIfPresent(humiEvent, details, "device_load_ms");

        // GeoIP fields — resolved server-side by humifortis-core (raw IP forwarded as-is by connector)
        // Normalize: accept both "country" and "geo_country" from different integrations
        if (!details.containsKey("geo_country") && details.containsKey("country")) {
            String c = details.get("country");
            if (c != null && !c.isBlank()) {
                humiEvent.addMetadata("geo_country", c);
            }
        }
        putIfPresent(humiEvent, details, "geo_country");
        putIfPresent(humiEvent, details, "geo_city");
        putIfPresent(humiEvent, details, "geo_lat");
        putIfPresent(humiEvent, details, "geo_lon");
        putIfPresent(humiEvent, details, "asn");
        putIfPresent(humiEvent, details, "asn_org");

        // Client/redirect context — useful for OAuth abuse detection
        putIfPresent(humiEvent, details, "redirect_uri");
        putIfPresent(humiEvent, details, "response_type");

        // Auth method context
        putIfPresent(humiEvent, details, "auth_method");
        putIfPresent(humiEvent, details, "auth_type");

        // Credential type (for MFA events)
        putIfPresent(humiEvent, details, "credential_type");

        // Account age — critical for new_account_new_device scoring
        putIfPresent(humiEvent, details, "account_age_days");

        // Email verification — required for EMAIL_OTP safety (unverified email is attackable)
        putIfPresent(humiEvent, details, "email_verified");

        // MFA methods — enrolled methods comma-separated (TOTP, WEBAUTHN, WEBAUTHN_PASSWORDLESS)
        putIfPresent(humiEvent, details, "mfa_methods");

        // Privilege context — critical for off_hours_privileged detection
        putIfPresent(humiEvent, details, "is_privileged");

        // User roles — full list for granular scoring (comma-separated)
        putIfPresent(humiEvent, details, "user_roles");

        // Session concurrency — multiple parallel sessions = risk indicator
        putIfPresent(humiEvent, details, "active_session_count");

        // MFA enrollment status — password-only users are higher risk
        putIfPresent(humiEvent, details, "mfa_enrolled");

        // Identity provider — federated vs local login context
        putIfPresent(humiEvent, details, "identity_provider");

        // FP hash — SHA-256 of full FP components JSON, cross-login drift detection
        putIfPresent(humiEvent, details, "device_fp_hash");

        // Anti-replay binding result: valid | stale | mismatch | absent | error (server-validated)
        putIfPresent(humiEvent, details, "device_binding_result");

        // GPU — hard to spoof, strong device class signal (T2/T3)
        putIfPresent(humiEvent, details, "device_webgl_vendor");
        putIfPresent(humiEvent, details, "device_webgl_renderer");

        // v2.2 passive discriminators
        putIfPresent(humiEvent, details, "device_touch_points");
        putIfPresent(humiEvent, details, "device_orientation");
        putIfPresent(humiEvent, details, "device_hash_perf_ms");

        // v2.3 Math/FPU fingerprint — anti-VM, anti-spoof signals
        putIfPresent(humiEvent, details, "device_math_hash");
        putIfPresent(humiEvent, details, "device_fpu_class");
        putIfPresent(humiEvent, details, "device_math_anomaly");
        putIfPresent(humiEvent, details, "device_math_exec_ms");
        putIfPresent(humiEvent, details, "device_math_consistency");
    }

    private void putIfPresent(
            HumifortisEvent humiEvent,
            Map<String, String> details,
            String key) {
        String value = details.get(key);
        if (value != null && !value.isBlank()) {
            humiEvent.addMetadata(key, value);
        }
    }

    private String detailOrFallback(
            Map<String, String> details,
            String key,
            String fallback) {
        if (details == null) return fallback;
        String value = details.get(key);
        return (value != null && !value.isBlank()) ? value : fallback;
    }

    /**
     * Extracts the flow_id that groups all events of one authentication attempt.
     *
     * Priority order (most stable first):
     *   1. authSessionId  — Keycloak auth session, present during the full auth flow
     *   2. code_id        — OIDC authorization code flows (same session, different key)
     *   3. sessionId      — post-auth fallback (session already established)
     *
     * Returns null only when all sources are missing (admin events, synthetic events).
     */
    private String extractFlowId(Map<String, String> details, String sessionId) {
        if (details != null) {
            String authSessionId = details.get("authSessionId");
            if (authSessionId != null && !authSessionId.isBlank()) return authSessionId;

            String codeId = details.get("code_id");
            if (codeId != null && !codeId.isBlank()) return codeId;
        }
        if (sessionId != null && !sessionId.isBlank()) return sessionId;
        return null;
    }
}

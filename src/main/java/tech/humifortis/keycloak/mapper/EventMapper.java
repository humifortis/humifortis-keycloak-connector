package tech.humifortis.keycloak.mapper;

import java.time.Instant;
import java.util.Map;

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

        addCommonMetadata(humiEvent, realmId, event.getClientId(),
                event.getIpAddress(), event.getSessionId(), event.getError());
        addContextMetadata(humiEvent, event.getDetails());

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

        addCommonMetadata(humiEvent, realmId, originEvent.getClientId(),
                originEvent.getIpAddress(), originEvent.getSessionId(), null);
        addContextMetadata(humiEvent, originEvent.getDetails());

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

        // Device fingerprint — injected by FingerprintJS in login.ftl
        putIfPresent(humiEvent, details, "device_id");

        // GeoIP fields — enriched by HumifortisEventListener via MaxMind
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
}

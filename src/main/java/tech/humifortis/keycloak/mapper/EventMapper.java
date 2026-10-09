package tech.humifortis.keycloak.mapper;

import tech.humifortis.keycloak.auth.DeviceSignals;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;

import tech.humifortis.keycloak.model.HumifortisEvent;
import tech.humifortis.keycloak.serviceaccount.AdminChange;
import tech.humifortis.keycloak.serviceaccount.AdminIdentityResolver;
import tech.humifortis.keycloak.serviceaccount.ServiceAccountContext;

public class EventMapper {

    // ----------------------------------------------------------------
    // User event → HumifortisEvent
    // ----------------------------------------------------------------

    public HumifortisEvent fromKeycloakEvent(Event event) {
        HumifortisEvent humiEvent = new HumifortisEvent();

        String realmId = event.getRealmId() != null ? event.getRealmId() : "unknown";
        boolean serviceAccount = ServiceAccountContext.isClientCredentialsEvent(event.getType());
        if (serviceAccount) {
            // A client authenticating with its own credentials is a service account, not a person:
            // the entity type is stated here, never inferred downstream. The client id identifies it
            // (a failed login has no user id, and the id is what an operator recognises).
            String clientId = event.getClientId() != null && !event.getClientId().isBlank() ? event.getClientId() : "unknown";
            humiEvent.setEntityId(String.format("service_account:keycloak:%s:%s", realmId, clientId));
            humiEvent.setEntityType("service_account");
        } else {
            String userId  = event.getUserId()  != null ? event.getUserId()  : detailOrFallback(event.getDetails(), "userId", null);
            if (userId == null || userId.isBlank()) {
                userId = detailOrFallback(event.getDetails(), "username", "anonymous");
            }
            humiEvent.setEntityId(String.format("user:keycloak:%s:%s", realmId, userId));
            humiEvent.setEntityType("user");
        }
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
        if (serviceAccount) {
            addServiceAccountMetadata(humiEvent, event.getDetails());
        }

        // flow_id — mandatory for auth events (groups all events of one authentication attempt).
        // Priority: authSessionId → code_id (OIDC) → sessionId (post-auth fallback)
        String flowId = extractFlowId(event.getDetails(), event.getSessionId());
        if (flowId == null && serviceAccount) {
            // a client_credentials request has no browser flow and often no session: one request is one flow
            flowId = serviceAccountFlowId(event);
        }
        humiEvent.setFlowId(flowId);

        return humiEvent;
    }

    // ----------------------------------------------------------------
    // Admin event → HumifortisEvent
    // ----------------------------------------------------------------

    public HumifortisEvent fromKeycloakAdminEvent(AdminEvent adminEvent) {
        return fromKeycloakAdminEvent(adminEvent, AdminIdentityResolver.NONE);
    }

    /**
     * @param resolver read-only view of Keycloak used to recognise service accounts as the actor or
     *                 the target of the change; never throws and answers "unknown" when it cannot tell
     */
    public HumifortisEvent fromKeycloakAdminEvent(AdminEvent adminEvent, AdminIdentityResolver resolver) {
        HumifortisEvent humiEvent = new HumifortisEvent();

        String realmId = adminEvent.getRealmId() != null ? adminEvent.getRealmId() : "unknown";
        String adminId = adminEvent.getAuthDetails() != null
            && adminEvent.getAuthDetails().getUserId() != null
            ? adminEvent.getAuthDetails().getUserId()
            : "admin";

        // A service account calling the Admin API acts through its internal service-account user:
        // the actor is the service account (the client), never a `user` entity.
        String actorClientId = safe(() -> resolver.serviceAccountClientOfUser(realmId, adminId));
        String actorEntityId = actorClientId != null
                ? serviceAccountEntityId(realmId, actorClientId)
                : String.format("user:keycloak:%s:%s", realmId, adminId);
        humiEvent.setEntityId(actorEntityId);
        humiEvent.setEntityType(actorClientId != null ? "service_account" : "user");
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

        addAdminChangeMetadata(humiEvent, adminEvent, resourceType, resourcePath, op, actorClientId, resolver);

        return humiEvent;
    }

    /**
     * The change kind, who acted and — when the target is a service account — which one. humifortis-core
     * scores an admin change to a service account only in the risky contexts these attributes describe.
     * Every attribute is optional: an unknown value is omitted, never guessed.
     */
    private void addAdminChangeMetadata(HumifortisEvent humiEvent, AdminEvent adminEvent, String resourceType,
                                        String resourcePath, OperationType op, String actorClientId,
                                        AdminIdentityResolver resolver) {
        String realmId = adminEvent.getRealmId() != null ? adminEvent.getRealmId() : "unknown";
        humiEvent.addMetadata("admin.actor_type", actorClientId != null ? "service_account" : "user");

        String change = AdminChange.kindOf(resourceType, op, resourcePath);
        if (change != null) humiEvent.addMetadata("admin.change", change);

        AdminChange.Target target = AdminChange.targetOf(resourcePath);
        if (target == null) return;
        String targetClientId = safe(() -> target.kind() == AdminChange.Target.Kind.USER
                ? resolver.serviceAccountClientOfUser(realmId, target.id())
                : resolver.serviceAccountClientOfClient(realmId, target.id()));
        if (targetClientId == null) {
            // a person the change acts on (password reset, session revocation, role change...): the subject of the change
            if (target.kind() == AdminChange.Target.Kind.USER) {
                humiEvent.addMetadata("admin.target_type", "user");
                humiEvent.addMetadata("admin.target_id", String.format("user:keycloak:%s:%s", realmId, target.id()));
            }
            return;
        }

        String targetId = serviceAccountEntityId(realmId, targetClientId);
        humiEvent.addMetadata("admin.target_type", "service_account");
        humiEvent.addMetadata("admin.target_id", targetId);
        humiEvent.addMetadata("admin.self_change", String.valueOf(targetId.equals(humiEvent.getEntityId())));

        if (AdminChange.PRIVILEGE_GRANTED.equals(change)) {
            // the representation of the granted roles is present only when the realm records it
            Boolean privileged = safe(() -> resolver.containsPrivilegedRole(realmId, adminEvent.getRepresentation()));
            if (privileged != null) humiEvent.addMetadata("admin.privileged_role", privileged.toString());
        }
    }

    private static String serviceAccountEntityId(String realmId, String clientId) {
        return String.format("service_account:keycloak:%s:%s", realmId, clientId);
    }

    /** A resolver answer, or null: a lookup failure must never lose the event. */
    private static <T> T safe(java.util.function.Supplier<T> lookup) {
        try {
            return lookup.get();
        } catch (RuntimeException e) {
            return null;
        }
    }

    // ----------------------------------------------------------------
    // Step-up outcome → HumifortisEvent
    // ----------------------------------------------------------------

    /** A step-up challenge the step-up router ran, completed: the login it concluded. */
    public static final String STEP_UP_SUCCEEDED = "mfa_challenge_succeeded";
    /** A step-up challenge answered wrongly (wrong code, failed WebAuthn assertion). */
    public static final String STEP_UP_FAILED = "mfa_challenge_failed";

    /**
     * The step-up the router ran succeeded: reported from the LOGIN event that concluded the flow, BEFORE the login
     * success. The router records the method it challenged; without it no step-up ran and nothing is reported.
     *
     * <p>The event_id is a stable UUID v3 derived from the login event id, so retries never duplicate it.
     *
     * @param method      the factor the router challenged (TOTP, WEBAUTHN, EMAIL_OTP)
     * @param challengeId the Verified-Unblock challenge the step-up answers, or null
     */
    public HumifortisEvent fromStepUpSucceeded(Event loginEvent, String method, String challengeId) {
        HumifortisEvent e = new HumifortisEvent();

        String realmId = loginEvent.getRealmId() != null ? loginEvent.getRealmId() : "unknown";
        String userId  = loginEvent.getUserId() != null
                ? loginEvent.getUserId()
                : detailOrFallback(loginEvent.getDetails(), "userId", "anonymous");

        e.setEntityId(String.format("user:keycloak:%s:%s", realmId, userId));
        e.setEntityType("user");
        e.setTimestamp(Instant.ofEpochMilli(loginEvent.getTime()).toString());
        e.setEventType(STEP_UP_SUCCEEDED);
        e.setSource("keycloak-rba");
        if (loginEvent.getId() != null) {
            e.setEventId(UUID.nameUUIDFromBytes((loginEvent.getId() + ":" + STEP_UP_SUCCEEDED).getBytes()).toString());
        }
        e.setFlowId(extractFlowId(loginEvent.getDetails(), loginEvent.getSessionId()));

        addCommonMetadata(e, realmId, loginEvent.getClientId(), loginEvent.getIpAddress(), loginEvent.getSessionId(), null);
        addContextMetadata(e, loginEvent.getDetails());
        e.addMetadata("mfa_method", method);
        // Verified-Unblock binding: the challenge id and a fresh step-up time
        e.addMetadata("mfa_timestamp", Instant.ofEpochMilli(loginEvent.getTime()).toString());
        if (challengeId != null && !challengeId.isBlank()) {
            e.addMetadata("challenge_id", challengeId);
        }
        return e;
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
                // an administrator ending a user's sessions: incident response on the target, never the user's own logout
                if (p.endsWith("/logout") || (p.contains("sessions") && "DELETE".equals(o))) yield "admin_sessions_revoked";
                yield "admin_user_action";
            }
            case "CLIENT" -> {
                yield "admin_client_action";
            }
            case "REALM_ROLE_MAPPING", "CLIENT_ROLE_MAPPING" -> {
                if ("DELETE".equals(o)) yield "role_revoked";
                yield "role_assigned";
            }
            case "USER_SESSION"        -> "admin_sessions_revoked";
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
            case CLIENT_LOGIN           -> "auth_login_success";
            case CLIENT_LOGIN_ERROR     -> "auth_login_failed";
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

        // Device signals — the field list lives in DeviceSignals (one source of truth). The raw
        // device_signals component map is not forwarded here (it goes to /evaluate).
        for (String field : DeviceSignals.EVENT_FIELDS) {
            putIfPresent(humiEvent, details, field);
        }

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

        // Account age — critical for new_account_new_device scoring; the creation time lets the
        // server compute the age itself
        putIfPresent(humiEvent, details, "account_age_days");
        putIfPresent(humiEvent, details, "account_created_at");
        putIfPresent(humiEvent, details, "account_created_source");

        // Groups and why the user counts as privileged (access policies scope on them)
        putIfPresent(humiEvent, details, "user_groups");
        putIfPresent(humiEvent, details, "user_groups_truncated");
        putIfPresent(humiEvent, details, "user_roles_truncated");
        putIfPresent(humiEvent, details, "privileged_reason");

        // How the client IP was resolved (Keycloak's proxy configuration)
        putIfPresent(humiEvent, details, "ip_source");
        putIfPresent(humiEvent, details, "proxy_headers_mode");
        putIfPresent(humiEvent, details, "proxy_trusted_addresses_set");

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
    }

    /** The context of a service account (client_credentials) request: how it authenticated and what it asked for. */
    private void addServiceAccountMetadata(HumifortisEvent humiEvent, Map<String, String> details) {
        if (details == null || details.isEmpty()) return;
        putIfPresent(humiEvent, details, "grant_type");
        putIfPresent(humiEvent, details, "client_auth_method");
        // the risk stage already decided this request (core records no second decision)
        putIfPresent(humiEvent, details, tech.humifortis.keycloak.serviceaccount.ServiceAccountRiskExecutor.DETAIL_DECISION_STAGE);
        for (String key : ServiceAccountContext.KEYS) {
            putIfPresent(humiEvent, details, key);
        }
    }

    // a request with a session has its flow id from it (enrichEvent); this is the failed authentication (no session)
    private String serviceAccountFlowId(Event event) {
        if (event.getId() != null && !event.getId().isBlank()) return event.getId();
        return String.format("client:%s:%d", event.getClientId(), event.getTime());
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

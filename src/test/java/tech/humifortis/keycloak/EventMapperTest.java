package tech.humifortis.keycloak;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.AuthDetails;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;

import tech.humifortis.keycloak.mapper.EventMapper;
import tech.humifortis.keycloak.model.HumifortisEvent;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies that EventMapper correctly propagates event_id and flow_id,
 * and that fromStepUpSucceeded produces a valid synthetic event.
 */
class EventMapperTest {

    private EventMapper mapper;

    @BeforeEach
    void setUp() {
        mapper = new EventMapper();
    }

    // ── fromKeycloakEvent — event_id ───────────────────────────────────────────

    @Test
    void fromKeycloakEvent_propagatesNativeId() {
        String nativeId = UUID.randomUUID().toString();
        Event event = buildEvent(nativeId, EventType.LOGIN);

        HumifortisEvent result = mapper.fromKeycloakEvent(event);

        assertEquals(nativeId, result.getEventId(),
            "event_id must equal Keycloak's native event UUID");
    }

    @Test
    void fromKeycloakEvent_nullId_eventIdIsNull() {
        Event event = buildEvent(null, EventType.LOGIN_ERROR);

        HumifortisEvent result = mapper.fromKeycloakEvent(event);

        assertNull(result.getEventId(),
            "event_id must be null when Keycloak event has no ID");
    }

    // ── fromKeycloakEvent — flow_id ────────────────────────────────────────────

    @Test
    void fromKeycloakEvent_propagatesFlowId_fromAuthSessionId() {
        String authSessionId = UUID.randomUUID().toString();
        Event event = buildEvent(UUID.randomUUID().toString(), EventType.LOGIN);
        event.getDetails().put("authSessionId", authSessionId);

        HumifortisEvent result = mapper.fromKeycloakEvent(event);

        assertEquals(authSessionId, result.getFlowId(),
            "flow_id must be extracted from authSessionId detail (highest priority)");
    }

    @Test
    void fromKeycloakEvent_flowId_fallsBackToCodeId() {
        String codeId = UUID.randomUUID().toString();
        Event event = buildEvent(UUID.randomUUID().toString(), EventType.CODE_TO_TOKEN);
        // No authSessionId — only code_id (OIDC authorization code flow)
        event.getDetails().put("code_id", codeId);

        HumifortisEvent result = mapper.fromKeycloakEvent(event);

        assertEquals(codeId, result.getFlowId(),
            "flow_id must fall back to code_id when authSessionId is absent");
    }

    @Test
    void fromKeycloakEvent_flowId_fallsBackToSessionId() {
        String sessionId = UUID.randomUUID().toString();
        Event event = buildEvent(UUID.randomUUID().toString(), EventType.LOGIN);
        event.setSessionId(sessionId);
        // No authSessionId or code_id in details

        HumifortisEvent result = mapper.fromKeycloakEvent(event);

        assertEquals(sessionId, result.getFlowId(),
            "flow_id must fall back to sessionId when both authSessionId and code_id are absent");
    }

    @Test
    void fromKeycloakEvent_authSessionIdTakesPriorityOverCodeId() {
        String authSessionId = UUID.randomUUID().toString();
        Event event = buildEvent(UUID.randomUUID().toString(), EventType.LOGIN);
        event.getDetails().put("authSessionId", authSessionId);
        event.getDetails().put("code_id", UUID.randomUUID().toString());

        HumifortisEvent result = mapper.fromKeycloakEvent(event);

        assertEquals(authSessionId, result.getFlowId(),
            "authSessionId must take priority over code_id");
    }

    // ── fromKeycloakAdminEvent ─────────────────────────────────────────────────

    @Test
    void fromKeycloakAdminEvent_propagatesNativeId() {
        String nativeId = UUID.randomUUID().toString();
        AdminEvent adminEvent = buildAdminEvent(nativeId);

        HumifortisEvent result = mapper.fromKeycloakAdminEvent(adminEvent);

        assertEquals(nativeId, result.getEventId(),
            "event_id must equal Keycloak's native admin event UUID");
    }

    // ── fromStepUpSucceeded ─────────────────────────────────────────────────────────

    @Test
    void fromStepUpSucceeded_setsCorrectEventType() {
        Event loginEvent = buildEvent(UUID.randomUUID().toString(), EventType.LOGIN);

        HumifortisEvent result = mapper.fromStepUpSucceeded(loginEvent, "TOTP", null);

        assertEquals("mfa_challenge_succeeded", result.getEventType(),
            "a completed step-up is reported as mfa_challenge_succeeded");
    }

    @Test
    void fromStepUpSucceeded_setsSourceKeycloakRba() {
        Event loginEvent = buildEvent(UUID.randomUUID().toString(), EventType.LOGIN);

        HumifortisEvent result = mapper.fromStepUpSucceeded(loginEvent, "TOTP", null);

        assertEquals("keycloak-rba", result.getSource());
    }

    @Test
    void fromStepUpSucceeded_derivesStableDeterministicId() {
        String loginId = UUID.randomUUID().toString();
        Event loginEvent = buildEvent(loginId, EventType.LOGIN);

        HumifortisEvent r1 = mapper.fromStepUpSucceeded(loginEvent, "TOTP", null);
        HumifortisEvent r2 = mapper.fromStepUpSucceeded(loginEvent, "TOTP", null);

        assertNotNull(r1.getEventId(), "fromStepUpSucceeded event_id must not be null");
        assertEquals(r1.getEventId(), r2.getEventId(),
            "same login event must always produce the same mfa_success event_id (idempotent)");
    }

    @Test
    void fromStepUpSucceeded_eventIdDifferentFromLoginEventId() {
        String loginId = UUID.randomUUID().toString();
        Event loginEvent = buildEvent(loginId, EventType.LOGIN);

        HumifortisEvent result = mapper.fromStepUpSucceeded(loginEvent, "TOTP", null);

        assertNotEquals(loginId, result.getEventId(),
            "mfa_success event_id must differ from the login event_id");
    }

    @Test
    void fromStepUpSucceeded_propagatesFlowId() {
        String authSessionId = UUID.randomUUID().toString();
        Event loginEvent = buildEvent(UUID.randomUUID().toString(), EventType.LOGIN);
        loginEvent.getDetails().put("authSessionId", authSessionId);

        HumifortisEvent result = mapper.fromStepUpSucceeded(loginEvent, "TOTP", null);

        assertEquals(authSessionId, result.getFlowId(),
            "fromStepUpSucceeded must share the same flow_id as the login event");
    }

    @Test
    void fromStepUpSucceeded_nullLoginId_eventIdIsNull() {
        Event loginEvent = buildEvent(null, EventType.LOGIN);

        HumifortisEvent result = mapper.fromStepUpSucceeded(loginEvent, "TOTP", null);

        assertNull(result.getEventId(),
            "event_id must be null when the login event has no ID");
    }

    @Test
    void fromStepUpSucceeded_setsEntityId() {
        Event loginEvent = buildEvent(UUID.randomUUID().toString(), EventType.LOGIN);
        loginEvent.setUserId("user-abc");
        loginEvent.setRealmId("my-realm");

        HumifortisEvent result = mapper.fromStepUpSucceeded(loginEvent, "TOTP", null);

        assertEquals("user:keycloak:my-realm:user-abc", result.getEntityId());
    }

    // -- service accounts (client_credentials) ------------------------------------------------

    @Test
    void clientLogin_isAServiceAccountLoginKeyedByTheClientId() {
        Event event = buildEvent(UUID.randomUUID().toString(), EventType.CLIENT_LOGIN);
        event.setClientId("svc-backup");
        event.getDetails().put("grant_type", "client_credentials");
        event.getDetails().put("client_auth_method", "client-secret");

        HumifortisEvent result = mapper.fromKeycloakEvent(event);

        assertEquals("service_account", result.getEntityType());
        assertEquals("service_account:keycloak:test-realm:svc-backup", result.getEntityId());
        assertEquals("auth_login_success", result.getEventType());
        assertEquals("client_credentials", result.getMetadata().get("grant_type"));
        assertEquals("client-secret", result.getMetadata().get("client_auth_method"));
        assertEquals("svc-backup", result.getMetadata().get("client_id"));
    }

    @Test
    void clientLoginError_isAFailedServiceAccountLoginWithoutAUser() {
        Event event = buildEvent(UUID.randomUUID().toString(), EventType.CLIENT_LOGIN_ERROR);
        event.setUserId(null);
        event.setClientId("svc-backup");
        event.setError("invalid_client_credentials");

        HumifortisEvent result = mapper.fromKeycloakEvent(event);

        assertEquals("service_account", result.getEntityType());
        assertEquals("service_account:keycloak:test-realm:svc-backup", result.getEntityId(),
            "a failed login has no user id: the client id identifies the service account");
        assertEquals("auth_login_failed", result.getEventType());
        assertEquals("invalid_client_credentials", result.getMetadata().get("error"));
    }

    @Test
    void serviceAccountContext_isForwardedUnderTheCoreFeatureNames() {
        Event event = buildEvent(UUID.randomUUID().toString(), EventType.CLIENT_LOGIN);
        event.setClientId("svc-backup");
        event.getDetails().put("service_account.source_allowlist_match", "false");
        event.getDetails().put("service_account.requested_scopes", "address,email");
        event.getDetails().put("service_account.historical_scopes", "email");
        event.getDetails().put("service_account.credential_age_days", "120");
        event.getDetails().put("service_account.rotation_max_age_days", "90");
        event.getDetails().put("service_account.expected_window_start_hour_utc", "1");
        event.getDetails().put("service_account.expected_window_end_hour_utc", "2");
        event.getDetails().put("unrelated", "not forwarded");

        Map<String, Object> md = mapper.fromKeycloakEvent(event).getMetadata();

        assertEquals("false", md.get("service_account.source_allowlist_match"));
        assertEquals("address,email", md.get("service_account.requested_scopes"));
        assertEquals("email", md.get("service_account.historical_scopes"));
        assertEquals("120", md.get("service_account.credential_age_days"));
        assertEquals("90", md.get("service_account.rotation_max_age_days"));
        assertEquals("1", md.get("service_account.expected_window_start_hour_utc"));
        assertEquals("2", md.get("service_account.expected_window_end_hour_utc"));
        assertFalse(md.containsKey("unrelated"));
    }

    @Test
    void serviceAccountFlowId_isTheRequestSessionElseTheEventId() {
        // a token request has a (transient) session: its id is the flow id, shared with the risk stage's evaluation
        Event withSession = buildEvent("evt-1", EventType.CLIENT_LOGIN);
        withSession.setClientId("svc-backup");
        withSession.getDetails().put("token_id", "tok-1");
        withSession.getDetails().put("authSessionId", "sess-1");
        assertEquals("sess-1", mapper.fromKeycloakEvent(withSession).getFlowId());

        Event withToken = buildEvent("evt-3", EventType.CLIENT_LOGIN);
        withToken.setClientId("svc-backup");
        withToken.getDetails().put("token_id", "tok-1");
        assertEquals("evt-3", mapper.fromKeycloakEvent(withToken).getFlowId(), "the token id is not a flow id");

        Event withoutToken = buildEvent("evt-2", EventType.CLIENT_LOGIN_ERROR);
        withoutToken.setClientId("svc-backup");
        assertEquals("evt-2", mapper.fromKeycloakEvent(withoutToken).getFlowId(),
            "humifortis-core rejects an auth event without a flow_id");

        Event bare = buildEvent(null, EventType.CLIENT_LOGIN_ERROR);
        bare.setClientId("svc-backup");
        assertNotNull(mapper.fromKeycloakEvent(bare).getFlowId());
    }

    @Test
    void aBrowserLoginIsStillAUser_andNeverCarriesServiceAccountContext() {
        Event event = buildEvent(UUID.randomUUID().toString(), EventType.LOGIN);
        event.setUserId("user-abc");
        event.setClientId("demo-app");
        event.getDetails().put("service_account.requested_scopes", "address");
        event.getDetails().put("grant_type", "authorization_code");

        HumifortisEvent result = mapper.fromKeycloakEvent(event);

        assertEquals("user", result.getEntityType());
        assertEquals("user:keycloak:test-realm:user-abc", result.getEntityId());
        assertFalse(result.getMetadata().containsKey("service_account.requested_scopes"));
        assertFalse(result.getMetadata().containsKey("grant_type"));
    }

    // ── helpers ────────────────────────────────────────────────────────────────

    private Event buildEvent(String id, EventType type) {
        Event e = new Event();
        e.setId(id);
        e.setType(type);
        e.setRealmId("test-realm");
        e.setUserId(UUID.randomUUID().toString());
        e.setTime(System.currentTimeMillis());
        e.setDetails(new HashMap<>());
        return e;
    }

    private AdminEvent buildAdminEvent(String id) {
        AdminEvent a = new AdminEvent();
        a.setId(id);
        a.setRealmId("test-realm");
        a.setOperationType(OperationType.CREATE);
        a.setResourceType(ResourceType.USER);
        a.setResourcePath("users/" + UUID.randomUUID());
        a.setTime(System.currentTimeMillis());
        AuthDetails auth = new AuthDetails();
        auth.setUserId(UUID.randomUUID().toString());
        a.setAuthDetails(auth);
        return a;
    }
}


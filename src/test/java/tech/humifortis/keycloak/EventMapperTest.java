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
 * and that fromMfaSuccess produces a valid synthetic event.
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

    // ── fromFeedback — event_id idempotency ───────────────────────────────────

    @Test
    void fromFeedback_derivesDeterministicId() {
        String originId = UUID.randomUUID().toString();
        Event origin = buildEvent(originId, EventType.LOGIN);

        HumifortisEvent r1 = mapper.fromFeedback(origin, "auth_decision_allow",
            "30", "LOW", "ALLOW", "below_threshold");
        HumifortisEvent r2 = mapper.fromFeedback(origin, "auth_decision_allow",
            "30", "LOW", "ALLOW", "below_threshold");

        assertNotNull(r1.getEventId(), "feedback event_id must not be null");
        assertEquals(r1.getEventId(), r2.getEventId(),
            "same origin + same feedbackType must produce the same event_id (idempotent)");
    }

    @Test
    void fromFeedback_differentTypes_produceDifferentIds() {
        String originId = UUID.randomUUID().toString();
        Event origin = buildEvent(originId, EventType.LOGIN);

        HumifortisEvent allow = mapper.fromFeedback(origin, "auth_decision_allow",
            "30", "LOW", "ALLOW", "r");
        HumifortisEvent block = mapper.fromFeedback(origin, "auth_decision_block",
            "90", "HIGH", "BLOCK", "r");

        assertNotEquals(allow.getEventId(), block.getEventId(),
            "different feedback types must produce different event_ids");
    }

    @Test
    void fromFeedback_nullOriginId_eventIdIsNull() {
        Event origin = buildEvent(null, EventType.LOGIN);

        HumifortisEvent result = mapper.fromFeedback(origin, "auth_decision_mfa",
            "50", "MEDIUM", "MFA", "mid_risk");

        assertNull(result.getEventId(),
            "event_id must be null when origin has no ID");
    }

    @Test
    void fromFeedback_propagatesFlowId() {
        String authSessionId = UUID.randomUUID().toString();
        Event origin = buildEvent(UUID.randomUUID().toString(), EventType.LOGIN);
        origin.getDetails().put("authSessionId", authSessionId);

        HumifortisEvent result = mapper.fromFeedback(origin, "auth_decision_allow",
            "30", "LOW", "ALLOW", "ok");

        assertEquals(authSessionId, result.getFlowId(),
            "fromFeedback must carry the same flow_id as the origin event");
    }

    // ── fromMfaSuccess ─────────────────────────────────────────────────────────

    @Test
    void fromMfaSuccess_setsCorrectEventType() {
        Event loginEvent = buildEvent(UUID.randomUUID().toString(), EventType.LOGIN);

        HumifortisEvent result = mapper.fromMfaSuccess(loginEvent);

        assertEquals("auth_mfa_success", result.getEventType(),
            "fromMfaSuccess must produce event_type=auth_mfa_success");
    }

    @Test
    void fromMfaSuccess_setsSourceKeycloakRba() {
        Event loginEvent = buildEvent(UUID.randomUUID().toString(), EventType.LOGIN);

        HumifortisEvent result = mapper.fromMfaSuccess(loginEvent);

        assertEquals("keycloak-rba", result.getSource());
    }

    @Test
    void fromMfaSuccess_derivesStableDeterministicId() {
        String loginId = UUID.randomUUID().toString();
        Event loginEvent = buildEvent(loginId, EventType.LOGIN);

        HumifortisEvent r1 = mapper.fromMfaSuccess(loginEvent);
        HumifortisEvent r2 = mapper.fromMfaSuccess(loginEvent);

        assertNotNull(r1.getEventId(), "fromMfaSuccess event_id must not be null");
        assertEquals(r1.getEventId(), r2.getEventId(),
            "same login event must always produce the same mfa_success event_id (idempotent)");
    }

    @Test
    void fromMfaSuccess_eventIdDifferentFromLoginEventId() {
        String loginId = UUID.randomUUID().toString();
        Event loginEvent = buildEvent(loginId, EventType.LOGIN);

        HumifortisEvent result = mapper.fromMfaSuccess(loginEvent);

        assertNotEquals(loginId, result.getEventId(),
            "mfa_success event_id must differ from the login event_id");
    }

    @Test
    void fromMfaSuccess_propagatesFlowId() {
        String authSessionId = UUID.randomUUID().toString();
        Event loginEvent = buildEvent(UUID.randomUUID().toString(), EventType.LOGIN);
        loginEvent.getDetails().put("authSessionId", authSessionId);

        HumifortisEvent result = mapper.fromMfaSuccess(loginEvent);

        assertEquals(authSessionId, result.getFlowId(),
            "fromMfaSuccess must share the same flow_id as the login event");
    }

    @Test
    void fromMfaSuccess_nullLoginId_eventIdIsNull() {
        Event loginEvent = buildEvent(null, EventType.LOGIN);

        HumifortisEvent result = mapper.fromMfaSuccess(loginEvent);

        assertNull(result.getEventId(),
            "event_id must be null when the login event has no ID");
    }

    @Test
    void fromMfaSuccess_setsEntityId() {
        Event loginEvent = buildEvent(UUID.randomUUID().toString(), EventType.LOGIN);
        loginEvent.setUserId("user-abc");
        loginEvent.setRealmId("my-realm");

        HumifortisEvent result = mapper.fromMfaSuccess(loginEvent);

        assertEquals("user:keycloak:my-realm:user-abc", result.getEntityId());
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


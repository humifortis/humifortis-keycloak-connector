package tech.humifortis.keycloak.mapper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;

import tech.humifortis.keycloak.model.HumifortisEvent;

class TokenEventsTest {

    private final EventMapper mapper = new EventMapper();

    @BeforeEach
    void reset() {
        TokenEvents.resetSampler();
    }

    private static Event event(EventType type, String error) {
        Event e = new Event();
        e.setId("11111111-2222-3333-4444-555555555555");
        e.setTime(1_760_000_000_000L);
        e.setType(type);
        e.setRealmId("test-realm");
        e.setClientId("demo-app");
        e.setUserId("user-1");
        e.setSessionId("sess-1");
        e.setIpAddress("203.0.113.5");
        e.setError(error);
        e.setDetails(new HashMap<>());
        return e;
    }

    // -- P14: the token events are evidence for the person they belong to ------------------------------------

    @Test
    void aRefreshAnIntrospectionAndAnExchangeAreEventsOfThePerson() {
        assertEquals("auth_token_refresh", mapper.fromKeycloakEvent(event(EventType.REFRESH_TOKEN, null)).getEventType());
        assertEquals("auth_token_introspect", mapper.fromKeycloakEvent(event(EventType.INTROSPECT_TOKEN, null)).getEventType());
        assertEquals("auth_token_introspect_failed", mapper.fromKeycloakEvent(event(EventType.INTROSPECT_TOKEN_ERROR, "invalid_token")).getEventType());
        assertEquals("auth_token_exchange", mapper.fromKeycloakEvent(event(EventType.TOKEN_EXCHANGE, null)).getEventType());
        assertEquals("auth_token_exchange_failed", mapper.fromKeycloakEvent(event(EventType.TOKEN_EXCHANGE_ERROR, "invalid_token")).getEventType(),
                "the failed exchange has the name the core maps, not auth_token_exchange_error");
        HumifortisEvent refresh = mapper.fromKeycloakEvent(event(EventType.REFRESH_TOKEN, null));
        assertEquals("user:keycloak:test-realm:user-1", refresh.getEntityId());
        assertEquals("203.0.113.5", refresh.getMetadata().get("ip"));
    }

    @Test
    void theTokenEventsOfAServiceAccountsUserAreNotSent() {
        for (EventType t : new EventType[] {EventType.REFRESH_TOKEN, EventType.TOKEN_EXCHANGE, EventType.INTROSPECT_TOKEN, EventType.INTROSPECT_TOKEN_ERROR, EventType.OAUTH2_DEVICE_CODE_TO_TOKEN}) {
            assertFalse(TokenEvents.accepts(event(t, null), true, 0L), t.name() + ": the service account is the client, its user must never become a person");
            assertTrue(TokenEvents.accepts(event(t, null), false, 0L), t.name());
        }
    }

    @Test
    void oneIntrospectionPerPersonAndApplicationPerMinuteIsSent() {
        Event first = event(EventType.INTROSPECT_TOKEN, null);
        assertTrue(TokenEvents.accepts(first, false, 1_000L), "the first one");
        assertFalse(TokenEvents.accepts(first, false, 30_000L), "a resource server introspects on every call");
        assertFalse(TokenEvents.accepts(first, false, 60_999L));
        assertTrue(TokenEvents.accepts(first, false, 61_000L), "a minute later");

        Event otherApp = event(EventType.INTROSPECT_TOKEN, null);
        otherApp.setClientId("another-resource-server");
        assertTrue(TokenEvents.accepts(otherApp, false, 62_000L), "another application is another key");
        Event otherPerson = event(EventType.INTROSPECT_TOKEN, null);
        otherPerson.setUserId("user-2");
        assertTrue(TokenEvents.accepts(otherPerson, false, 62_000L), "another person is another key");
        Event failed = event(EventType.INTROSPECT_TOKEN_ERROR, "invalid_token");
        assertTrue(TokenEvents.accepts(failed, false, 62_000L), "a failure is counted apart from the successes");
    }

    // -- P11: a bound token presented without the proof of its key ------------------------------------------

    @Test
    void aRefusedDpopProofIsABindingFailureWhateverTheEndpoint() {
        for (EventType t : new EventType[] {EventType.CODE_TO_TOKEN_ERROR, EventType.REFRESH_TOKEN_ERROR, EventType.TOKEN_EXCHANGE_ERROR,
                EventType.INTROSPECT_TOKEN_ERROR, EventType.USER_INFO_REQUEST_ERROR}) {
            assertEquals("auth_token_binding_failed", mapper.fromKeycloakEvent(event(t, "invalid_dpop_proof")).getEventType(), t.name());
            assertEquals("invalid_dpop_proof", mapper.fromKeycloakEvent(event(t, "invalid_dpop_proof")).getMetadata().get("error"));
        }
        assertEquals("auth_token_refresh_failed", mapper.fromKeycloakEvent(event(EventType.REFRESH_TOKEN_ERROR, "invalid_token")).getEventType(),
                "an expired token is not a binding failure");
    }

    @Test
    void aUserInfoRefusalIsSentOnlyWhenItIsABindingFailure() {
        assertTrue(TokenEvents.accepts(event(EventType.USER_INFO_REQUEST_ERROR, "invalid_dpop_proof"), false, 0L));
        assertFalse(TokenEvents.accepts(event(EventType.USER_INFO_REQUEST_ERROR, "invalid_token"), false, 0L),
                "an expired token at a resource server says nothing");
        assertTrue(TokenEvents.accepts(event(EventType.INTROSPECT_TOKEN_ERROR, "invalid_dpop_proof"), false, 0L));
        assertTrue(TokenEvents.accepts(event(EventType.INTROSPECT_TOKEN_ERROR, "invalid_dpop_proof"), false, 1L),
                "a binding failure is never sampled away");
    }

    @Test
    void aServiceAccountsClientLoginKeepsItsName() {
        Event e = event(EventType.CLIENT_LOGIN_ERROR, "invalid_dpop_proof");
        e.setUserId(null);
        assertEquals("auth_login_failed", mapper.fromKeycloakEvent(e).getEventType(), "judged as a client authentication");
        assertNull(TokenEvents.eventTypeOf(EventType.CLIENT_LOGIN_ERROR, "invalid_dpop_proof", true));
    }

    // -- P12: the device grant --------------------------------------------------------------------------------

    @Test
    void theTokensOfADeviceAreAnEventOfThePersonWhoApprovedIt() {
        Event e = event(EventType.OAUTH2_DEVICE_CODE_TO_TOKEN, null);
        e.getDetails().put("grant_type", "urn:ietf:params:oauth:grant-type:device_code");
        HumifortisEvent out = mapper.fromKeycloakEvent(e);
        assertEquals("auth_device_token_issued", out.getEventType());
        assertEquals("user:keycloak:test-realm:user-1", out.getEntityId());
    }

    @Test
    void aWrongUserCodeIsAFactAboutTheApplication_neverAPersonsFailedPassword() {
        Event e = event(EventType.OAUTH2_DEVICE_VERIFY_USER_CODE_ERROR, "invalid_user_code");
        e.setUserId(null);
        e.getDetails().put("code_id", "flow-9");
        assertTrue(TokenEvents.accepts(e, false, 0L));
        HumifortisEvent out = mapper.fromKeycloakEvent(e);
        assertEquals("device_user_code_failed", out.getEventType());
        assertEquals("integration:keycloak", out.getEntityId(), "not an \"anonymous\" person");
        assertEquals("integration", out.getEntityType());
        assertEquals("demo-app", out.getMetadata().get("client_id"));
        assertEquals("203.0.113.5", out.getMetadata().get("ip"));
        assertEquals("invalid_user_code", out.getMetadata().get("failure_code"));
        assertFalse(out.getMetadata().containsKey("error"), "it is not a failed login: no \"error\" for the credential rules");
        assertEquals("flow-9", out.getFlowId());
    }

    @Test
    void aUserInfoRefusalNamesTheDpopProofInItsReasonNotItsError() {
        Event event = new Event();
        event.setType(EventType.USER_INFO_REQUEST_ERROR);
        event.setError("invalid_token");
        event.setDetails(new java.util.HashMap<>(java.util.Map.of("reason", "DPoP proof is missing")));
        assertEquals("invalid_token DPoP proof is missing", TokenEvents.refusal(event));
        assertEquals(TokenEvents.BINDING_FAILED, TokenEvents.eventTypeOf(event.getType(), TokenEvents.refusal(event), false));
        assertTrue(TokenEvents.accepts(event, false, 0L));
        event.setDetails(java.util.Map.of());
        assertNull(TokenEvents.eventTypeOf(event.getType(), TokenEvents.refusal(event), false));
        assertFalse(TokenEvents.accepts(event, false, 0L));
    }
}

package tech.humifortis.keycloak.mapper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;

import org.junit.jupiter.api.Test;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;

import tech.humifortis.keycloak.model.HumifortisEvent;
import tech.humifortis.keycloak.serviceaccount.ClientEntityType;

class ClientRegistrationTest {

    @Test
    void anAgentRegisteringItselfIsTheFirstEventOfANewAgentEntity() {
        Event e = new Event();
        e.setId("aaaaaaaa-0000-4000-8000-000000000001");
        e.setType(EventType.CLIENT_REGISTER);
        e.setRealmId("demo");
        e.setClientId("planner-agent");
        e.setIpAddress("203.0.113.8");
        e.setTime(1_760_000_000_000L);
        e.setDetails(new HashMap<>(java.util.Map.of("registration_auth", "anonymous")));

        HumifortisEvent out = ClientRegistration.registered(e);

        assertEquals("agent:keycloak:demo:planner-agent", out.getEntityId());
        assertEquals("agent", out.getEntityType());
        assertEquals("auth_client_registered", out.getEventType());
        assertEquals("planner-agent", out.getMetadata().get("client_id"));
        assertEquals("anonymous", out.getMetadata().get("registration_auth"));
        assertEquals("aaaaaaaa-0000-4000-8000-000000000001", out.getFlowId());
    }

    @Test
    void onlyARegistrationIsOne() {
        assertTrue(ClientRegistration.is(EventType.CLIENT_REGISTER));
        assertFalse(ClientRegistration.is(EventType.CLIENT_UPDATE));
        assertFalse(ClientRegistration.is(EventType.CLIENT_LOGIN));
    }

    @Test
    void aClientIsAnAgentOnlyWhenItSaysSo() {
        assertEquals("agent", ClientEntityType.of("agent"));
        assertEquals("agent", ClientEntityType.of(" Agent "));
        assertEquals("service_account", ClientEntityType.of(null));
        assertEquals("service_account", ClientEntityType.of(""));
        assertEquals("service_account", ClientEntityType.of("robot"), "any other value is a service account, never a new type by accident");
        assertEquals("agent:keycloak:r1:planner", ClientEntityType.entityId("agent", "r1", "planner"));
    }

    @Test
    void anAgentsClientLoginIsAnEventOfTheAgent() {
        Event login = new Event();
        login.setId("aaaaaaaa-0000-4000-8000-000000000002");
        login.setType(EventType.CLIENT_LOGIN);
        login.setRealmId("demo");
        login.setClientId("planner-agent");
        login.setTime(1_760_000_000_000L);
        login.setDetails(new HashMap<>(java.util.Map.of(ClientEntityType.ATTR, "agent", "client_auth_method", "client-jwt")));
        HumifortisEvent out = new EventMapper().fromKeycloakEvent(login);
        assertEquals("agent", out.getEntityType());
        assertEquals("agent:keycloak:demo:planner-agent", out.getEntityId());

        login.setDetails(new HashMap<>(java.util.Map.of("client_auth_method", "client-secret")));
        HumifortisEvent sa = new EventMapper().fromKeycloakEvent(login);
        assertEquals("service_account", sa.getEntityType());
    }
}

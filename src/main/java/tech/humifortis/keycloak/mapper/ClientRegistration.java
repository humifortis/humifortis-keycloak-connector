package tech.humifortis.keycloak.mapper;

import java.time.Instant;
import java.util.Map;

import org.keycloak.events.Event;
import org.keycloak.events.EventType;

import tech.humifortis.keycloak.model.HumifortisEvent;
import tech.humifortis.keycloak.serviceaccount.ClientEntityType;

/**
 * An agent registering itself as a client (dynamic client registration, RFC 7591; docs/sso-and-external-idp-e2e.spec.md, P17,
 * AG-1). Keycloak reports {@code CLIENT_REGISTER} for every client registered through the registration endpoint; only a client
 * that declares itself an agent ({@code humifortis.entity_type=agent}) is an entity of Humifortis. The registration is the
 * first event of that entity: it is born with no history.
 */
public final class ClientRegistration {

    public static final String EVENT_TYPE = "auth_client_registered";

    private ClientRegistration() {}

    public static boolean is(EventType type) {
        return type == EventType.CLIENT_REGISTER;
    }

    /** The event of the new agent. The caller has checked that the client declares itself an agent. */
    public static HumifortisEvent registered(Event event) {
        HumifortisEvent e = new HumifortisEvent();
        String realmId = event.getRealmId() != null ? event.getRealmId() : "unknown";
        String clientId = event.getClientId() != null && !event.getClientId().isBlank() ? event.getClientId() : "unknown";
        e.setEntityId(ClientEntityType.entityId(ClientEntityType.AGENT, realmId, clientId));
        e.setEntityType(ClientEntityType.AGENT);
        e.setTimestamp(Instant.ofEpochMilli(event.getTime()).toString());
        e.setEventType(EVENT_TYPE);
        e.setSource("keycloak");
        if (event.getId() != null) e.setEventId(event.getId());
        // one registration is one flow
        e.setFlowId(event.getId() != null ? event.getId() : String.format("client:%s:%d", clientId, event.getTime()));
        e.addMetadata("realm", realmId);
        e.addMetadata("client_id", clientId);
        if (event.getIpAddress() != null) e.addMetadata("ip", event.getIpAddress());
        Map<String, String> details = event.getDetails();
        if (details != null) {
            String auth = details.get("registration_auth");
            if (auth != null && !auth.isBlank()) e.addMetadata("registration_auth", auth);
        }
        e.addMetadata("grant_type", "client_registration");
        return e;
    }
}

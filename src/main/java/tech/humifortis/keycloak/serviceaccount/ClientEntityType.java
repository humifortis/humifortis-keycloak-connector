package tech.humifortis.keycloak.serviceaccount;

import java.util.Locale;

/**
 * What kind of entity a client is to Humifortis (docs/sso-and-external-idp-e2e.spec.md, P17): a service account (a workload
 * with a secret or a key, the default) or an AI agent. The operator says so on the client, with the attribute
 * {@code humifortis.entity_type=agent}, which an agent can also set itself when it registers (dynamic client registration,
 * RFC 7591). The type is a declaration on the client, never a guess from its behaviour; any other value is a service account.
 *
 * <p>The connector only names the type; everything that differs between the two lives in the core's entity-type registry.</p>
 */
public final class ClientEntityType {

    /** The client attribute (and the event detail the listener copies it to). */
    public static final String ATTR = "humifortis.entity_type";
    public static final String SERVICE_ACCOUNT = "service_account";
    public static final String AGENT = "agent";

    private ClientEntityType() {}

    /** The entity type a client declares. */
    public static String of(String declared) {
        return declared != null && AGENT.equals(declared.trim().toLowerCase(Locale.ROOT)) ? AGENT : SERVICE_ACCOUNT;
    }

    /** The entity id of a client of this type: {@code <type>:keycloak:<realm id>:<client id>}. */
    public static String entityId(String type, String realmId, String clientId) {
        return String.format("%s:keycloak:%s:%s", type, realmId, clientId);
    }
}

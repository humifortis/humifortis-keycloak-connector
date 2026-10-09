package tech.humifortis.keycloak.serviceaccount;

import java.time.Instant;

import org.keycloak.models.ClientModel;

/**
 * Disabling a service account's client: the one persistent containment the connector performs for a machine, by the
 * risk stage (a {@code DISABLE_CLIENT} decision) or on an analyst's response (RISC {@code account-disabled} on a
 * {@code service_account:} subject).
 *
 * <p>Only a client that opts in is ever disabled ({@code humifortis.allow_disable=true}), never an exempt one
 * ({@code humifortis.enforcement=off}). The client keeps why on its attributes, so an operator sees it in the admin
 * console; re-enabling it is the normal Keycloak action. A client already disabled is not touched.
 */
public final class ClientContainment {

    /** Client attribute: {@code true} lets a decision or an analyst disable this client. */
    public static final String ATTR_ALLOW_DISABLE = "humifortis.allow_disable";
    /** Set on the client when it is disabled: when, and by what (a decision rule, or the analyst response). */
    public static final String ATTR_DISABLED_AT = "humifortis.disabled_at";
    public static final String ATTR_DISABLED_BY = "humifortis.disabled_by";

    /** What a disable request did. */
    public enum Result { DISABLED, ALREADY_DISABLED, NOT_ALLOWED }

    private ClientContainment() {}

    /** Whether the client lets Humifortis disable it. */
    public static boolean allowsDisable(ClientModel client) {
        return client != null
                && "true".equalsIgnoreCase(trim(client.getAttribute(ATTR_ALLOW_DISABLE)))
                && !"off".equalsIgnoreCase(trim(client.getAttribute(ServiceAccountRiskExecutor.ATTR_ENFORCEMENT)));
    }

    /**
     * Disables the client when it allows it.
     *
     * @param by what disabled it: {@code rule:<decision rule>} or {@code analyst}
     */
    public static Result disable(ClientModel client, String by) {
        if (!allowsDisable(client)) return Result.NOT_ALLOWED;
        if (!client.isEnabled()) return Result.ALREADY_DISABLED;
        client.setEnabled(false);
        client.setAttribute(ATTR_DISABLED_AT, Instant.now().toString());
        client.setAttribute(ATTR_DISABLED_BY, by);
        return Result.DISABLED;
    }

    private static String trim(String v) {
        return v == null ? "" : v.trim();
    }
}

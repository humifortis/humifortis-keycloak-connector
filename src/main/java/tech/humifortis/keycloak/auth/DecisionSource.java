package tech.humifortis.keycloak.auth;

import java.util.List;
import java.util.Locale;

/**
 * Where the decision of a login is made (docs/risk-as-data.spec.md, D4).
 *
 * <ul>
 *   <li>{@code server} (default): the action returned by Humifortis is enforced, as always.</li>
 *   <li>{@code local}: the connector asks for the evaluation context, writes it into the authentication session
 *       and lets the realm's own flow decide, with the Humifortis conditions. An explicit deny of the platform
 *       is still enforced by the connector (D17).</li>
 * </ul>
 *
 * Set with {@code HUMIFORTIS_DECISION_SOURCE}. Anything but {@code local} is {@code server}: a typo never opens a door.
 */
public final class DecisionSource {

    public static final String ENV_SOURCE = "HUMIFORTIS_DECISION_SOURCE";
    public static final String ENV_ATTRIBUTES = "HUMIFORTIS_CONTEXT_ATTRIBUTES";

    /** The attributes a condition can read by default (D13): no address, e-mail or user agent among them. */
    public static final List<String> DEFAULT_ATTRIBUTES = List.of(
            "network.is_anonymous", "network.is_tor", "network.is_vpn", "network.is_datacenter",
            "network.country_mismatch", "network.implied_speed_kmh", "device.first_seen");

    private DecisionSource() {}

    public static boolean isLocal() {
        return isLocal(System.getenv(ENV_SOURCE));
    }

    static boolean isLocal(String value) {
        return value != null && "local".equals(value.trim().toLowerCase(Locale.ROOT));
    }

    /** The attributes the connector asks for and writes: the allowlist of {@code HUMIFORTIS_CONTEXT_ATTRIBUTES}, or the default. */
    public static List<String> attributeAllowlist() {
        return parseAllowlist(System.getenv(ENV_ATTRIBUTES));
    }

    static List<String> parseAllowlist(String value) {
        if (value == null || value.isBlank()) return DEFAULT_ATTRIBUTES;
        List<String> out = new java.util.ArrayList<>();
        for (String part : value.split(",")) {
            String name = part.trim();
            if (!name.isEmpty() && name.length() <= 128 && !out.contains(name)) out.add(name);
            if (out.size() >= 32) break;
        }
        return out.isEmpty() ? DEFAULT_ATTRIBUTES : List.copyOf(out);
    }

    /** The key of the risk authenticator's execution configuration that overrides the environment for that flow. */
    public static final String CONFIG_KEY = "decision.source";

    /**
     * The source for a flow: its execution configuration ({@code server} or {@code local}) wins, so a realm can move
     * one flow at a time; anything else follows {@code HUMIFORTIS_DECISION_SOURCE}.
     */
    public static boolean isLocalFor(java.util.Map<String, String> executionConfig) {
        String configured = executionConfig == null ? null : executionConfig.get(CONFIG_KEY);
        if (configured != null) {
            String c = configured.trim().toLowerCase(Locale.ROOT);
            if (c.equals("local")) return true;
            if (c.equals("server")) return false;
        }
        return isLocal();
    }

    /** The evaluate path: in {@code local} source it asks for the context and for the allowlisted attributes. */
    public static String evaluatePath(boolean local) {
        if (!local) return "/evaluate";
        return "/evaluate?include=context&attributes=" + String.join(",", attributeAllowlist());
    }
}

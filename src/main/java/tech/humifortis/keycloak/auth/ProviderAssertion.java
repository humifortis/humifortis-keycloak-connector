package tech.humifortis.keycloak.auth;

import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * What an external identity provider says about HOW the person authenticated (docs/sso-and-external-idp-e2e.spec.md, P4,
 * ID-9): the {@code amr} / {@code acr} claims of an OpenID Connect ID token, the authentication context class of a SAML
 * assertion.
 *
 * <p>The connector only <em>reports</em> the claim ({@code idp_asserted_mfa}: {@code true}, {@code false}, absent when the
 * provider said nothing). Whether it is worth anything is the tenant's decision and Humifortis' (the provider's trust level
 * and the decision are in core); a claim of a provider is not a verification Humifortis made, so it never lowers a
 * step-up here.</p>
 */
final class ProviderAssertion {

    /** RFC 8176 method references, by the kind of factor they prove. */
    private static final Set<String> KNOWLEDGE = Set.of("pwd", "kba", "pin");
    private static final Set<String> POSSESSION = Set.of("otp", "sms", "tel", "hwk", "swk", "pop", "sc");
    private static final Set<String> INHERENCE = Set.of("fpt", "face", "iris", "retina", "vbm");

    /** SAML authentication contexts that prove a second factor (matched in lower case inside the serialized statement). */
    private static final Set<String> SAML_MULTI_FACTOR = Set.of(
            "timesynctoken", "mobiletwofactor", "smartcard", "multifactor", "twofactor");

    private ProviderAssertion() {}

    /**
     * The claim of an ID token, given as its JSON: {@code Boolean.TRUE} when it asserts more than one factor,
     * {@code Boolean.FALSE} when it describes the authentication and does not, {@code null} when it carries neither
     * {@code amr} nor {@code acr} (or is not readable).
     */
    static Boolean fromIdToken(String idTokenJson) {
        String json = payloadJson(idTokenJson);
        if (json == null) return null;
        try {
            JsonElement root = JsonParser.parseString(json);
            if (!root.isJsonObject()) return null;
            JsonObject token = root.getAsJsonObject();
            Set<String> amr = amrValues(token.get("amr"));
            String acr = token.has("acr") && token.get("acr").isJsonPrimitive() ? token.get("acr").getAsString() : null;
            if (amr.isEmpty() && (acr == null || acr.isBlank())) return null;
            if (amrAssertsMfa(amr)) return Boolean.TRUE;
            if (acrAssertsMfa(acr)) return Boolean.TRUE;
            return Boolean.FALSE;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /**
     * The JSON of an ID token as Keycloak keeps it in the brokered context: the base64url payload of the token (what it
     * serialises), a whole compact JWT, or the JSON itself.
     */
    static String payloadJson(String data) {
        if (data == null || data.isBlank()) return null;
        String d = data.trim();
        if (d.startsWith("{")) return d;
        try {
            String[] parts = d.split("\\.");
            String payload = parts.length >= 2 ? parts[1] : parts[0];
            return new String(java.util.Base64.getUrlDecoder().decode(payload), java.nio.charset.StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** True when the method references prove two kinds of factor, or say so ({@code mfa}). */
    static boolean amrAssertsMfa(Set<String> amr) {
        if (amr.contains("mfa") || amr.contains("multifactor")) return true;
        int kinds = 0;
        if (amr.stream().anyMatch(KNOWLEDGE::contains)) kinds++;
        if (amr.stream().anyMatch(POSSESSION::contains)) kinds++;
        if (amr.stream().anyMatch(INHERENCE::contains)) kinds++;
        return kinds >= 2;
    }

    /** True for a numeric level of 2 or more (the level of Keycloak and of ISO 29115) or a context that names multiple factors. */
    static boolean acrAssertsMfa(String acr) {
        if (acr == null || acr.isBlank()) return false;
        String v = acr.trim().toLowerCase(Locale.ROOT);
        try {
            return Integer.parseInt(v) >= 2;
        } catch (NumberFormatException notANumber) {
            return v.contains("mfa") || v.contains("multi") || v.contains("2fa") || v.contains("twofactor")
                    || v.contains("phr") || v.contains("phishing");
        }
    }

    /**
     * The statement of a SAML assertion, given as the text Keycloak serialized: {@code TRUE} when its authentication
     * context names a multi-factor class, {@code FALSE} when it names another one, {@code null} when it names none.
     */
    static Boolean fromSamlAuthnStatement(String serialized) {
        if (serialized == null || serialized.isBlank()) return null;
        String v = serialized.toLowerCase(Locale.ROOT);
        if (!v.contains("classref") && !v.contains("authncontext") && !v.contains("urn:oasis:names:tc:saml:2.0:ac:classes")) return null;
        for (String marker : SAML_MULTI_FACTOR) {
            if (v.contains(marker)) return Boolean.TRUE;
        }
        return Boolean.FALSE;
    }

    private static Set<String> amrValues(JsonElement amr) {
        Set<String> out = new HashSet<>();
        if (amr == null || amr.isJsonNull()) return out;
        if (amr.isJsonArray()) {
            amr.getAsJsonArray().forEach(e -> {
                if (e.isJsonPrimitive()) out.add(e.getAsString().trim().toLowerCase(Locale.ROOT));
            });
        } else if (amr.isJsonPrimitive()) {
            out.add(amr.getAsString().trim().toLowerCase(Locale.ROOT));
        }
        out.remove("");
        return out;
    }
}

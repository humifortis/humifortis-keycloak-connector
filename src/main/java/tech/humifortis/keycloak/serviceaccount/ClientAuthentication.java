package tech.humifortis.keycloak.serviceaccount;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.x509.X509ClientCertificateLookup;

/**
 * How a client proved its identity at the token endpoint (docs/sso-and-external-idp-e2e.spec.md, P11): the method in the
 * vocabulary of Humifortis, and what the credential names.
 *
 * <p>Keycloak names the method by the id of its client authenticator ({@code client-secret}, {@code client-jwt}, ...). This
 * class translates it, so the core never learns the names of one identity provider: {@code secret}, {@code secret_jwt},
 * {@code signed_jwt}, {@code mtls}, {@code workload_identity}. A secretless method is stronger evidence than a shared
 * secret because there is nothing to copy; the rules of the core read that through the attribute
 * {@code service_account.secret_based}.</p>
 *
 * <p>What the credential names is the identity of a workload that has no secret to steal: the subject of the client
 * certificate ({@code mtls}), or the subject and the issuer of the signed token ({@code signed_jwt},
 * {@code workload_identity}). The token is read, never verified: Keycloak verified it before this point, and the value is only
 * a label for the analyst. A method this class does not know, or a credential it cannot read, is omitted, never guessed.</p>
 */
public final class ClientAuthentication {

    public static final String KEY_METHOD = "service_account.auth_method";
    public static final String KEY_SUBJECT = "service_account.auth_subject";

    static final int MAX_SUBJECT_CHARS = 255;

    private ClientAuthentication() {}

    /** The product's name of Keycloak's client authenticator, or null when it is not one the product names. */
    public static String canonicalMethod(String authenticatorId) {
        if (authenticatorId == null) return null;
        return switch (authenticatorId.trim()) {
            case "client-secret" -> "secret";
            case "client-secret-jwt" -> "secret_jwt";
            case "client-jwt" -> "signed_jwt";
            case "client-x509" -> "mtls";
            case "federated-jwt" -> "workload_identity";
            default -> null;
        };
    }

    /**
     * The attributes of the request: {@link #KEY_METHOD} and, when the credential names one, {@link #KEY_SUBJECT}.
     *
     * @param authenticatorId   Keycloak's client authenticator id (the client's setting, or the event's {@code client_auth_method})
     * @param clientAssertion   the {@code client_assertion} of the request, null for a secret or a certificate
     * @param certificateSubject the subject of the client certificate Keycloak accepted, null when there was none
     */
    public static Map<String, String> resolve(String authenticatorId, String clientAssertion, String certificateSubject) {
        Map<String, String> out = new LinkedHashMap<>();
        String method = canonicalMethod(authenticatorId);
        if (method == null) return out;
        out.put(KEY_METHOD, method);
        String subject = switch (method) {
            case "mtls" -> clean(certificateSubject);
            case "signed_jwt", "workload_identity" -> assertionSubject(clientAssertion);
            default -> null; // a shared secret names nobody
        };
        if (subject != null) out.put(KEY_SUBJECT, subject);
        return out;
    }


    /**
     * The subject of the client certificate of the request being served, or null when there is none. Keycloak behind a
     * TLS-terminating proxy reads the certificate from the header its x509cert-lookup provider is configured for; the chain
     * of the connection itself is the fallback. Never throws.
     */
    public static String certificateSubject(KeycloakSession session) {
        try {
            var request = session.getContext().getHttpRequest();
            if (request == null) return null;
            java.security.cert.X509Certificate[] chain = null;
            X509ClientCertificateLookup lookup = session.getProvider(X509ClientCertificateLookup.class);
            if (lookup != null) chain = lookup.getCertificateChain(request);
            if (chain == null || chain.length == 0) chain = request.getClientCertificateChain();
            return chain != null && chain.length > 0 ? clean(chain[0].getSubjectX500Principal().getName()) : null;
        } catch (Exception e) {
            return null;
        }
    }

    /** "sub@iss" of a compact JWT, or just the part that is present; null when it cannot be read. The signature is not checked. */
    static String assertionSubject(String jwt) {
        if (jwt == null || jwt.isBlank()) return null;
        String[] parts = jwt.trim().split("\\.");
        if (parts.length < 2) return null;
        try {
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            JsonObject claims = JsonParser.parseString(new String(payload, StandardCharsets.UTF_8)).getAsJsonObject();
            String sub = text(claims, "sub");
            String iss = text(claims, "iss");
            if (sub == null && iss == null) return null;
            if (sub == null) return clean(iss);
            if (iss == null || iss.equals(sub)) return clean(sub); // a client signing for itself names itself once
            return clean(sub + "@" + iss);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String text(JsonObject o, String name) {
        var v = o.get(name);
        if (v == null || !v.isJsonPrimitive()) return null;
        String s = v.getAsString();
        return s.isBlank() ? null : s;
    }

    private static String clean(String s) {
        if (s == null || s.isBlank()) return null;
        String t = s.trim();
        return t.length() > MAX_SUBJECT_CHARS ? t.substring(0, MAX_SUBJECT_CHARS) : t;
    }
}

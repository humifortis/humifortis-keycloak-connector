package tech.humifortis.keycloak.token;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Set;

import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;

/**
 * The key a client proved possession of at a token endpoint (DPoP, RFC 9449): evidence for Humifortis.
 *
 * Keycloak validates the proof (signature, method, URL, freshness, replay) and binds the token it issues to the key
 * ({@code cnf.jkt}); a proof it refuses fails the request, which the connector already reports as
 * {@code auth_token_binding_failed}. This class reports the other half: when the request SUCCEEDED and carried a proof, the
 * thumbprint of the key (RFC 7638) travels with the event, so that a client or a person's token that suddenly proves another
 * key can be told from one that always proved the same.
 *
 * The connector never validates a proof itself: it reads the key from the header of a proof Keycloak has just accepted. A
 * request with a proof but without success, or without a key it can read, reports nothing.
 */
public final class DpopProof {

    /** Event detail the thumbprint travels in (the mapper turns it into the metadata {@code dpop_jkt}). */
    public static final String DETAIL_JKT = "dpop_jkt";

    private static final Set<EventType> TOKEN_SUCCESSES = Set.of(
            EventType.LOGIN, EventType.CLIENT_LOGIN, EventType.REFRESH_TOKEN, EventType.TOKEN_EXCHANGE, EventType.OAUTH2_DEVICE_CODE_TO_TOKEN);

    private DpopProof() {}

    /** Adds the thumbprint of the proved key to the details of a successful token event, when the request carried a proof. */
    public static void attribute(KeycloakSession session, Event event) {
        if (event.getError() != null || !TOKEN_SUCCESSES.contains(event.getType())) return;
        try {
            var request = session.getContext().getHttpRequest();
            if (request == null) return;
            String jkt = thumbprintOf(request.getHttpHeaders().getHeaderString("DPoP"));
            if (jkt == null) return;
            if (event.getDetails() == null) event.setDetails(new java.util.HashMap<>());
            event.getDetails().put(DETAIL_JKT, jkt);
        } catch (RuntimeException e) {
            // evidence is best effort: a header that cannot be read never disturbs the token request
        }
    }

    /** The RFC 7638 thumbprint of the key in the header of a DPoP proof (EC, OKP and RSA keys), or null. */
    static String thumbprintOf(String proof) {
        if (proof == null || proof.isBlank() || proof.length() > 16_384) return null;
        try {
            JWK jwk = new JWSInput(proof.trim()).getHeader().getKey();
            return jwk == null ? null : thumbprint(jwk);
        } catch (Exception e) {
            return null;
        }
    }

    static String thumbprint(JWK jwk) throws Exception {
        String kty = jwk.getKeyType();
        if (kty == null) return null;
        // the required members, in lexicographic order, no whitespace (RFC 7638, section 3)
        String canonical = switch (kty) {
            case "EC" -> member(jwk, "crv", "kty", "x", "y");
            case "OKP" -> member(jwk, "crv", "kty", "x");
            case "RSA" -> member(jwk, "e", "kty", "n");
            default -> null;
        };
        if (canonical == null) return null;
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private static String member(JWK jwk, String... names) {
        StringBuilder out = new StringBuilder("{");
        for (int i = 0; i < names.length; i++) {
            String value = "kty".equals(names[i]) ? jwk.getKeyType() : jwk.getOtherClaim(names[i], String.class);
            if (value == null || value.isEmpty()) return null;
            if (i > 0) out.append(',');
            out.append('"').append(names[i]).append("\":\"").append(value).append('"');
        }
        return out.append('}').toString();
    }
}

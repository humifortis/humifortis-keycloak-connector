package tech.humifortis.keycloak.caep;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import org.junit.jupiter.api.Test;

/**
 * CRY-5 (receiver side): Humifortis rotates the key it signs events with and publishes the set. The receiver follows the
 * published set by the key id of each event: an event signed with the previous key is accepted while the set still publishes it
 * (the rotation window) and refused once the key is retired.
 */
class CaepKeyRotationTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
    private static final CaepConfig CONFIG = new CaepConfig(true, "https://issuer.test", "keycloak-realm", "https://jwks.test", 60, true, 600, true, true, true, true, false);

    private static KeyPair newKey() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }

    private static JsonObject jwk(String kid, KeyPair pair) {
        RSAPublicKey pub = (RSAPublicKey) pair.getPublic();
        JsonObject o = new JsonObject();
        o.addProperty("kty", "RSA");
        o.addProperty("kid", kid);
        o.addProperty("n", unsigned(pub.getModulus().toByteArray()));
        o.addProperty("e", unsigned(pub.getPublicExponent().toByteArray()));
        return o;
    }

    private static String unsigned(byte[] v) {
        int offset = (v.length > 1 && v[0] == 0) ? 1 : 0;
        byte[] u = new byte[v.length - offset];
        System.arraycopy(v, offset, u, 0, u.length);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(u);
    }

    private static String token(String kid, KeyPair signer) throws Exception {
        String header = "{\"alg\":\"RS256\",\"kid\":\"" + kid + "\",\"typ\":\"secevent+jwt\"}";
        String payload = ("{\"iss\":\"https://issuer.test\",\"aud\":\"keycloak-realm\",\"iat\":1767225570,\"exp\":1767225900,\"jti\":\"j-" + kid
                + "\",\"sub\":\"user-1\",\"events\":{\"https://schemas.openid.net/secevent/caep/event-type/session-revoked\":{}}}");
        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
        String input = enc.encodeToString(header.getBytes(StandardCharsets.UTF_8)) + "." + enc.encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(signer.getPrivate());
        s.update(input.getBytes(StandardCharsets.UTF_8));
        return input + "." + enc.encodeToString(s.sign());
    }

    @Test
    void anEventSignedWithThePreviousKeyIsAcceptedDuringTheWindowAndRefusedAfterTheRetirement() throws Exception {
        KeyPair previous = newKey();
        KeyPair current = newKey();
        JsonArray during = new JsonArray();
        during.add(jwk("caep-new", current));
        during.add(jwk("caep-old", previous));
        JsonArray afterRetirement = new JsonArray();
        afterRetirement.add(jwk("caep-new", current));

        String signedWithOld = token("caep-old", previous);
        String signedWithNew = token("caep-new", current);

        CaepSetValidator inWindow = new CaepSetValidator(uri -> during, CLOCK);
        assertEquals("j-caep-old", inWindow.validate(signedWithOld, CONFIG).jti(), "the previous key is still published: no event is lost during the rotation");
        assertEquals("j-caep-new", inWindow.validate(signedWithNew, CONFIG).jti());

        CaepSetValidator retired = new CaepSetValidator(uri -> afterRetirement, CLOCK);
        assertEquals("j-caep-new", retired.validate(signedWithNew, CONFIG).jti(), "the new key keeps working");
        CaepValidationException ex = assertThrows(CaepValidationException.class, () -> retired.validate(signedWithOld, CONFIG));
        assertEquals(401, ex.getStatusCode());
        assertTrue(ex.getMessage().contains("No matching key"), "refused because the retired key is no longer published: " + ex.getMessage());
    }

    @Test
    void aRetiredKeyIdCannotBeSignedAgainWithAnotherKey() throws Exception {
        KeyPair current = newKey();
        KeyPair attacker = newKey();
        JsonArray published = new JsonArray();
        published.add(jwk("caep-new", current));
        CaepSetValidator validator = new CaepSetValidator(uri -> published, CLOCK);
        // the attacker claims the current key id but signs with a key of his own
        assertThrows(CaepValidationException.class, () -> validator.validate(token("caep-new", attacker), CONFIG));
    }
}

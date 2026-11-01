package tech.humifortis.keycloak.caep;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class CaepSetValidatorTest {
    private KeyPair keyPair;
    private JsonArray jwks;
    private CaepConfig config;
    private Clock clock;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        JsonObject key = new JsonObject();
        key.addProperty("kty", "RSA");
        key.addProperty("kid", "kid-1");
        key.addProperty("n", toUnsignedBase64Url(publicKey.getModulus().toByteArray()));
        key.addProperty("e", toUnsignedBase64Url(publicKey.getPublicExponent().toByteArray()));
        jwks = new JsonArray();
        jwks.add(key);

        clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
        config = new CaepConfig(true, "https://issuer.test", "keycloak-realm", "https://jwks.test", 60, true, 600, true, true, true, true, false);
    }

    @Test
    void validatesSignedToken() throws Exception {
        CaepSetValidator validator = new CaepSetValidator(uri -> jwks, clock);
        String token = buildToken("https://issuer.test", "keycloak-realm", Instant.parse("2025-12-31T23:59:30Z").getEpochSecond(), Instant.parse("2026-01-01T00:05:00Z").getEpochSecond(), "j-1");

        CaepParsedSet parsed = validator.validate(token, config);

        assertEquals("j-1", parsed.jti());
        assertEquals("https://issuer.test", parsed.issuer());
        assertTrue(parsed.events().has("https://schemas.openid.net/secevent/caep/event-type/session-revoked"));
    }

    @Test
    void rejectsInvalidSignature() throws Exception {
        CaepSetValidator validator = new CaepSetValidator(uri -> jwks, clock);
        String token = buildToken("https://issuer.test", "keycloak-realm", Instant.parse("2025-12-31T23:59:30Z").getEpochSecond(), Instant.parse("2026-01-01T00:05:00Z").getEpochSecond(), "j-2");
        String tamperedToken = token.substring(0, token.length() - 2) + "aa";

        CaepValidationException ex = assertThrows(CaepValidationException.class, () -> validator.validate(tamperedToken, config));
        assertEquals(401, ex.getStatusCode());
    }

    @Test
    void rejectsIssuerAndAudienceMismatch() throws Exception {
        CaepSetValidator validator = new CaepSetValidator(uri -> jwks, clock);
        String badIssuer = buildToken("https://evil.test", "keycloak-realm", Instant.parse("2025-12-31T23:59:30Z").getEpochSecond(), Instant.parse("2026-01-01T00:05:00Z").getEpochSecond(), "j-3");
        CaepValidationException issuerEx = assertThrows(CaepValidationException.class, () -> validator.validate(badIssuer, config));
        assertEquals(401, issuerEx.getStatusCode());

        String badAud = buildToken("https://issuer.test", "wrong-aud", Instant.parse("2025-12-31T23:59:30Z").getEpochSecond(), Instant.parse("2026-01-01T00:05:00Z").getEpochSecond(), "j-4");
        CaepValidationException audEx = assertThrows(CaepValidationException.class, () -> validator.validate(badAud, config));
        assertEquals(401, audEx.getStatusCode());
    }

    @Test
    void rejectsMalformedAndExpiredToken() throws Exception {
        CaepSetValidator validator = new CaepSetValidator(uri -> jwks, clock);
        CaepValidationException malformed = assertThrows(CaepValidationException.class, () -> validator.validate("abc", config));
        assertEquals(400, malformed.getStatusCode());

        String expired = buildToken("https://issuer.test", "keycloak-realm", Instant.parse("2025-12-31T23:00:00Z").getEpochSecond(), Instant.parse("2025-12-31T23:10:00Z").getEpochSecond(), "j-5");
        CaepValidationException expiredEx = assertThrows(CaepValidationException.class, () -> validator.validate(expired, config));
        assertEquals(400, expiredEx.getStatusCode());
    }

    @Test
    void rejectsMissingAndEmptyEventsClaim() throws Exception {
        CaepSetValidator validator = new CaepSetValidator(uri -> jwks, clock);
        String missingEvents = buildTokenFromPayload("""
                {
                  "iss":"https://issuer.test",
                  "aud":"keycloak-realm",
                  "iat":1767225570,
                  "exp":1767225900,
                  "jti":"j-6",
                  "sub":"user-1",
                  "sid":"sess-1"
                }
                """);
        CaepValidationException missing = assertThrows(CaepValidationException.class, () -> validator.validate(missingEvents, config));
        assertEquals(400, missing.getStatusCode());

        String emptyEvents = buildTokenFromPayload("""
                {
                  "iss":"https://issuer.test",
                  "aud":"keycloak-realm",
                  "iat":1767225570,
                  "exp":1767225900,
                  "jti":"j-7",
                  "sub":"user-1",
                  "sid":"sess-1",
                  "events":{}
                }
                """);
        CaepValidationException empty = assertThrows(CaepValidationException.class, () -> validator.validate(emptyEvents, config));
        assertEquals(400, empty.getStatusCode());
    }

    private String buildToken(String issuer, String audience, long iat, long exp, String jti) throws Exception {
        String header = "{\"alg\":\"RS256\",\"kid\":\"kid-1\",\"typ\":\"secevent+jwt\"}";
        String payload = """
                {
                  "iss":"%s",
                  "aud":"%s",
                  "iat":%d,
                  "exp":%d,
                  "jti":"%s",
                  "sub":"user-1",
                  "sid":"sess-1",
                  "events":{"https://schemas.openid.net/secevent/caep/event-type/session-revoked":{"decision_id":"d-1"}}
                }
                """.formatted(issuer, audience, iat, exp, jti).replace("\n", "").replace(" ", "");
        String encodedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes(StandardCharsets.UTF_8));
        String encodedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        return sign(encodedHeader, encodedPayload);
    }

    private String buildTokenFromPayload(String payload) throws Exception {
        String header = "{\"alg\":\"RS256\",\"kid\":\"kid-1\",\"typ\":\"secevent+jwt\"}";
        String encodedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes(StandardCharsets.UTF_8));
        String encodedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(payload.replace("\n", "").replace(" ", "").getBytes(StandardCharsets.UTF_8));
        return sign(encodedHeader, encodedPayload);
    }

    private String sign(String encodedHeader, String encodedPayload) throws Exception {
        String signingInput = encodedHeader + "." + encodedPayload;

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(signingInput.getBytes(StandardCharsets.UTF_8));
        String encodedSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(signature.sign());
        return signingInput + "." + encodedSignature;
    }

    private String toUnsignedBase64Url(byte[] value) {
        int offset = (value.length > 1 && value[0] == 0) ? 1 : 0;
        byte[] unsigned = new byte[value.length - offset];
        System.arraycopy(value, offset, unsigned, 0, unsigned.length);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(unsigned);
    }
}

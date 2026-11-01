package tech.humifortis.keycloak.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.Test;

class DpopProofTest {

    private static String b64(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    /** A proof whose signature nobody checks here: Keycloak did. Only its header matters. */
    private static String proofWith(String jwk) {
        return b64("{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":" + jwk + "}") + "." + b64("{\"htm\":\"POST\"}") + "." + b64("sig");
    }

    @Test
    void theThumbprintOfAnRsaKeyIsTheOneOfRfc7638() {
        // RFC 7638, section 3.1
        String jwk = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
        assertEquals("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", DpopProof.thumbprintOf(proofWith(jwk)));
    }

    @Test
    void anEcKeyHasItsRequiredMembersOnly() {
        // RFC 9449, section 4.1 example key
        String jwk = "{\"kty\":\"EC\",\"x\":\"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs\",\"y\":\"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA\",\"crv\":\"P-256\",\"use\":\"sig\",\"kid\":\"x\"}";
        assertEquals("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I", DpopProof.thumbprintOf(proofWith(jwk)));
    }

    @Test
    void anythingItCannotReadGivesNothing() {
        assertNull(DpopProof.thumbprintOf(null));
        assertNull(DpopProof.thumbprintOf(""));
        assertNull(DpopProof.thumbprintOf("not.a.jwt"));
        assertNull(DpopProof.thumbprintOf(b64("{\"typ\":\"dpop+jwt\"}") + "." + b64("{}") + "." + b64("s")), "no key");
        assertNull(DpopProof.thumbprintOf(proofWith("{\"kty\":\"oct\",\"k\":\"AAAA\"}")), "a symmetric key is never a DPoP key");
        assertNull(DpopProof.thumbprintOf(proofWith("{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"abc\"}")), "a member is missing");
        assertNull(DpopProof.thumbprintOf("a".repeat(20_000)), "bounded");
    }
}

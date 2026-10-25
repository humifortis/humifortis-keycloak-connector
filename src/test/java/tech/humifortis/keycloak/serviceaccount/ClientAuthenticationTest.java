package tech.humifortis.keycloak.serviceaccount;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import org.junit.jupiter.api.Test;

class ClientAuthenticationTest {

    private static String jwt(String payloadJson) {
        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
        return enc.encodeToString("{\"alg\":\"RS256\"}".getBytes(StandardCharsets.UTF_8)) + "."
                + enc.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8)) + ".signature";
    }

    @Test
    void keycloakAuthenticatorsAreNamedInTheProductVocabulary() {
        assertEquals("secret", ClientAuthentication.canonicalMethod("client-secret"));
        assertEquals("secret_jwt", ClientAuthentication.canonicalMethod("client-secret-jwt"));
        assertEquals("signed_jwt", ClientAuthentication.canonicalMethod("client-jwt"));
        assertEquals("mtls", ClientAuthentication.canonicalMethod("client-x509"));
        assertEquals("workload_identity", ClientAuthentication.canonicalMethod("federated-jwt"));
    }

    @Test
    void aMethodTheProductDoesNotNameIsOmittedNeverGuessed() {
        assertNull(ClientAuthentication.canonicalMethod(null));
        assertNull(ClientAuthentication.canonicalMethod(""));
        assertNull(ClientAuthentication.canonicalMethod("some-custom-authenticator"));
        assertTrue(ClientAuthentication.resolve("some-custom-authenticator", null, null).isEmpty());
    }

    @Test
    void aSecretNamesNobody() {
        Map<String, String> out = ClientAuthentication.resolve("client-secret", null, "CN=ignored");
        assertEquals(Map.of(ClientAuthentication.KEY_METHOD, "secret"), out);
        assertEquals(Map.of(ClientAuthentication.KEY_METHOD, "secret_jwt"),
                ClientAuthentication.resolve("client-secret-jwt", jwt("{\"sub\":\"svc\"}"), null),
                "a token signed with the shared secret is still a shared secret: it names nobody");
    }

    @Test
    void aSignedTokenNamesItsSubjectAndItsIssuer() {
        Map<String, String> out = ClientAuthentication.resolve("client-jwt", jwt("{\"iss\":\"billing-job\",\"sub\":\"billing-job\"}"), null);
        assertEquals("signed_jwt", out.get(ClientAuthentication.KEY_METHOD));
        assertEquals("billing-job", out.get(ClientAuthentication.KEY_SUBJECT), "a client signing for itself names itself once");
    }

    @Test
    void aWorkloadIdentityIsTheIssuerAndSubjectOfThePlatformToken() {
        Map<String, String> out = ClientAuthentication.resolve("federated-jwt",
                jwt("{\"iss\":\"https://kubernetes.default.svc\",\"sub\":\"system:serviceaccount:payments:api\"}"), null);
        assertEquals("workload_identity", out.get(ClientAuthentication.KEY_METHOD));
        assertEquals("system:serviceaccount:payments:api@https://kubernetes.default.svc", out.get(ClientAuthentication.KEY_SUBJECT));
    }

    @Test
    void aCertificateNamesItsSubject() {
        Map<String, String> out = ClientAuthentication.resolve("client-x509", null, "CN=billing-job,O=Example");
        assertEquals("mtls", out.get(ClientAuthentication.KEY_METHOD));
        assertEquals("CN=billing-job,O=Example", out.get(ClientAuthentication.KEY_SUBJECT));
        assertFalse(ClientAuthentication.resolve("client-x509", null, null).containsKey(ClientAuthentication.KEY_SUBJECT),
                "no certificate seen: no subject");
    }

    @Test
    void anUnreadableTokenGivesNoSubjectButKeepsTheMethod() {
        for (String bad : new String[] {null, "", "not-a-jwt", "a.b.c", "x." + Base64.getUrlEncoder().withoutPadding().encodeToString("[]".getBytes(StandardCharsets.UTF_8)) + ".y"}) {
            Map<String, String> out = ClientAuthentication.resolve("client-jwt", bad, null);
            assertEquals("signed_jwt", out.get(ClientAuthentication.KEY_METHOD), String.valueOf(bad));
            assertFalse(out.containsKey(ClientAuthentication.KEY_SUBJECT), String.valueOf(bad));
        }
    }

    @Test
    void aSubjectIsBounded() {
        String longSub = "s".repeat(1000);
        String subject = ClientAuthentication.assertionSubject(jwt("{\"sub\":\"" + longSub + "\"}"));
        assertEquals(ClientAuthentication.MAX_SUBJECT_CHARS, subject.length());
    }
}

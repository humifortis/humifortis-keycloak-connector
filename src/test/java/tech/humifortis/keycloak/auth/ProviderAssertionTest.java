package tech.humifortis.keycloak.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

import org.junit.jupiter.api.Test;

/** What an identity provider says about how the person authenticated (P4, ID-9). Reported, never trusted here. */
class ProviderAssertionTest {

    @Test
    void anAmrWithTwoKindsOfFactorIsMultiFactor() {
        assertEquals(Boolean.TRUE, ProviderAssertion.fromIdToken("{\"sub\":\"1\",\"amr\":[\"pwd\",\"otp\"]}"));
        assertEquals(Boolean.TRUE, ProviderAssertion.fromIdToken("{\"amr\":[\"pwd\",\"hwk\"]}"));
        assertEquals(Boolean.TRUE, ProviderAssertion.fromIdToken("{\"amr\":[\"PWD\",\"Fpt\"]}"), "case does not matter");
    }

    @Test
    void theMfaReferenceSaysSoItself() {
        assertEquals(Boolean.TRUE, ProviderAssertion.fromIdToken("{\"amr\":[\"mfa\"]}"));
        assertEquals(Boolean.TRUE, ProviderAssertion.fromIdToken("{\"amr\":\"mfa\"}"), "a single string is read too");
    }

    @Test
    void oneKindOfFactorIsNotMultiFactor() {
        assertEquals(Boolean.FALSE, ProviderAssertion.fromIdToken("{\"amr\":[\"pwd\"]}"));
        assertEquals(Boolean.FALSE, ProviderAssertion.fromIdToken("{\"amr\":[\"otp\",\"sms\"]}"), "two codes are one kind (possession)");
        assertEquals(Boolean.FALSE, ProviderAssertion.fromIdToken("{\"amr\":[\"something-new\"]}"), "an unknown reference proves nothing");
    }

    @Test
    void anAcrOfLevelTwoOrMoreIsMultiFactorWhenThereIsNoAmr() {
        assertEquals(Boolean.TRUE, ProviderAssertion.fromIdToken("{\"acr\":\"2\"}"));
        assertEquals(Boolean.TRUE, ProviderAssertion.fromIdToken("{\"acr\":\"3\"}"));
        assertEquals(Boolean.TRUE, ProviderAssertion.fromIdToken("{\"acr\":\"urn:example:mfa\"}"));
        assertEquals(Boolean.FALSE, ProviderAssertion.fromIdToken("{\"acr\":\"1\"}"), "Keycloak's level for a password");
        assertEquals(Boolean.FALSE, ProviderAssertion.fromIdToken("{\"acr\":\"0\"}"));
    }

    @Test
    void aProviderThatSaysNothingIsNotSaidToHaveRefused() {
        assertNull(ProviderAssertion.fromIdToken("{\"sub\":\"1\",\"email\":\"a@b.c\"}"));
        assertNull(ProviderAssertion.fromIdToken("{\"acr\":\"\"}"));
    }

    @Test
    void anUnreadableTokenIsNothing() {
        assertNull(ProviderAssertion.fromIdToken(null));
        assertNull(ProviderAssertion.fromIdToken(""));
        assertNull(ProviderAssertion.fromIdToken("{not json"));
        assertNull(ProviderAssertion.fromIdToken("[\"amr\"]"));
    }

    @Test
    void theHelpersAgree() {
        assertTrue(ProviderAssertion.amrAssertsMfa(Set.of("pwd", "swk")));
        assertFalse(ProviderAssertion.amrAssertsMfa(Set.of("pwd")));
        assertFalse(ProviderAssertion.amrAssertsMfa(Set.of()));
        assertFalse(ProviderAssertion.acrAssertsMfa(null));
    }

    @Test
    void aSamlAuthenticationContextIsReadFromTheSerializedStatement() {
        assertEquals(Boolean.TRUE, ProviderAssertion.fromSamlAuthnStatement(
                "{\"authnContext\":{\"sequence\":{\"classRef\":\"urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken\"}}}"));
        assertEquals(Boolean.TRUE, ProviderAssertion.fromSamlAuthnStatement(
                "{\"authnContext\":{\"classRef\":\"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract\"}}"));
        assertEquals(Boolean.FALSE, ProviderAssertion.fromSamlAuthnStatement(
                "{\"authnContext\":{\"classRef\":\"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport\"}}"));
        assertNull(ProviderAssertion.fromSamlAuthnStatement("{\"sessionIndex\":\"s1\"}"), "no context named");
        assertNull(ProviderAssertion.fromSamlAuthnStatement(null));
    }

    @Test
    void theTokenAsKeycloakKeepsItIsTheBase64PayloadOrACompactJwt() {
        String json = "{\"amr\":[\"pwd\",\"otp\"]}";
        String payload = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        assertEquals(Boolean.TRUE, ProviderAssertion.fromIdToken(payload));
        assertEquals(Boolean.TRUE, ProviderAssertion.fromIdToken("eyJhbGciOiJub25lIn0." + payload + ".sig"));
        assertEquals(Boolean.TRUE, ProviderAssertion.fromIdToken(json));
        assertNull(ProviderAssertion.fromIdToken("not base64 !!"));
    }
}

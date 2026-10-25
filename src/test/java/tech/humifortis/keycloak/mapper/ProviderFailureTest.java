package tech.humifortis.keycloak.mapper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.keycloak.events.EventType;

class ProviderFailureTest {

    @Test
    void onlyTheFailureOfAProviderSignIn() {
        assertTrue(ProviderFailure.is(EventType.IDENTITY_PROVIDER_LOGIN_ERROR, "identity_provider_login_failure"));
        assertTrue(ProviderFailure.is(EventType.IDENTITY_PROVIDER_LOGIN_ERROR, null), "the round trip failed whatever the code");
        assertFalse(ProviderFailure.is(EventType.LOGIN_ERROR, "invalid_user_credentials"), "a wrong password is a person's");
        assertFalse(ProviderFailure.is(EventType.IDENTITY_PROVIDER_FIRST_LOGIN_ERROR, "x"), "our own first-login flow, not the provider");
        assertFalse(ProviderFailure.is(EventType.IDENTITY_PROVIDER_RESPONSE_ERROR, "access_denied"), "the provider answered: a person refused or cancelled");
        assertFalse(ProviderFailure.is(EventType.IDENTITY_PROVIDER_RESPONSE_ERROR, null), "no code: not attributable");
    }

    @Test
    void aSamlResponseKeycloakRefusesToTrustIsAFailureOfTheProvider() {
        for (String code : new String[] {"invalid_signature", "invalid_saml_response", "invalid_saml_document", "invalid_destination",
                "missing_required_destination", "invalid_artifact_response"}) {
            assertTrue(ProviderFailure.is(EventType.IDENTITY_PROVIDER_RESPONSE_ERROR, code), code);
        }
        assertFalse(ProviderFailure.is(EventType.LOGIN_ERROR, "invalid_signature"), "only a provider's response counts");
    }

    @Test
    void theAliasIsTheOneOfTheBrokerCallback() {
        assertEquals("corp-idp", ProviderFailure.aliasOf("/auth/realms/demo/broker/corp-idp/endpoint"));
        assertEquals("corp-faulty", ProviderFailure.aliasOf("/realms/demo/broker/corp-faulty/endpoint/"));
        assertEquals("corp-idp", ProviderFailure.aliasOf("/realms/demo/broker/corp-idp/login"));
        assertEquals("my idp", ProviderFailure.aliasOf("/realms/demo/broker/my%20idp/endpoint"), "decoded");
    }

    @Test
    void aPathThatIsNotABrokerCallbackNamesNoProvider() {
        assertNull(ProviderFailure.aliasOf(null));
        assertNull(ProviderFailure.aliasOf(""));
        assertNull(ProviderFailure.aliasOf("/realms/demo/protocol/openid-connect/auth"), "never a guess");
        assertNull(ProviderFailure.aliasOf("/realms/demo/broker//endpoint"));
    }
}

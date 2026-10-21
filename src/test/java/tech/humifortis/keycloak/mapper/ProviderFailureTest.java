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
        assertTrue(ProviderFailure.is(EventType.IDENTITY_PROVIDER_LOGIN_ERROR));
        assertFalse(ProviderFailure.is(EventType.LOGIN_ERROR), "a wrong password is a person's");
        assertFalse(ProviderFailure.is(EventType.IDENTITY_PROVIDER_FIRST_LOGIN_ERROR), "our own first-login flow, not the provider");
        assertFalse(ProviderFailure.is(EventType.IDENTITY_PROVIDER_RESPONSE_ERROR), "the provider answered: a person refused or cancelled");
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

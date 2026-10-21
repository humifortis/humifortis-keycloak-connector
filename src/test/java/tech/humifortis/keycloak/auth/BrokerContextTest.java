package tech.humifortis.keycloak.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.PostBrokerLoginConstants;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

class BrokerContextTest {

    private final Map<String, String> notes = new HashMap<>();
    private AuthenticationSessionModel as;

    @BeforeEach
    void setUp() {
        as = mock(AuthenticationSessionModel.class);
        // Keycloak's own reader asks the realm how usernames are built
        lenient().when(as.getRealm()).thenReturn(mock(RealmModel.class));
        lenient().when(as.getAuthNote(anyString())).thenAnswer(i -> notes.get((String) i.getArgument(0)));
    }

    /** What Keycloak itself writes into the authentication session for a brokered identity. */
    private void brokered(String note, String alias) throws Exception {
        SerializedBrokeredIdentityContext ctx = new SerializedBrokeredIdentityContext();
        ctx.setId("id-1");
        ctx.setIdentityProviderId(alias);
        notes.put(note, JsonSerialization.writeValueAsString(ctx));
    }

    @Test
    void aPasswordLoginIsLocal() {
        assertEquals("local", BrokerContext.identityProvider(as));
        assertFalse(BrokerContext.firstBrokerLogin(as));
        assertNull(BrokerContext.firstBrokerLoginOf(as), "no provider: the question does not apply");
    }

    @Test
    void noAuthenticationSessionIsLocal() {
        assertEquals("local", BrokerContext.identityProvider(null));
        assertFalse(BrokerContext.firstBrokerLogin(null));
    }

    @Test
    void aPostLoginFlowNamesTheProvider() throws Exception {
        brokered(PostBrokerLoginConstants.PBL_BROKERED_IDENTITY_CONTEXT, "corp-idp");
        assertEquals("corp-idp", BrokerContext.identityProvider(as));
        assertFalse(BrokerContext.firstBrokerLogin(as), "an existing account: not a first login");
        assertEquals("false", BrokerContext.firstBrokerLoginOf(as), "a later brokered sign-in is a known false");
    }

    @Test
    void theFirstBrokerLoginFlowNamesTheProviderAndIsFirst() throws Exception {
        brokered(AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE, "corp-idp");
        assertEquals("corp-idp", BrokerContext.identityProvider(as));
        assertTrue(BrokerContext.firstBrokerLogin(as));
        assertEquals("true", BrokerContext.firstBrokerLoginOf(as));
    }

    @Test
    void theAfterFirstBrokerLoginMarkIsAFirstLogin() throws Exception {
        brokered(PostBrokerLoginConstants.PBL_BROKERED_IDENTITY_CONTEXT, "corp-idp");
        notes.put(PostBrokerLoginConstants.PBL_AFTER_FIRST_BROKER_LOGIN, "true");
        assertTrue(BrokerContext.firstBrokerLogin(as));
    }

    @Test
    void anUnreadableNoteIsNeverAnError() {
        notes.put(PostBrokerLoginConstants.PBL_BROKERED_IDENTITY_CONTEXT, "{not json");
        assertEquals("local", BrokerContext.identityProvider(as));
    }
}

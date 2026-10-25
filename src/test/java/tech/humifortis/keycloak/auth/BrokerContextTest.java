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
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.PostBrokerLoginConstants;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
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

    /** A brokered identity whose context data carries the entries Keycloak keeps for the provider's answer. */
    private void brokeredWith(String note, String alias, Map<String, String> contextData) throws Exception {
        SerializedBrokeredIdentityContext ctx = new SerializedBrokeredIdentityContext();
        ctx.setId("id-1");
        ctx.setIdentityProviderId(alias);
        Map<String, SerializedBrokeredIdentityContext.ContextDataEntry> entries = new HashMap<>();
        contextData.forEach((k, v) -> entries.put(k, SerializedBrokeredIdentityContext.ContextDataEntry.create("java.lang.String", v)));
        ctx.setContextData(entries);
        notes.put(note, JsonSerialization.writeValueAsString(ctx));
    }

    @Test
    void anAccountCreatedAtTheFirstBrokerLoginIsNotLinked() throws Exception {
        brokered(AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE, "corp-idp");
        notes.put(BrokerContext.NOTE_REGISTERED_NEW_USER, "true");
        assertEquals("false", BrokerContext.accountLinkedOf(as));
    }

    @Test
    void anExistingAccountTheFirstBrokerLoginMetIsLinked() throws Exception {
        brokered(AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE, "corp-idp");
        assertEquals("true", BrokerContext.accountLinkedOf(as), "no new user was registered: the account existed");
    }

    @Test
    void theLinkQuestionOnlyAppliesToAFirstBrokerLogin() throws Exception {
        assertNull(BrokerContext.accountLinkedOf(as), "no provider");
        brokered(PostBrokerLoginConstants.PBL_BROKERED_IDENTITY_CONTEXT, "corp-idp");
        assertNull(BrokerContext.accountLinkedOf(as), "a later sign-in is not a linking");
        assertNull(BrokerContext.accountLinkedOf(null));
    }

    @Test
    void theRealmsTrustInTheProvidersEmailIsReported() throws Exception {
        brokered(PostBrokerLoginConstants.PBL_BROKERED_IDENTITY_CONTEXT, "corp-idp");
        RealmModel realm = mock(RealmModel.class);
        IdentityProviderModel provider = new IdentityProviderModel();
        provider.setAlias("corp-idp");
        provider.setTrustEmail(true);
        lenient().when(realm.getIdentityProviderByAlias("corp-idp")).thenReturn(provider);
        assertEquals("true", BrokerContext.emailTrustedOf(as, realm));
        provider.setTrustEmail(false);
        assertEquals("false", BrokerContext.emailTrustedOf(as, realm));
    }

    @Test
    void noEmailTrustWithoutAProvider() throws Exception {
        RealmModel realm = mock(RealmModel.class);
        assertNull(BrokerContext.emailTrustedOf(as, realm), "a password sign-in has no provider");
        brokered(PostBrokerLoginConstants.PBL_BROKERED_IDENTITY_CONTEXT, "gone");
        assertNull(BrokerContext.emailTrustedOf(as, realm), "a provider the realm no longer has");
    }

    @Test
    void aProviderThatAssertsTwoFactorsIsReported() throws Exception {
        brokeredWith(PostBrokerLoginConstants.PBL_BROKERED_IDENTITY_CONTEXT, "corp-idp",
                Map.of("VALIDATED_ID_TOKEN", "{\"sub\":\"1\",\"acr\":\"1\",\"amr\":[\"pwd\",\"otp\"]}"));
        assertEquals("true", BrokerContext.assertedMfaOf(as));
    }

    @Test
    void aProviderThatDescribesAPasswordSignInIsReportedAsNotMfa() throws Exception {
        brokeredWith(PostBrokerLoginConstants.PBL_BROKERED_IDENTITY_CONTEXT, "corp-idp",
                Map.of("VALIDATED_ID_TOKEN", "{\"sub\":\"1\",\"acr\":\"1\"}"));
        assertEquals("false", BrokerContext.assertedMfaOf(as));
    }

    @Test
    void aProviderThatSaysNothingAboutHowIsNotReported() throws Exception {
        brokeredWith(PostBrokerLoginConstants.PBL_BROKERED_IDENTITY_CONTEXT, "corp-idp", Map.of("VALIDATED_ID_TOKEN", "{\"sub\":\"1\"}"));
        assertNull(BrokerContext.assertedMfaOf(as));
        brokered(PostBrokerLoginConstants.PBL_BROKERED_IDENTITY_CONTEXT, "corp-idp");
        assertNull(BrokerContext.assertedMfaOf(as), "no context data at all");
        notes.clear();
        assertNull(BrokerContext.assertedMfaOf(as), "no provider");
    }

    @Test
    void aSamlProviderIsReadFromItsAuthenticationStatement() throws Exception {
        brokeredWith(PostBrokerLoginConstants.PBL_BROKERED_IDENTITY_CONTEXT, "corp-saml",
                Map.of("SAML_AUTHN_STATEMENT", "{\"authnContext\":{\"classRef\":\"urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken\"}}"));
        assertEquals("true", BrokerContext.assertedMfaOf(as));
    }

    @Test
    void theProvidersAnAccountIsLinkedToAreListedSorted() {
        KeycloakSession session = mock(KeycloakSession.class);
        UserProvider users = mock(UserProvider.class);
        RealmModel realm = mock(RealmModel.class);
        UserModel user = mock(UserModel.class);
        lenient().when(session.users()).thenReturn(users);
        lenient().when(users.getFederatedIdentitiesStream(realm, user)).thenReturn(Stream.of(
                new FederatedIdentityModel("corp-social", "u2", "n"), new FederatedIdentityModel("corp-idp", "u1", "n")));
        assertEquals("corp-idp,corp-social", BrokerContext.linkedProvidersOf(session, realm, user));
        lenient().when(users.getFederatedIdentitiesStream(realm, user)).thenReturn(Stream.empty());
        assertNull(BrokerContext.linkedProvidersOf(session, realm, user), "none linked: nothing sent");
        assertNull(BrokerContext.linkedProvidersOf(session, realm, null));
    }
}

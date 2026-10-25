package tech.humifortis.keycloak.caep;

import com.google.gson.JsonObject;
import org.junit.jupiter.api.Test;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.UserSessionProvider;
import org.keycloak.models.UserProvider;

import java.time.Instant;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

class CaepActionDispatcherTest {

    @Test
    void revokesSessionBySid() {
        KeycloakSession keycloakSession = mock(KeycloakSession.class);
        RealmModel realm = mock(RealmModel.class);
        UserSessionProvider sessionProvider = mock(UserSessionProvider.class);
        when(keycloakSession.sessions()).thenReturn(sessionProvider);

        UserSessionModel userSession = mock(UserSessionModel.class);
        when(sessionProvider.getUserSession(realm, "sid-1")).thenReturn(userSession);

        CaepParsedSet set = new CaepParsedSet("j1", "iss", Set.of("aud"), Instant.now(), Instant.now().plusSeconds(60), "user-1", "sid-1", new JsonObject());
        CaepConfig config = new CaepConfig(true, "iss", "aud", "jwks", 60, true, 600, true, true, true, true, false);

        CaepDispatchResult result = new CaepActionDispatcher(keycloakSession).dispatch(CaepEventRegistry.SESSION_REVOKED, set, config, realm);

        verify(sessionProvider).removeUserSession(realm, userSession);
        assertEquals("processed", result.processingResult());
    }

    @Test
    void revokesAllUserSessionsBySubWhenSidMissing() {
        KeycloakSession keycloakSession = mock(KeycloakSession.class);
        RealmModel realm = mock(RealmModel.class);
        UserSessionProvider sessionProvider = mock(UserSessionProvider.class);
        UserProvider userProvider = mock(UserProvider.class);
        when(keycloakSession.sessions()).thenReturn(sessionProvider);
        when(keycloakSession.users()).thenReturn(userProvider);

        UserModel user = mock(UserModel.class);
        when(userProvider.getUserById(realm, "user-1")).thenReturn(user);

        UserSessionModel s1 = mock(UserSessionModel.class);
        UserSessionModel s2 = mock(UserSessionModel.class);
        when(sessionProvider.getUserSessionsStream(realm, user)).thenReturn(Stream.of(s1, s2));

        CaepParsedSet set = new CaepParsedSet("j2", "iss", Set.of("aud"), Instant.now(), Instant.now().plusSeconds(60), "user-1", null, new JsonObject());
        CaepConfig config = new CaepConfig(true, "iss", "aud", "jwks", 60, true, 600, true, true, true, true, false);

        CaepDispatchResult result = new CaepActionDispatcher(keycloakSession).dispatch(CaepEventRegistry.SESSION_REVOKED, set, config, realm);

        verify(sessionProvider).removeUserSession(realm, s1);
        verify(sessionProvider).removeUserSession(realm, s2);
        assertEquals("processed", result.processingResult());
    }

    @Test
    void stepUpUnsupportedWithoutReauthFallback() {
        KeycloakSession keycloakSession = mock(KeycloakSession.class);
        RealmModel realm = mock(RealmModel.class);
        CaepParsedSet set = new CaepParsedSet("j3", "iss", Set.of("aud"), Instant.now(), Instant.now().plusSeconds(60), "user-1", "sid-1", new JsonObject());
        CaepConfig config = new CaepConfig(true, "iss", "aud", "jwks", 60, true, 600, true, true, true, true, false);

        CaepDispatchResult result = new CaepActionDispatcher(keycloakSession).dispatch(CaepEventRegistry.ASSURANCE_LEVEL_CHANGE, set, config, realm);

        assertEquals("enforcement_failed", result.processingResult());
        assertEquals("step_up", result.action());
    }

    // ── analyst responses (RISC): opt-in, they change the account ─────────────────

    private static CaepConfig accountActions(boolean disabled, boolean compromise) {
        return new CaepConfig(true, "iss", "aud", "jwks", 60, true, 600, true, true, true, true, false, disabled, compromise);
    }

    @Test
    void accountDisabledLocksTheUserAndEndsItsSessions() {
        KeycloakSession keycloakSession = mock(KeycloakSession.class);
        RealmModel realm = mock(RealmModel.class);
        UserProvider users = mock(UserProvider.class);
        UserSessionProvider sessions = mock(UserSessionProvider.class);
        when(keycloakSession.users()).thenReturn(users);
        when(keycloakSession.sessions()).thenReturn(sessions);
        UserModel user = mock(UserModel.class);
        when(users.getUserById(realm, "user-1")).thenReturn(user);
        UserSessionModel s1 = mock(UserSessionModel.class);
        when(sessions.getUserSessionsStream(realm, user)).thenReturn(Stream.of(s1));

        CaepParsedSet set = new CaepParsedSet("j4", "iss", Set.of("aud"), Instant.now(), Instant.now().plusSeconds(60), "user:keycloak:demo:user-1", null, new JsonObject());
        CaepDispatchResult result = new CaepActionDispatcher(keycloakSession).dispatch(CaepEventRegistry.ACCOUNT_DISABLED, set, accountActions(true, false), realm);

        verify(user).setEnabled(false);
        verify(sessions).removeUserSession(realm, s1);
        assertEquals("processed", result.processingResult());
        assertEquals("account_disabled", result.action());
    }

    @Test
    void credentialCompromiseRequiresANewPasswordAndEndsTheSessions() {
        KeycloakSession keycloakSession = mock(KeycloakSession.class);
        RealmModel realm = mock(RealmModel.class);
        UserProvider users = mock(UserProvider.class);
        UserSessionProvider sessions = mock(UserSessionProvider.class);
        when(keycloakSession.users()).thenReturn(users);
        when(keycloakSession.sessions()).thenReturn(sessions);
        UserModel user = mock(UserModel.class);
        when(users.getUserById(realm, "user-1")).thenReturn(user);
        UserSessionModel s1 = mock(UserSessionModel.class);
        when(sessions.getUserSessionsStream(realm, user)).thenReturn(Stream.of(s1));

        CaepParsedSet set = new CaepParsedSet("j5", "iss", Set.of("aud"), Instant.now(), Instant.now().plusSeconds(60), "user-1", null, new JsonObject());
        CaepDispatchResult result = new CaepActionDispatcher(keycloakSession).dispatch(CaepEventRegistry.CREDENTIAL_COMPROMISE, set, accountActions(false, true), realm);

        verify(user).addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
        verify(sessions).removeUserSession(realm, s1);
        assertEquals("processed", result.processingResult());
        assertEquals("password_reset_required", result.action());
    }

    @Test
    void accountActionsAreOffUnlessTheRealmEnablesThem() {
        KeycloakSession keycloakSession = mock(KeycloakSession.class);
        RealmModel realm = mock(RealmModel.class);
        CaepParsedSet set = new CaepParsedSet("j6", "iss", Set.of("aud"), Instant.now(), Instant.now().plusSeconds(60), "user-1", null, new JsonObject());
        CaepActionDispatcher dispatcher = new CaepActionDispatcher(keycloakSession);

        CaepDispatchResult disabled = dispatcher.dispatch(CaepEventRegistry.ACCOUNT_DISABLED, set, accountActions(false, false), realm);
        CaepDispatchResult compromise = dispatcher.dispatch(CaepEventRegistry.CREDENTIAL_COMPROMISE, set, accountActions(false, false), realm);

        assertEquals("ignored", disabled.processingResult());
        assertEquals("ignored", compromise.processingResult());
        assertEquals(true, disabled.error().contains("hf.caep.enforce.accountDisabled"));
        verifyNoInteractions(keycloakSession); // not even a user lookup
    }

    @Test
    void anUnknownTargetIsIgnoredNotAnError() {
        KeycloakSession keycloakSession = mock(KeycloakSession.class);
        RealmModel realm = mock(RealmModel.class);
        UserProvider users = mock(UserProvider.class);
        when(keycloakSession.users()).thenReturn(users);
        CaepParsedSet set = new CaepParsedSet("j7", "iss", Set.of("aud"), Instant.now(), Instant.now().plusSeconds(60), "ghost", null, new JsonObject());

        CaepDispatchResult result = new CaepActionDispatcher(keycloakSession).dispatch(CaepEventRegistry.ACCOUNT_DISABLED, set, accountActions(true, false), realm);

        assertEquals("ignored", result.processingResult());
        assertEquals("target user not found", result.error());
    }

    @Test
    void theRiscEventUrisResolve() {
        CaepEventRegistry registry = new CaepEventRegistry();
        assertEquals(CaepEventRegistry.ACCOUNT_DISABLED, registry.resolve("https://schemas.openid.net/secevent/risc/event-type/account-disabled"));
        assertEquals(CaepEventRegistry.CREDENTIAL_COMPROMISE, registry.resolve("https://schemas.openid.net/secevent/risc/event-type/credential-compromise"));
    }
    // ── a service account's client (subject service_account:keycloak:<realm id>:<client id>) ──────────────

    private static CaepParsedSet clientSubject(String sub) {
        return new CaepParsedSet("j9", "iss", Set.of("aud"), Instant.now(), Instant.now().plusSeconds(60), sub, null, new JsonObject());
    }

    /** People's lock switch off: a client follows its own opt-in, not the realm's. */
    private static final CaepConfig LOCK_OFF = new CaepConfig(true, "iss", "aud", "jwks", 60, true, 600, false, false, false, false, false);

    private static ClientModel client(RealmModel realm, String allowDisable, boolean enabled) {
        ClientModel c = mock(ClientModel.class);
        when(realm.getClientByClientId("billing-job")).thenReturn(c);
        when(c.getAttribute("humifortis.allow_disable")).thenReturn(allowDisable);
        when(c.isEnabled()).thenReturn(enabled);
        return c;
    }

    @Test
    void anAnalystDisablesAClientThatAllowsIt() {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getId()).thenReturn("demo");
        ClientModel c = client(realm, "true", true);
        CaepDispatchResult result = new CaepActionDispatcher(mock(KeycloakSession.class))
                .dispatch(CaepEventRegistry.ACCOUNT_DISABLED, clientSubject("service_account:keycloak:demo:billing-job"), LOCK_OFF, realm);
        assertEquals("processed", result.processingResult());
        assertEquals("client_disabled", result.action());
        verify(c).setEnabled(false);
        verify(c).setAttribute(eq("humifortis.disabled_by"), eq("analyst"));
    }

    @Test
    void aClientThatDoesNotAllowItIsLeftAloneAndTheAnalystIsToldWhy() {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getId()).thenReturn("demo");
        ClientModel c = client(realm, null, true);
        CaepDispatchResult result = new CaepActionDispatcher(mock(KeycloakSession.class))
                .dispatch(CaepEventRegistry.ACCOUNT_DISABLED, clientSubject("service_account:keycloak:demo:billing-job"), LOCK_OFF, realm);
        assertEquals("ignored", result.processingResult());
        verify(c, never()).setEnabled(anyBoolean());

        RealmModel other = mock(RealmModel.class);
        when(other.getId()).thenReturn("prod");
        when(other.getName()).thenReturn("prod");
        assertEquals("ignored", new CaepActionDispatcher(mock(KeycloakSession.class))
                .dispatch(CaepEventRegistry.ACCOUNT_DISABLED, clientSubject("service_account:keycloak:demo:billing-job"), LOCK_OFF, other).processingResult(),
                "a subject of another realm");
    }
}

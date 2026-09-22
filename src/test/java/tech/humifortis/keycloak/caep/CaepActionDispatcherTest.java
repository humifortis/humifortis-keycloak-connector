package tech.humifortis.keycloak.caep;

import com.google.gson.JsonObject;
import org.junit.jupiter.api.Test;
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
}

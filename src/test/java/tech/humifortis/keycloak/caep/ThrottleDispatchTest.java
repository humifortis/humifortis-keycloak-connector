package tech.humifortis.keycloak.caep;

import com.google.gson.JsonObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserLoginFailureModel;
import org.keycloak.models.UserLoginFailureProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;

import java.time.Instant;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** The throttle is carried out with Keycloak's native temporary lockout, and only ever moves forward. */
class ThrottleDispatchTest {

    private static final String URI = "https://schemas.humifortis.dev/secevent/event-type/throttle";
    private static final CaepConfig CONFIG = new CaepConfig(true, "iss", "aud", "jwks", 60, true, 600, true, true, true, true, false);

    private KeycloakSession session;
    private RealmModel realm;
    private UserLoginFailureProvider failures;
    private UserLoginFailureModel failure;

    @BeforeEach
    void setUp() {
        session = mock(KeycloakSession.class);
        realm = mock(RealmModel.class);
        UserProvider users = mock(UserProvider.class);
        failures = mock(UserLoginFailureProvider.class);
        failure = mock(UserLoginFailureModel.class);
        UserModel user = mock(UserModel.class);
        when(session.users()).thenReturn(users);
        when(session.loginFailures()).thenReturn(failures);
        when(users.getUserById(realm, "u1")).thenReturn(user);
        when(user.getId()).thenReturn("u1");
        when(realm.isBruteForceProtected()).thenReturn(true);
    }

    private static CaepParsedSet throttle(String subject, long until, boolean lifted) {
        JsonObject body = new JsonObject();
        body.addProperty("until", until);
        body.addProperty("lifted", lifted);
        JsonObject events = new JsonObject();
        events.add(URI, body);
        return new CaepParsedSet("j", "iss", Set.of("aud"), Instant.now(), Instant.now().plusSeconds(60), subject, null, events);
    }

    private CaepDispatchResult dispatch(CaepParsedSet set) {
        return new CaepActionDispatcher(session).dispatch(CaepEventRegistry.THROTTLE, set, CONFIG, realm);
    }

    private static long in(long seconds) {
        return Instant.now().getEpochSecond() + seconds;
    }

    @Test
    void theEventTypeIsResolvedAndAlwaysReceived() {
        CaepEventRegistry registry = new CaepEventRegistry();
        assertEquals(CaepEventRegistry.THROTTLE, registry.resolve(URI));
        assertTrue(registry.isEnabled(CaepEventRegistry.THROTTLE, CONFIG));
    }

    @Test
    void setsTheNativeLockoutDeadlineOfTheUser() {
        when(failures.getUserLoginFailure(realm, "u1")).thenReturn(null);
        when(failures.addUserLoginFailure(realm, "u1")).thenReturn(failure);
        long until = in(300);

        CaepDispatchResult r = dispatch(throttle("user:keycloak:demo:u1", until, false));

        verify(failure).setFailedLoginNotBefore((int) until);
        assertEquals("processed", r.processingResult());
        assertEquals("throttle", r.action());
    }

    @Test
    void neverShortensAnActiveLockout() {
        when(failures.getUserLoginFailure(realm, "u1")).thenReturn(failure);
        when(failure.getFailedLoginNotBefore()).thenReturn((int) in(1800));

        CaepDispatchResult r = dispatch(throttle("user:keycloak:demo:u1", in(300), false));

        verify(failure, never()).setFailedLoginNotBefore(anyInt());
        assertEquals("processed", r.processingResult());
    }

    @Test
    void extendsAShorterLockout() {
        when(failures.getUserLoginFailure(realm, "u1")).thenReturn(failure);
        when(failure.getFailedLoginNotBefore()).thenReturn((int) in(60));
        long later = in(1800);

        dispatch(throttle("user:keycloak:demo:u1", later, false));

        verify(failure).setFailedLoginNotBefore((int) later);
    }

    @Test
    void reportsHonestlyWhenTheRealmDoesNotDetectBruteForce() {
        when(realm.isBruteForceProtected()).thenReturn(false);
        when(failures.getUserLoginFailure(realm, "u1")).thenReturn(null);

        CaepDispatchResult r = dispatch(throttle("user:keycloak:demo:u1", in(300), false));

        assertEquals("ignored", r.processingResult());
        assertEquals("realm_bruteforce_disabled", r.error());
        verify(failures, never()).addUserLoginFailure(realm, "u1");
    }

    @Test
    void aLiftClearsTheDeadlineEvenWithoutTheRealmFlag() {
        when(realm.isBruteForceProtected()).thenReturn(false);
        when(failures.getUserLoginFailure(realm, "u1")).thenReturn(failure);
        when(failure.getFailedLoginNotBefore()).thenReturn((int) in(900));

        CaepDispatchResult r = dispatch(throttle("user:keycloak:demo:u1", in(0), true));

        verify(failures).removeUserLoginFailure(realm, "u1");
        assertEquals("throttle_lifted", r.action());
    }

    @Test
    void anExpiredDeadlineRestrictsNothing() {
        when(failures.getUserLoginFailure(realm, "u1")).thenReturn(null);

        CaepDispatchResult r = dispatch(throttle("user:keycloak:demo:u1", in(-10), false));

        assertEquals("ignored", r.processingResult());
        verify(failures, never()).addUserLoginFailure(realm, "u1");
    }

    @Test
    void aServiceAccountIsNotThrottledThroughTheUserLoginForm() {
        CaepDispatchResult r = dispatch(throttle("service_account:keycloak:demo:billing-job", in(300), false));

        assertEquals("ignored", r.processingResult());
        assertEquals("throttle_unsupported_for_entity_type", r.error());
    }

    @Test
    void aMalformedEventIsIgnored() {
        CaepParsedSet set = new CaepParsedSet("j", "iss", Set.of("aud"), Instant.now(), Instant.now().plusSeconds(60),
                "user:keycloak:demo:u1", null, new JsonObject());
        assertEquals("ignored", dispatch(set).processingResult());
    }

    @Test
    void aLockoutRefusalIsNotAFailedLogin() {
        assertTrue(ThrottleLockout.isLockoutRefusal(EventType.LOGIN_ERROR, "user_temporarily_disabled"));
        assertFalse(ThrottleLockout.isLockoutRefusal(EventType.LOGIN_ERROR, "invalid_user_credentials"));
        assertFalse(ThrottleLockout.isLockoutRefusal(EventType.CLIENT_LOGIN_ERROR, "user_temporarily_disabled"));
        assertFalse(ThrottleLockout.isLockoutRefusal(EventType.LOGIN, null));
    }
}

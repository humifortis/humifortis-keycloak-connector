package tech.humifortis.keycloak.listener;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.keycloak.events.Errors;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;

/** Only a failed sign-in with no user, for a known username, can be a directory outage; anything else is left alone. */
class DirectoryOutageTest {

    private static Event event(EventType type, String userId, String error, String username) {
        Event e = new Event();
        e.setType(type);
        e.setUserId(userId);
        e.setError(error);
        e.setRealmId("demo");
        Map<String, String> details = new HashMap<>();
        if (username != null) details.put("username", username);
        e.setDetails(details);
        return e;
    }

    @Test
    void aWrongPasswordForAKnownPerson_isNotTouched() {
        KeycloakSession session = mock(KeycloakSession.class);
        assertFalse(DirectoryOutage.mark(session, event(EventType.LOGIN_ERROR, "u1", Errors.INVALID_USER_CREDENTIALS, "alice")));
        verifyNoInteractions(session);
    }

    @Test
    void otherEventsAndErrors_areNotTouched() {
        KeycloakSession session = mock(KeycloakSession.class);
        assertFalse(DirectoryOutage.mark(session, event(EventType.LOGIN, null, null, "alice")));
        assertFalse(DirectoryOutage.mark(session, event(EventType.LOGIN_ERROR, null, Errors.EXPIRED_CODE, "alice")));
        assertFalse(DirectoryOutage.mark(session, event(EventType.LOGIN_ERROR, null, Errors.INVALID_USER_CREDENTIALS, null)));
        verifyNoInteractions(session);
    }

    @Test
    void aFaultWhileLookingUp_neverThrows_andLeavesTheEventAFailedSignIn() {
        KeycloakSession session = mock(KeycloakSession.class); // realms() returns null: the lookup fails
        Event e = event(EventType.LOGIN_ERROR, null, Errors.INVALID_USER_CREDENTIALS, "alice");
        assertFalse(DirectoryOutage.mark(session, e));
        assertFalse(DirectoryOutage.isMarked(e));
    }

    @Test
    void aMarkedEvent_isRecognised() {
        Event e = event(EventType.LOGIN_ERROR, null, Errors.INVALID_USER_CREDENTIALS, "alice");
        e.getDetails().put(DirectoryOutage.DETAIL_REASON, DirectoryOutage.REASON);
        assertTrue(DirectoryOutage.isMarked(e));
    }
}

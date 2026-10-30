package tech.humifortis.keycloak.user;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.keycloak.models.UserSessionModel;
import org.keycloak.sessions.AuthenticationSessionModel;

/** The session's last proof (docs/session-assurance-sas.spec.md, S2): recorded at the step, read at every later decision. */
class SessionProofTest {

    /** An authentication session whose user-session notes land in a map, as Keycloak carries them onto the user session. */
    private static AuthenticationSessionModel authSession(Map<String, String> notes) {
        AuthenticationSessionModel as = mock(AuthenticationSessionModel.class);
        doAnswer(i -> notes.put(i.getArgument(0), i.getArgument(1))).when(as).setUserSessionNote(anyString(), anyString());
        return as;
    }

    private static UserSessionModel userSession(Map<String, String> notes, int lastRefresh) {
        UserSessionModel us = mock(UserSessionModel.class);
        when(us.getNote(anyString())).thenAnswer(i -> notes.get(i.<String>getArgument(0)));
        when(us.getLastSessionRefresh()).thenReturn(lastRefresh);
        return us;
    }

    @Test
    void aStepUpIsReadBackWithItsKindAndTheIdleTime() {
        Map<String, String> notes = new HashMap<>();
        SessionProof.record(authSession(notes), 3, "Device_Bound", 1_000);
        Map<String, String> meta = SessionProof.metadata(userSession(notes, 1_300), 1_360);
        assertEquals("3", meta.get(SessionProof.META_LEVEL));
        assertEquals("1000", meta.get(SessionProof.META_TIME));
        assertEquals("device_bound", meta.get(SessionProof.META_KIND));
        assertEquals("60", meta.get(SessionProof.META_IDLE), "since the session's last use");
    }

    @Test
    void theLastProofWinsAndAPasswordClearsTheKind() {
        Map<String, String> notes = new HashMap<>();
        SessionProof.record(authSession(notes), 3, "security_key", 1_000);
        SessionProof.record(authSession(notes), 1, null, 2_000);
        Map<String, String> meta = SessionProof.metadata(userSession(notes, 2_000), 2_000);
        assertEquals("1", meta.get(SessionProof.META_LEVEL));
        assertEquals("2000", meta.get(SessionProof.META_TIME));
        assertTrue(!meta.containsKey(SessionProof.META_KIND), "a password has no credential kind");
    }

    @Test
    void nothingRecordedIsNothingSent() {
        assertTrue(SessionProof.metadata(userSession(new HashMap<>(), 100), 200).isEmpty());
        assertTrue(SessionProof.metadata(null, 200).isEmpty());
        Map<String, String> notes = new HashMap<>(Map.of(SessionProof.NOTE_LEVEL, "x", SessionProof.NOTE_TIME, "100"));
        assertTrue(SessionProof.metadata(userSession(notes, 100), 200).isEmpty(), "a corrupt note is no proof");
    }

    @Test
    void aLevelAboveTheLadderIsTheTopAndNoLevelIsNotRecorded() {
        Map<String, String> notes = new HashMap<>();
        SessionProof.record(authSession(notes), 7, null, 10);
        assertEquals("3", notes.get(SessionProof.NOTE_LEVEL));
        AuthenticationSessionModel as = mock(AuthenticationSessionModel.class);
        SessionProof.record(as, 0, null, 10);
        verify(as, never()).setUserSessionNote(anyString(), anyString());
    }
}

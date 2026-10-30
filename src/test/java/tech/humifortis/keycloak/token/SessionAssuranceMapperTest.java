package tech.humifortis.keycloak.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.keycloak.models.UserSessionModel;

import com.google.gson.Gson;

import tech.humifortis.keycloak.auth.HumifortisRiskEvaluator;

/** The session_assurance claim (docs/session-assurance-sas.spec.md 5.2): written at a decision, read into the tokens. */
class SessionAssuranceMapperTest {

    private static UserSessionModel session(Map<String, String> notes) {
        UserSessionModel us = mock(UserSessionModel.class);
        when(us.getNote(anyString())).thenAnswer(i -> notes.get(i.<String>getArgument(0)));
        doAnswer(i -> notes.put(i.getArgument(0), i.getArgument(1))).when(us).setNote(anyString(), anyString());
        return us;
    }

    private static HumifortisRiskEvaluator.EvaluateResponse decision(String json) {
        return new Gson().fromJson(json, HumifortisRiskEvaluator.EvaluateResponse.class);
    }

    @Test
    void theDecisionsLevelAndVisibilityBecomeTheClaim() {
        Map<String, String> notes = new HashMap<>();
        UserSessionModel us = session(notes);
        SessionAssuranceMapper.record(us, decision("{\"action\":\"ALLOW\",\"session_assurance\":{\"level\":2,\"limited_by\":\"freshness\"},\"visibility\":{\"level\":\"partial\"}}"));
        Map<String, Object> claim = SessionAssuranceMapper.claimOf(us);
        assertEquals(2, claim.get("level"));
        assertEquals("partial", claim.get("visibility"));
    }

    @Test
    void noAxesIsNoClaimNeverLevelZero() {
        assertTrue(SessionAssuranceMapper.notesOf(decision("{\"action\":\"ALLOW\"}")).isEmpty());
        assertNull(SessionAssuranceMapper.claimOf(session(new HashMap<>())));
        assertNull(SessionAssuranceMapper.claimOf(session(new HashMap<>(Map.of(SessionAssuranceMapper.NOTE_LEVEL, "9")))), "outside the scale");
        assertNull(SessionAssuranceMapper.claimOf(null));
    }

    @Test
    void aLaterDecisionReplacesTheLevel() {
        Map<String, String> notes = new HashMap<>();
        UserSessionModel us = session(notes);
        SessionAssuranceMapper.record(us, decision("{\"session_assurance\":{\"level\":1},\"visibility\":{\"level\":\"full\"}}"));
        SessionAssuranceMapper.record(us, decision("{\"session_assurance\":{\"level\":3},\"visibility\":{\"level\":\"full\"}}"));
        assertEquals(3, SessionAssuranceMapper.claimOf(us).get("level"));
    }
}

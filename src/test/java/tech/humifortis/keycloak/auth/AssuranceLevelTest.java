package tech.humifortis.keycloak.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;

import org.junit.jupiter.api.Test;

class AssuranceLevelTest {

    private static final Map<String, Integer> MAP = Map.of("urn:humifortis:acr:code", 1, "urn:humifortis:acr:app", 2, "urn:humifortis:acr:key", 3);

    @Test
    void theFirstValueTheRealmMapsIsTheLevelAsked() {
        assertEquals(2, AssuranceLevel.requested("urn:humifortis:acr:app", MAP));
        assertEquals(3, AssuranceLevel.requested("urn:humifortis:acr:key urn:humifortis:acr:app", MAP), "in order of preference");
        assertEquals(2, AssuranceLevel.requested("unknown-value urn:humifortis:acr:app", MAP), "an unknown value is skipped");
    }

    @Test
    void aBareNumberIsALevelToo() {
        assertEquals(2, AssuranceLevel.requested("2", null));
        assertEquals(3, AssuranceLevel.requested("9", MAP), "above the ladder is the top of the ladder, never ignored");
    }

    @Test
    void nothingAskedIsZero() {
        assertEquals(0, AssuranceLevel.requested(null, MAP));
        assertEquals(0, AssuranceLevel.requested("   ", MAP));
        assertEquals(0, AssuranceLevel.requested("something-else", MAP));
        assertEquals(0, AssuranceLevel.requested("0", MAP), "a password alone is no level of this ladder");
    }

    @Test
    void theAchievedLevelIsReadFromTheDecisionNote() {
        assertEquals(2, AssuranceLevel.achieved("2"));
        assertEquals(3, AssuranceLevel.achieved("8"));
        assertEquals(0, AssuranceLevel.achieved(null));
        assertEquals(0, AssuranceLevel.achieved("x"));
        assertEquals(0, AssuranceLevel.achieved("-3"));
    }
}

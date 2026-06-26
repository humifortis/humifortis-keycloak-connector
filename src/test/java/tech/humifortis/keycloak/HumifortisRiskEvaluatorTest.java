package tech.humifortis.keycloak;

import org.junit.jupiter.api.Test;
import tech.humifortis.keycloak.auth.HumifortisRiskEvaluator;
import tech.humifortis.keycloak.model.Risk;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for HumifortisRiskEvaluator — risk level mapping, env helper, circuit-breaker logic.
 *
 * Full HTTP integration is NOT tested here (requires live humifortis-core server).
 * We test the pure-logic methods that are package/public accessible.
 */
class HumifortisRiskEvaluatorTest {

    // ── Risk level mapping ────────────────────────────────────────────────────

    @Test
    void mapRiskLevel_MINIMAL_returns_NONE_score() {
        Risk r = HumifortisRiskEvaluator.mapRiskLevel("MINIMAL", "test");
        assertEquals(Risk.Score.NONE, r.getScore());
    }

    @Test
    void mapRiskLevel_LOW_returns_VERY_SMALL_score() {
        Risk r = HumifortisRiskEvaluator.mapRiskLevel("LOW", "test");
        assertEquals(Risk.Score.VERY_SMALL, r.getScore());
    }

    @Test
    void mapRiskLevel_MEDIUM_returns_MEDIUM_score() {
        Risk r = HumifortisRiskEvaluator.mapRiskLevel("MEDIUM", "test");
        assertEquals(Risk.Score.MEDIUM, r.getScore());
    }

    @Test
    void mapRiskLevel_HIGH_returns_HIGH_score() {
        Risk r = HumifortisRiskEvaluator.mapRiskLevel("HIGH", "test");
        assertEquals(Risk.Score.HIGH, r.getScore());
    }

    @Test
    void mapRiskLevel_CRITICAL_returns_EXTREME_score() {
        Risk r = HumifortisRiskEvaluator.mapRiskLevel("CRITICAL", "test");
        assertEquals(Risk.Score.EXTREME, r.getScore());
    }

    @Test
    void mapRiskLevel_unknown_returns_NONE_score() {
        Risk r = HumifortisRiskEvaluator.mapRiskLevel("FOOBAR", "test");
        assertEquals(Risk.Score.NONE, r.getScore());
    }

    @Test
    void mapRiskLevel_caseInsensitive() {
        Risk r = HumifortisRiskEvaluator.mapRiskLevel("critical", "test");
        assertEquals(Risk.Score.EXTREME, r.getScore());
    }

    @Test
    void mapRiskLevel_preservesReason() {
        Risk r = HumifortisRiskEvaluator.mapRiskLevel("HIGH", "rule:vpn_exit");
        assertTrue(r.getReason().isPresent());
        assertEquals("rule:vpn_exit", r.getReason().get());
    }

    // ── envOrDefault ─────────────────────────────────────────────────────────

    @Test
    void envOrDefault_missingKey_returnsDefault() {
        String val = HumifortisRiskEvaluator.envOrDefault(
                "HF_TEST_KEY_THAT_DOES_NOT_EXIST_12345", "DEFAULT_VAL");
        assertEquals("DEFAULT_VAL", val);
    }

    @Test
    void envOrDefault_nullDefault_returnsNull() {
        assertNull(HumifortisRiskEvaluator.envOrDefault(
                "HF_TEST_KEY_THAT_DOES_NOT_EXIST_12345", null));
    }
}

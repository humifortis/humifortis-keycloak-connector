package tech.humifortis.keycloak;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for HumifortisError enum — error catalogue, user messages and log messages.
 */
class HumifortisErrorTest {

    @Test
    void allErrorsHaveCodeStartingWithHF() {
        for (HumifortisError e : HumifortisError.values()) {
            assertTrue(e.code.startsWith("HF-"),
                    "Code must start with HF-: " + e.name() + " -> " + e.code);
        }
    }

    @Test
    void allErrorsHaveNonBlankSummary() {
        for (HumifortisError e : HumifortisError.values()) {
            assertNotNull(e.summary,     e.name() + ".summary is null");
            assertFalse(e.summary.isBlank(), e.name() + ".summary is blank");
        }
    }

    @Test
    void userMessageContainsCode() {
        HumifortisError err = HumifortisError.ACCESS_DENIED_RISK;
        assertTrue(err.userMessage().contains("HF-2001"),
                "userMessage must contain the error code");
    }

    @Test
    void userMessageDoesNotContainTechnicalDetail() {
        // userMessage() is for end-users — no implementation details
        String msg = HumifortisError.SERVICE_TIMEOUT.userMessage();
        assertFalse(msg.toLowerCase().contains("exception"),
                "userMessage must not expose technical details");
    }

    @Test
    void logMessageContainsCodeAndDetail() {
        String log = HumifortisError.SERVICE_TIMEOUT.logMessage("connection refused");
        assertTrue(log.contains("HF-1001"), "logMessage must contain code");
        assertTrue(log.contains("connection refused"), "logMessage must contain detail");
    }

    @Test
    void codesAreUnique() {
        long distinct = java.util.Arrays.stream(HumifortisError.values())
                .map(e -> e.code)
                .distinct()
                .count();
        assertEquals(HumifortisError.values().length, distinct, "All error codes must be unique");
    }

    @Test
    void errorSeriesMapping() {
        // 1xxx = service
        assertTrue(HumifortisError.SERVICE_TIMEOUT.code.startsWith("HF-1"));
        // 2xxx = policy
        assertTrue(HumifortisError.ACCESS_DENIED_RISK.code.startsWith("HF-2"));
        // 3xxx = config
        assertTrue(HumifortisError.MISCONFIGURED_URL.code.startsWith("HF-3"));
        // 4xxx = user
        assertTrue(HumifortisError.MFA_INVALID_CODE.code.startsWith("HF-4"));
        // 5xxx = internal
        assertTrue(HumifortisError.INTERNAL_ERROR.code.startsWith("HF-5"));
    }
}

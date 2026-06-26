package tech.humifortis.keycloak;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for HumifortisAuditLog — pseudonymisation and sanitisation.
 */
class HumifortisAuditLogTest {

    @Test
    void pseudoUser_nullInput_returnsUnknown() {
        assertEquals("hf:u:unknown", HumifortisAuditLog.pseudoUser(null));
    }

    @Test
    void pseudoUser_blankInput_returnsUnknown() {
        assertEquals("hf:u:unknown", HumifortisAuditLog.pseudoUser("   "));
    }

    @Test
    void pseudoUser_hasPrefixHfu() {
        String result = HumifortisAuditLog.pseudoUser("user-id-123");
        assertTrue(result.startsWith("hf:u:"),
                "pseudoUser must start with hf:u:");
    }

    @Test
    void pseudoUser_isTruncatedTo13Chars() {
        // "hf:u:" (5) + 8 chars = 13
        String result = HumifortisAuditLog.pseudoUser("user-id-123");
        assertEquals(13, result.length(), "pseudoUser length must be 13");
    }

    @Test
    void pseudoUser_isDeterministic() {
        String a = HumifortisAuditLog.pseudoUser("user-42");
        String b = HumifortisAuditLog.pseudoUser("user-42");
        assertEquals(a, b, "Same input must produce same pseudo-ID");
    }

    @Test
    void pseudoUser_differentInputsDifferentOutput() {
        assertNotEquals(
                HumifortisAuditLog.pseudoUser("alice"),
                HumifortisAuditLog.pseudoUser("bob"),
                "Different users must produce different pseudo-IDs");
    }

    @Test
    void sanitize_removesNewlines() {
        assertEquals("line1_line2", HumifortisAuditLog.sanitize("line1\nline2"));
    }

    @Test
    void sanitize_removesCarriageReturn() {
        assertEquals("a_b", HumifortisAuditLog.sanitize("a\rb"));
    }

    @Test
    void sanitize_removesDoubleQuotes() {
        assertEquals("say_hello_", HumifortisAuditLog.sanitize("say\"hello\""));
    }

    @Test
    void sanitize_removesLtGt() {
        assertEquals("_script_", HumifortisAuditLog.sanitize("<script>"));
    }

    @Test
    void sanitize_nullInput_returnsEmpty() {
        assertEquals("", HumifortisAuditLog.sanitize(null));
    }

    @Test
    void sanitize_cleanInput_unchanged() {
        assertEquals("mfa_success", HumifortisAuditLog.sanitize("mfa_success"));
    }

    @Test
    void log_doesNotThrow() {
        // Just verifies no exception is thrown
        assertDoesNotThrow(() ->
            HumifortisAuditLog.log("test_event", "uid-123", "EMAIL_OTP",
                    "verified", "HF-0000", "CORR1234", "detail"));
    }

    @Test
    void log_withNullFields_doesNotThrow() {
        assertDoesNotThrow(() ->
            HumifortisAuditLog.log(null, null, null, null, null, null, null));
    }
}

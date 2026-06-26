package tech.humifortis.keycloak.auth;

import org.junit.jupiter.api.*;
import tech.humifortis.keycloak.HumifortisCache;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for HumifortisRateLimiter — cooldown, blocking, anti-replay, IP hashing.
 * Lives in the auth package to access package-private constructor and key builders.
 */
class HumifortisRateLimiterTest {

    private HumifortisCache       cache;
    private HumifortisRateLimiter rl;

    @BeforeEach
    void setUp() {
        cache = HumifortisCache.getInstance();
        cache.clear();
        rl = new HumifortisRateLimiter(cache);   // package-private ctor
    }

    // ── canSendOtp / recordSend ───────────────────────────────────────────────

    @Test
    void canSendOtp_firstTime_returnsTrue() {
        assertTrue(rl.canSendOtp("u1"), "First OTP send should be allowed");
    }

    @Test
    void canSendOtp_afterRecordSend_returnsFalse() {
        rl.recordSend("u2");
        assertFalse(rl.canSendOtp("u2"), "Second send within cooldown must be blocked");
    }

    @Test
    void canSendOtp_afterCooldownExpired_returnsTrue() throws Exception {
        // Inject expired timestamp
        cache.put(rl.keySend("u3"),
                System.currentTimeMillis() - HumifortisRateLimiter.OTP_SEND_COOLDOWN_MS - 1,
                1L);
        Thread.sleep(5);
        assertTrue(rl.canSendOtp("u3"), "After cooldown expiry send must be allowed");
    }

    // ── isUserBlocked / recordFailure / clearFailures ────────────────────────

    @Test
    void isUserBlocked_byDefault_returnsFalse() {
        assertFalse(rl.isUserBlocked("u-new"));
    }

    @Test
    void recordFailure_belowThreshold_notBlocked() {
        for (int i = 0; i < HumifortisRateLimiter.MAX_FAILS_PER_USER - 1; i++)
            rl.recordFailure("u-threshold", "1.2.3.4");
        assertFalse(rl.isUserBlocked("u-threshold"), "Below threshold must not block");
    }

    @Test
    void recordFailure_atThreshold_triggersBlock() {
        for (int i = 0; i < HumifortisRateLimiter.MAX_FAILS_PER_USER; i++)
            rl.recordFailure("u-block", "1.2.3.4");
        assertTrue(rl.isUserBlocked("u-block"), "At threshold must trigger soft block");
    }

    @Test
    void clearFailures_removesBlock() {
        for (int i = 0; i < HumifortisRateLimiter.MAX_FAILS_PER_USER; i++)
            rl.recordFailure("u-clear", "1.2.3.4");
        assertTrue(rl.isUserBlocked("u-clear"));
        rl.clearFailures("u-clear");
        assertFalse(rl.isUserBlocked("u-clear"), "After clearFailures block must be removed");
    }

    // ── isIpBlocked ───────────────────────────────────────────────────────────

    @Test
    void isIpBlocked_byDefault_returnsFalse() {
        assertFalse(rl.isIpBlocked("10.0.0.1"));
    }

    @Test
    void isIpBlocked_afterMaxFailsFromSameIp() {
        String ip = "10.0.0.200";
        for (int i = 0; i < HumifortisRateLimiter.MAX_FAILS_PER_IP; i++)
            rl.recordFailure("user-" + i, ip);
        assertTrue(rl.isIpBlocked(ip), "IP must be blocked after MAX_FAILS_PER_IP failures");
    }

    // ── Anti-replay ───────────────────────────────────────────────────────────

    @Test
    void isOtpAlreadyUsed_beforeMark_returnsFalse() {
        assertFalse(rl.isOtpAlreadyUsed("hash-abc123"));
    }

    @Test
    void isOtpAlreadyUsed_afterMark_returnsTrue() {
        rl.markOtpUsed("hash-abc123");
        assertTrue(rl.isOtpAlreadyUsed("hash-abc123"), "OTP must be marked as used");
    }

    @Test
    void isOtpAlreadyUsed_differentHash_returnsFalse() {
        rl.markOtpUsed("hash-aaa");
        assertFalse(rl.isOtpAlreadyUsed("hash-bbb"), "Different hash must not be blocked");
    }

    // ── hashIp ────────────────────────────────────────────────────────────────

    @Test
    void hashIp_notNull() {
        assertNotNull(rl.hashIp("192.168.1.1"));
    }

    @Test
    void hashIp_isDeterministic() {
        assertEquals(rl.hashIp("192.168.1.1"), rl.hashIp("192.168.1.1"));
    }

    @Test
    void hashIp_differentIpsDifferentHashes() {
        assertNotEquals(rl.hashIp("1.2.3.4"), rl.hashIp("5.6.7.8"));
    }

    @Test
    void hashIp_doesNotContainRawIp() {
        String h = rl.hashIp("192.168.1.1");
        assertFalse(h.contains("192.168"), "Hashed IP must not contain the raw address");
    }

    @Test
    void hashIp_lengthIs8() {
        assertEquals(8, rl.hashIp("10.0.0.1").length(), "Hash must be 8 chars");
    }

    // ── safeParseInt / safeParseLong ──────────────────────────────────────────

    @Test void safeParseInt_valid()             { assertEquals(42,    HumifortisRateLimiter.safeParseInt("42", 0)); }
    @Test void safeParseInt_invalid_default()   { assertEquals(7,     HumifortisRateLimiter.safeParseInt("NaN", 7)); }
    @Test void safeParseInt_null_default()      { assertEquals(3,     HumifortisRateLimiter.safeParseInt(null, 3)); }
    @Test void safeParseLong_valid()            { assertEquals(600_000L, HumifortisRateLimiter.safeParseLong("600000", 0L)); }
    @Test void safeParseLong_invalid_default()  { assertEquals(99L,   HumifortisRateLimiter.safeParseLong("bad", 99L)); }
}

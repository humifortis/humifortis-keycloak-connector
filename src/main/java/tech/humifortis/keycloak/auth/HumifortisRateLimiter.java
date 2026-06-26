package tech.humifortis.keycloak.auth;

import org.jboss.logging.Logger;
import tech.humifortis.keycloak.HumifortisCache;

/**
 * Rate-limiter for OTP flows.  JVM in-memory — no external dependency.
 *
 * Cache keys:
 *   hf:otp:send:{userId}       – last send timestamp (cooldown)
 *   hf:otp:fail:user:{userId}  – failure counter (15-min window)
 *   hf:otp:fail:ip:{hashedIp}  – per-IP failure counter
 *   hf:otp:block:{userId}      – soft-block flag
 *   hf:otp:replay:{prefix24}   – anti-replay marker
 *
 * Cluster note: per-node only.  For multi-node active-active clusters
 * externalise to POST /api/v1/ratelimit/check on Humifortis Core.
 */
public class HumifortisRateLimiter {

    private static final Logger logger = Logger.getLogger(HumifortisRateLimiter.class);

    public static final long OTP_SEND_COOLDOWN_MS    = 30_000L;
    public static final int  MAX_FAILS_PER_USER      = 10;
    public static final int  MAX_FAILS_PER_IP        = 20;
    public static final long FAIL_WINDOW_MS          = 900_000L;
    public static final long REPLAY_TTL_MS           = 300_000L;
    public static final long SOFT_BLOCK_AFTER_MAX_MS = 300_000L;
    static final int         REPLAY_PREFIX_LEN       = 24;

    private final HumifortisCache cache;

    public HumifortisRateLimiter() { this.cache = HumifortisCache.getInstance(); }

    /** Package-private for unit-testing with an injected cache. */
    HumifortisRateLimiter(HumifortisCache cache) { this.cache = cache; }

    // ── Key builders ─────────────────────────────────────────────────────────
    String keySend(String uid)       { return "hf:otp:send:"       + uid; }
    String keyFailUser(String uid)   { return "hf:otp:fail:user:"  + uid; }
    String keyFailIp(String ip)      { return "hf:otp:fail:ip:"    + ip;  }
    String keySoftBlock(String uid)  { return "hf:otp:block:"      + uid; }
    String keyReplay(String prefix)  { return "hf:otp:replay:"     + prefix; }

    // ── Public API ───────────────────────────────────────────────────────────

    /** @return true if OTP send is allowed (cooldown not active). */
    public boolean canSendOtp(String userId) {
        try {
            Long last = cache.get(keySend(userId));
            if (last != null) {
                long remaining = OTP_SEND_COOLDOWN_MS - (System.currentTimeMillis() - last);
                if (remaining > 0) {
                    logger.infof("[RateLimiter] OTP send rate-limited uid=%s cooldown=%ds",
                                 userId, remaining / 1000);
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            logger.warnf("[RateLimiter] canSendOtp check failed (fail-open): %s", e.getMessage());
            return true;
        }
    }

    /** Record a successful OTP send — starts the cooldown timer. */
    public void recordSend(String userId) {
        try { cache.put(keySend(userId), System.currentTimeMillis(), OTP_SEND_COOLDOWN_MS); }
        catch (Exception e) { logger.warnf("[RateLimiter] recordSend: %s", e.getMessage()); }
    }

    /** @return true if user is soft-blocked or has exceeded failure threshold. */
    public boolean isUserBlocked(String userId) {
        try {
            if (cache.exists(keySoftBlock(userId))) return true;
            Long c = cache.get(keyFailUser(userId));
            return c != null && c >= MAX_FAILS_PER_USER;
        } catch (Exception e) { return false; }
    }

    /** @return true if IP exceeded failure threshold. */
    public boolean isIpBlocked(String ip) {
        try {
            Long c = cache.get(keyFailIp(hashIp(ip)));
            return c != null && c >= MAX_FAILS_PER_IP;
        } catch (Exception e) { return false; }
    }

    /** Record OTP failure; triggers soft-block when threshold reached. */
    public void recordFailure(String userId, String ip) {
        try {
            long count = cache.increment(keyFailUser(userId), FAIL_WINDOW_MS);
            cache.increment(keyFailIp(hashIp(ip)), FAIL_WINDOW_MS);
            if (count >= MAX_FAILS_PER_USER) {
                cache.mark(keySoftBlock(userId), SOFT_BLOCK_AFTER_MAX_MS);
                logger.warnf("[RateLimiter] User soft-blocked: %s (%d fails/15min)", userId, count);
            }
        } catch (Exception e) { logger.warnf("[RateLimiter] recordFailure: %s", e.getMessage()); }
    }

    /** Clear all counters after successful authentication. */
    public void clearFailures(String userId) {
        try {
            cache.remove(keyFailUser(userId));
            cache.remove(keySoftBlock(userId));
            cache.remove(keySend(userId));
        } catch (Exception e) { logger.warnf("[RateLimiter] clearFailures: %s", e.getMessage()); }
    }

    /** Mark an OTP hash as used (anti-replay). */
    public void markOtpUsed(String otpHash) {
        try { cache.mark(keyReplay(safePrefix(otpHash)), REPLAY_TTL_MS); }
        catch (Exception e) { logger.warnf("[RateLimiter] markOtpUsed: %s", e.getMessage()); }
    }

    /** @return true if this OTP hash was already used (replay detected). */
    public boolean isOtpAlreadyUsed(String otpHash) {
        try { return cache.exists(keyReplay(safePrefix(otpHash))); }
        catch (Exception e) { return false; }
    }

    /** SHA-256 hash of raw IP — no PII in logs. */
    public String hashIp(String ip) {
        try {
            var md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] h = md.digest(ip.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return java.util.Base64.getEncoder().encodeToString(h).substring(0, 8);
        } catch (Exception e) { return "unknown"; }
    }

    private String safePrefix(String hash) {
        if (hash == null) return "null";
        return hash.substring(0, Math.min(REPLAY_PREFIX_LEN, hash.length()));
    }

    public static int safeParseInt(String v, int def) {
        try { return v != null ? Integer.parseInt(v.trim()) : def; }
        catch (NumberFormatException e) { return def; }
    }

    public static long safeParseLong(String v, long def) {
        try { return v != null ? Long.parseLong(v.trim()) : def; }
        catch (NumberFormatException e) { return def; }
    }
}

package tech.humifortis.keycloak.auth;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.*;
import tech.humifortis.keycloak.HumifortisAuditLog;
import tech.humifortis.keycloak.HumifortisError;

import java.security.SecureRandom;
import java.util.*;

/**
 * MFA Step-Up Router v1.3.1
 *
 * Reads HUMIFORTIS_RISK_ACTION from the auth-session note and routes to the
 * appropriate MFA challenge.  Replaces a static auth-otp-form binding.
 *
 * Resolution table
 * ─────────────────────────────────────────────────────────────────
 * REQUIRE_EMAIL_OTP  → EMAIL_OTP (forced, no override)
 * REQUIRE_WEBAUTHN   → WEBAUTHN if enrolled, else EMAIL_OTP (degraded)
 * REQUIRE_TOTP       → TOTP if enrolled, else EMAIL_OTP (allow.enrollment=true triggers wizard)
 * REQUIRE_MFA        → first method in fallback.order that is available
 * null / blank       → defaultMethod (default: EMAIL_OTP) — fail-secure
 * unknown string     → defaultMethod — fail-secure + warn log
 * ALLOW/DENY/LOCK    → ERROR log + defaultMethod (mis-routing guard)
 * ─────────────────────────────────────────────────────────────────
 *
 * Configurator properties (Keycloak admin UI):
 *   fallback.order    – comma-separated: EMAIL_OTP,TOTP,WEBAUTHN
 *   default.method    – EMAIL_OTP | TOTP | WEBAUTHN
 *   email_otp.expiry  – seconds (default 180; clamped 60 for CRITICAL, 120 for HIGH)
 *   allow.enrollment  – boolean (default false; SECURITY: keep false in production)
 */
public class HumifortisStepUpRouter implements Authenticator {

    private static final Logger logger = Logger.getLogger(HumifortisStepUpRouter.class);

    // ── Auth session note keys ────────────────────────────────────────────────
    public static final String NOTE_MFA_METHOD             = "HUMIFORTIS_MFA_METHOD";
    static final String NOTE_EMAIL_OTP_HASH                = "HUMIFORTIS_EMAIL_OTP_HASH";
    static final String NOTE_EMAIL_OTP_EXPIRY              = "HUMIFORTIS_EMAIL_OTP_EXPIRY";
    static final String NOTE_EMAIL_OTP_ATTEMPTS            = "HUMIFORTIS_EMAIL_OTP_ATTEMPTS";
    static final String NOTE_EMAIL_OTP_MAX_ATTEMPTS        = "HUMIFORTIS_EMAIL_OTP_MAX_ATTEMPTS";
    static final String NOTE_CHALLENGE_STARTED             = "HUMIFORTIS_CHALLENGE_STARTED";
    static final String NOTE_EMAIL_OTP_LAST_SENT           = "HUMIFORTIS_EMAIL_OTP_LAST_SENT";

    // ── Env vars ──────────────────────────────────────────────────────────────
    static final String ENV_TRUSTED_PROXY    = "HUMIFORTIS_TRUSTED_PROXY_HEADER";
    static final String ENV_HMAC_SECRET      = "HUMIFORTIS_OTP_HMAC_SECRET";
    static final String ENV_HMAC_SECRET_PREV = "HUMIFORTIS_OTP_HMAC_SECRET_PREVIOUS";

    // ── Tuning constants ──────────────────────────────────────────────────────
    static final int  DEFAULT_MAX_ATTEMPTS      = 3;
    static final long MAX_CHALLENGE_LIFETIME_MS = 600_000L;

    // ── MFA method enum ───────────────────────────────────────────────────────
    enum MfaMethod {
        TOTP, EMAIL_OTP, WEBAUTHN;

        static MfaMethod fromString(String s) {
            if (s == null) return EMAIL_OTP;
            try { return valueOf(s.toUpperCase(Locale.ROOT)); }
            catch (IllegalArgumentException e) { return EMAIL_OTP; }
        }
    }

    // ── Internal exception for SMTP failures ─────────────────────────────────
    static class HumifortisEmailException extends RuntimeException {
        final HumifortisError error;
        final String technicalDetail;

        HumifortisEmailException(HumifortisError error, String detail) {
            super(error.code + ": " + detail);
            this.error = error;
            this.technicalDetail = detail;
        }
    }

    // =========================================================================
    // AUTHENTICATE — challenge phase
    // =========================================================================

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        try {
            AuthenticatorConfigModel cfg = context.getAuthenticatorConfig();
            String fallbackOrder = getConfig(cfg, "fallback.order", "EMAIL_OTP,TOTP,WEBAUTHN");
            String defaultMethod = getConfig(cfg, "default.method",  "EMAIL_OTP");

            String enforcedAction = context.getAuthenticationSession()
                                           .getAuthNote(HumifortisRiskAuthenticator.NOTE_RISK_ACTION);
            String correlationId  = context.getAuthenticationSession()
                                           .getAuthNote("HUMIFORTIS_CORRELATION_ID");
            String userId         = context.getUser().getId();

            HumifortisRateLimiter rl       = new HumifortisRateLimiter();
            String                clientIp = getClientIp(context);

            if (rl.isIpBlocked(clientIp)) {
                HumifortisAuditLog.log("ip_rate_limited", userId, "EMAIL_OTP",
                        "blocked", HumifortisError.MFA_CHALLENGE_FAILED.code, correlationId,
                        "ip_hash=" + rl.hashIp(clientIp));
                denyWithCode(context, HumifortisError.MFA_CHALLENGE_FAILED, "IP rate-limited");
                return;
            }

            if (rl.isUserBlocked(userId)) {
                HumifortisAuditLog.log("user_blocked", userId, "EMAIL_OTP",
                        "soft_blocked", HumifortisError.MFA_CHALLENGE_FAILED.code, correlationId, "");
                denyWithCode(context, HumifortisError.MFA_CHALLENGE_FAILED,
                        "user soft-blocked: " + context.getUser().getUsername());
                return;
            }

            MfaMethod method = resolveMethodSafely(enforcedAction, context.getUser(),
                                                    fallbackOrder, defaultMethod, cfg);

            logger.infof("[StepUpRouter] action=%s -> method=%s user=%s",
                         enforcedAction, method, context.getUser().getUsername());

            context.getAuthenticationSession().setAuthNote(NOTE_MFA_METHOD, method.name());
            context.getAuthenticationSession().setAuthNote(NOTE_CHALLENGE_STARTED,
                    String.valueOf(System.currentTimeMillis()));

            HumifortisAuditLog.log("mfa_challenge", userId, method.name(),
                    "initiated", "", correlationId, "action=" + enforcedAction);

            switch (method) {
                case TOTP     -> challengeTotp(context);
                case WEBAUTHN -> challengeWebAuthn(context, cfg, correlationId);
                case EMAIL_OTP -> {
                    if (!canSendEmail(context.getUser())) {
                        denyWithCode(context, HumifortisError.MFA_EMAIL_UNVERIFIED,
                                "user=" + context.getUser().getUsername());
                        return;
                    }
                    try {
                        challengeEmailOtp(context, cfg);
                    } catch (HumifortisEmailException e) {
                        if (isEnrolled(context.getUser(), MfaMethod.TOTP)) {
                            logger.warnf("[StepUpRouter] SMTP failed -> fallback TOTP user=%s [%s]",
                                         context.getUser().getUsername(), e.error.code);
                            HumifortisAuditLog.log("smtp_fallback_totp", userId,
                                    "EMAIL_OTP->TOTP", "degraded",
                                    e.error.code, correlationId, e.technicalDetail);
                            context.getAuthenticationSession()
                                   .setAuthNote(NOTE_MFA_METHOD, MfaMethod.TOTP.name());
                            challengeTotp(context);
                        } else {
                            denyWithCode(context, e.error, e.technicalDetail);
                        }
                    }
                }
            }
        } catch (Exception e) {
            String user = context.getUser() != null ? context.getUser().getUsername() : "unknown";
            logger.errorf("[StepUpRouter] Unexpected error: %s user=%s", e.getMessage(), user);
            denyWithCode(context, HumifortisError.ROUTER_ERROR,
                         "exception=" + e.getClass().getSimpleName());
        }
    }

    // =========================================================================
    // ACTION — validation phase
    // =========================================================================

    @Override
    public void action(AuthenticationFlowContext context) {
        try {
            MfaMethod method = MfaMethod.fromString(
                    context.getAuthenticationSession().getAuthNote(NOTE_MFA_METHOD));
            switch (method) {
                case TOTP     -> context.attempted(); // delegated to auth-otp-form ALTERNATIVE
                case WEBAUTHN, EMAIL_OTP -> validateEmailOtp(context);
            }
        } catch (Exception e) {
            logger.errorf("[StepUpRouter] Validation error: %s", e.getMessage());
            denyWithCode(context, HumifortisError.MFA_CHALLENGE_FAILED,
                         "validation exception=" + e.getClass().getSimpleName());
        }
    }

    // =========================================================================
    // METHOD RESOLUTION
    // =========================================================================

    MfaMethod resolveMethodSafely(String action, UserModel user, String fallbackOrder,
                                   String defaultMethod, AuthenticatorConfigModel cfg) {
        try {
            return resolveMethod(action, user, fallbackOrder, defaultMethod, cfg);
        } catch (Exception e) {
            logger.errorf("[StepUpRouter] resolveMethod threw: %s -> defaultMethod=%s",
                          e.getMessage(), defaultMethod);
            return MfaMethod.fromString(defaultMethod);
        }
    }

    MfaMethod resolveMethod(String action, UserModel user, String fallbackOrder,
                             String defaultMethod, AuthenticatorConfigModel cfg) {
        if (action == null || action.isBlank()) {
            logger.warnf("[StepUpRouter] No action in session -> %s (fail-secure)", defaultMethod);
            return MfaMethod.fromString(defaultMethod);
        }

        boolean allowEnroll = getBoolConfig(cfg, "allow.enrollment", false);

        return switch (action.toUpperCase(Locale.ROOT)) {

            case "REQUIRE_EMAIL_OTP" -> MfaMethod.EMAIL_OTP;

            case "REQUIRE_WEBAUTHN"  ->
                    isEnrolled(user, MfaMethod.WEBAUTHN) ? MfaMethod.WEBAUTHN : MfaMethod.EMAIL_OTP;

            case "REQUIRE_TOTP" -> {
                if (isEnrolled(user, MfaMethod.TOTP)) yield MfaMethod.TOTP;
                if (allowEnroll) {
                    user.addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
                    logger.infof("[StepUpRouter] TOTP enrollment triggered user=%s",
                                 user.getUsername());
                    yield MfaMethod.TOTP;
                }
                yield MfaMethod.EMAIL_OTP;
            }

            case "REQUIRE_MFA" -> firstAvailable(user, parseFallbackOrder(fallbackOrder));

            case "ALLOW", "DENY", "LOCK_ACCOUNT" -> {
                logger.errorf("[StepUpRouter] Unexpected action '%s' in MFA sub-flow -> %s",
                              action, defaultMethod);
                yield MfaMethod.fromString(defaultMethod);
            }

            default -> {
                logger.warnf("[StepUpRouter] Unknown action '%s' -> %s (fail-secure)",
                             action, defaultMethod);
                yield MfaMethod.fromString(defaultMethod);
            }
        };
    }

    private MfaMethod firstAvailable(UserModel user, List<MfaMethod> order) {
        for (MfaMethod m : order) {
            if (m == MfaMethod.EMAIL_OTP) { if (canSendEmail(user)) return m; }
            else if (isEnrolled(user, m)) return m;
        }
        return MfaMethod.EMAIL_OTP;
    }

    boolean isEnrolled(UserModel user, MfaMethod method) {
        try {
            return switch (method) {
                case TOTP     -> user.credentialManager().getStoredCredentialsStream()
                                     .anyMatch(c -> "otp".equals(c.getType()));
                case WEBAUTHN -> user.credentialManager().getStoredCredentialsStream()
                                     .anyMatch(c -> "webauthn".equals(c.getType())
                                                 || "webauthn-passwordless".equals(c.getType()));
                case EMAIL_OTP -> canSendEmail(user);
            };
        } catch (Exception e) {
            logger.warnf("[StepUpRouter] Enrollment check for %s failed: %s", method, e.getMessage());
            return false;
        }
    }

    boolean canSendEmail(UserModel user) {
        return user.isEmailVerified()
            && user.getEmail() != null
            && !user.getEmail().isBlank();
    }

    // =========================================================================
    // TOTP — delegates to native auth-otp-form ALTERNATIVE in realm flow
    // =========================================================================

    private void challengeTotp(AuthenticationFlowContext context) {
        logger.infof("[StepUpRouter] TOTP delegated to auth-otp-form user=%s",
                     context.getUser().getUsername());
        HumifortisAuditLog.log("totp_delegated", context.getUser().getId(),
                "TOTP", "delegated_to_native", "", "", "");
        context.attempted();
    }

    // =========================================================================
    // WEBAUTHN — fallback to EMAIL_OTP
    // =========================================================================

    private void challengeWebAuthn(AuthenticationFlowContext context,
                                   AuthenticatorConfigModel cfg, String correlationId) {
        logger.warnf("[StepUpRouter] REQUIRE_WEBAUTHN: not enrolled -> degraded EMAIL_OTP user=%s",
                     context.getUser().getUsername());
        HumifortisAuditLog.log("webauthn_degraded", context.getUser().getId(),
                "WEBAUTHN->EMAIL_OTP", "degraded", "", correlationId, "not_enrolled");
        context.getAuthenticationSession().setAuthNote(NOTE_MFA_METHOD, MfaMethod.EMAIL_OTP.name());
        if (!canSendEmail(context.getUser())) {
            denyWithCode(context, HumifortisError.MFA_EMAIL_UNVERIFIED,
                         "webauthn fallback: email not verified");
            return;
        }
        try { challengeEmailOtp(context, cfg); }
        catch (HumifortisEmailException e) { denyWithCode(context, e.error, e.technicalDetail); }
    }

    // =========================================================================
    // EMAIL OTP — challenge
    // =========================================================================

    void challengeEmailOtp(AuthenticationFlowContext context, AuthenticatorConfigModel cfg) {
        int expirySeconds = resolveOtpExpiry(context, cfg);
        int maxAttempts   = resolveMaxAttempts(context);

        HumifortisRateLimiter rl = new HumifortisRateLimiter();
        if (!rl.canSendOtp(context.getUser().getId())) {
            context.challenge(
                context.form()
                       .setAttribute("email", maskEmail(context.getUser().getEmail()))
                       .setAttribute("resendCooldown", HumifortisRateLimiter.OTP_SEND_COOLDOWN_MS / 1000)
                       .createForm("humifortis-email-otp.ftl"));
            return;
        }

        String sessionId  = context.getAuthenticationSession().getParentSession().getId();
        String userId     = context.getUser().getId();
        String code       = generateOtp();
        String hashedCode = hmacOtp(code, sessionId, userId);
        long   expiry     = System.currentTimeMillis() + (expirySeconds * 1000L);

        context.getAuthenticationSession().setAuthNote(NOTE_EMAIL_OTP_HASH,         hashedCode);
        context.getAuthenticationSession().setAuthNote(NOTE_EMAIL_OTP_EXPIRY,       String.valueOf(expiry));
        context.getAuthenticationSession().setAuthNote(NOTE_EMAIL_OTP_ATTEMPTS,     "0");
        context.getAuthenticationSession().setAuthNote(NOTE_EMAIL_OTP_MAX_ATTEMPTS, String.valueOf(maxAttempts));
        context.getAuthenticationSession().setAuthNote(NOTE_EMAIL_OTP_LAST_SENT,    String.valueOf(System.currentTimeMillis()));

        sendOtpEmail(context, code, expirySeconds);
        rl.recordSend(userId);

        context.challenge(
            context.form()
                   .setAttribute("email",         maskEmail(context.getUser().getEmail()))
                   .setAttribute("expirySeconds", expirySeconds)
                   .createForm("humifortis-email-otp.ftl"));
    }

    // =========================================================================
    // EMAIL OTP — validation
    // =========================================================================

    void validateEmailOtp(AuthenticationFlowContext context) {
        String submitted     = context.getHttpRequest().getDecodedFormParameters().getFirst("email_otp");
        String storedHash    = context.getAuthenticationSession().getAuthNote(NOTE_EMAIL_OTP_HASH);
        String expiryStr     = context.getAuthenticationSession().getAuthNote(NOTE_EMAIL_OTP_EXPIRY);
        String startedStr    = context.getAuthenticationSession().getAuthNote(NOTE_CHALLENGE_STARTED);
        String correlationId = context.getAuthenticationSession().getAuthNote("HUMIFORTIS_CORRELATION_ID");
        String sessionId     = context.getAuthenticationSession().getParentSession().getId();
        String userId        = context.getUser().getId();
        int attempts    = HumifortisRateLimiter.safeParseInt(
                context.getAuthenticationSession().getAuthNote(NOTE_EMAIL_OTP_ATTEMPTS), 0);
        int maxAttempts = HumifortisRateLimiter.safeParseInt(
                context.getAuthenticationSession().getAuthNote(NOTE_EMAIL_OTP_MAX_ATTEMPTS), DEFAULT_MAX_ATTEMPTS);

        HumifortisRateLimiter rl = new HumifortisRateLimiter();

        // ── Max challenge lifetime ────────────────────────────────────────────
        if (startedStr != null) {
            long elapsed = System.currentTimeMillis()
                         - HumifortisRateLimiter.safeParseLong(startedStr, 0L);
            if (elapsed > MAX_CHALLENGE_LIFETIME_MS) {
                invalidateOtp(context);
                HumifortisAuditLog.log("otp_expired", userId, "EMAIL_OTP",
                        "lifetime_exceeded", HumifortisError.MFA_INVALID_CODE.code, correlationId, "");
                denyWithCode(context, HumifortisError.MFA_INVALID_CODE, "challenge lifetime exceeded");
                return;
            }
        }

        // ── Expiry check ──────────────────────────────────────────────────────
        long expiry = HumifortisRateLimiter.safeParseLong(expiryStr, 0L);
        if (expiry == 0 || System.currentTimeMillis() > expiry) {
            invalidateOtp(context);
            HumifortisAuditLog.log("otp_expired", userId, "EMAIL_OTP",
                    "code_expired", HumifortisError.MFA_INVALID_CODE.code, correlationId, "");
            context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
                context.form()
                       .setAttribute("errorCode", HumifortisError.MFA_INVALID_CODE.code)
                       .setError("emailOtpExpired")
                       .createForm("humifortis-email-otp.ftl"));
            return;
        }

        // ── Max attempts ──────────────────────────────────────────────────────
        if (attempts >= maxAttempts) {
            invalidateOtp(context);
            rl.recordFailure(userId, getClientIp(context));
            HumifortisAuditLog.log("otp_max_attempts", userId, "EMAIL_OTP",
                    "max_attempts", HumifortisError.MFA_CHALLENGE_FAILED.code, correlationId,
                    "attempts=" + attempts + "/" + maxAttempts);
            denyWithCode(context, HumifortisError.MFA_CHALLENGE_FAILED,
                    "max attempts exceeded user=" + context.getUser().getUsername());
            return;
        }

        // ── Anti-replay ───────────────────────────────────────────────────────
        if (storedHash != null && rl.isOtpAlreadyUsed(storedHash)) {
            logger.warnf("[StepUpRouter] OTP replay detected user=%s", context.getUser().getUsername());
            HumifortisAuditLog.log("otp_replay", userId, "EMAIL_OTP",
                    "denied", HumifortisError.MFA_INVALID_CODE.code, correlationId, "replay_detected");
            denyWithCode(context, HumifortisError.MFA_INVALID_CODE, "OTP replay detected");
            return;
        }

        // ── Code validation ───────────────────────────────────────────────────
        if (submitted == null || storedHash == null
                || !validateHmac(submitted, storedHash, sessionId, userId)) {
            context.getAuthenticationSession()
                   .setAuthNote(NOTE_EMAIL_OTP_ATTEMPTS, String.valueOf(attempts + 1));
            rl.recordFailure(userId, getClientIp(context));
            try {
                org.keycloak.events.EventBuilder evt = context.getEvent().clone();
                evt.event(org.keycloak.events.EventType.LOGIN_ERROR);
                evt.error(org.keycloak.events.Errors.INVALID_USER_CREDENTIALS);
                evt.user(context.getUser());
                evt.detail("method", "EMAIL_OTP");
                evt.detail("hf_code", HumifortisError.MFA_INVALID_CODE.code);
            } catch (Exception ignored) {}
            HumifortisAuditLog.log("mfa_failure", userId, "EMAIL_OTP",
                    "invalid_code", HumifortisError.MFA_INVALID_CODE.code, correlationId,
                    "attempts=" + (attempts + 1) + "/" + maxAttempts);
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                context.form()
                       .setAttribute("errorCode",         HumifortisError.MFA_INVALID_CODE.code)
                       .setAttribute("remainingAttempts", maxAttempts - attempts - 1)
                       .setError("invalidEmailOtp")
                       .createForm("humifortis-email-otp.ftl"));
            return;
        }

        // ── SUCCESS — mark replay BEFORE success() ────────────────────────────
        rl.markOtpUsed(storedHash);
        invalidateOtp(context);
        rl.clearFailures(userId);
        HumifortisAuditLog.log("mfa_success", userId, "EMAIL_OTP", "verified", "", correlationId, "");
        context.success();
    }

    // =========================================================================
    // CRYPTO — HMAC-SHA256, dual-key rotation
    // =========================================================================

    String hmacOtp(String otp, String sessionId, String userId) {
        return computeHmac(otp, sessionId, userId, currentSecret());
    }

    boolean validateHmac(String submitted, String stored, String sessionId, String userId) {
        if (constantTimeEquals(computeHmac(submitted, sessionId, userId, currentSecret()), stored))
            return true;
        String prev = System.getenv(ENV_HMAC_SECRET_PREV);
        if (prev != null && !prev.isBlank()) {
            if (constantTimeEquals(computeHmac(submitted, sessionId, userId, prev), stored)) {
                logger.infof("[StepUpRouter] OTP validated with previous HMAC key (key rotation)");
                return true;
            }
        }
        return false;
    }

    private String currentSecret() {
        String s = System.getenv(ENV_HMAC_SECRET);
        if (s == null || s.isBlank()) {
            logger.warnf("[StepUpRouter] %s not set — SHA-256 fallback active (set in production!)",
                         ENV_HMAC_SECRET);
            return null;
        }
        return s;
    }

    String computeHmac(String otp, String sessionId, String userId, String secret) {
        String input = otp + "|" + sessionId + "|" + userId;
        if (secret == null) return hashSha256(input);
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(
                secret.getBytes(java.nio.charset.StandardCharsets.UTF_8), "HmacSHA256"));
            return java.util.Base64.getEncoder().encodeToString(
                mac.doFinal(input.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (Exception e) { throw new RuntimeException("HMAC failed", e); }
    }

    private String hashSha256(String input) {
        try {
            var md = java.security.MessageDigest.getInstance("SHA-256");
            return java.util.Base64.getEncoder().encodeToString(
                md.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (Exception e) { throw new RuntimeException("SHA-256 failed", e); }
    }

    boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        try {
            byte[] ba = java.util.Base64.getDecoder().decode(a);
            byte[] bb = java.util.Base64.getDecoder().decode(b);
            return java.security.MessageDigest.isEqual(ba, bb);
        } catch (Exception e) { return false; }
    }

    // =========================================================================
    // EMAIL — send OTP code
    // =========================================================================

    private void sendOtpEmail(AuthenticationFlowContext context, String code, int expirySeconds) {
        var smtp = context.getRealm().getSmtpConfig();
        if (smtp == null || smtp.isEmpty())
            throw new HumifortisEmailException(HumifortisError.SERVICE_HTTP_ERROR, "SMTP not configured");
        try {
            UserModel user    = context.getUser();
            String textBody   = "Your authentication code is: " + code
                              + "\n\nExpires in " + expirySeconds + "s.  Do not share it.";
            String htmlBody   = "<p>Your authentication code is: <strong>" + code + "</strong></p>"
                              + "<p>Expires in " + expirySeconds + " seconds.</p>"
                              + "<p>Do not share this code.</p>";
            context.getSession()
                   .getProvider(org.keycloak.email.EmailSenderProvider.class)
                   .send(smtp, user, "Your authentication code", textBody, htmlBody);
            logger.infof("[StepUpRouter] OTP sent to %s", maskEmail(user.getEmail()));
        } catch (HumifortisEmailException e) {
            throw e;
        } catch (Exception e) {
            throw new HumifortisEmailException(HumifortisError.SERVICE_HTTP_ERROR,
                    "SMTP send failed: " + e.getMessage());
        }
    }

    // =========================================================================
    // DENY helper
    // =========================================================================

    private void denyWithCode(AuthenticationFlowContext context,
                               HumifortisError error, String technicalDetail) {
        logger.errorf("[StepUpRouter] %s", error.logMessage(technicalDetail));
        context.failure(AuthenticationFlowError.ACCESS_DENIED,
            context.form()
                   .setAttribute("hfErrorCode",      error.code)
                   .setAttribute("hfErrorMessageKey", error.messageKey())
                   .setAttribute("hfTimestamp",       java.time.Instant.now().toString())
                   .createForm("humifortis-error.ftl"));
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    private int resolveOtpExpiry(AuthenticationFlowContext context, AuthenticatorConfigModel cfg) {
        int base = getIntConfig(cfg, "email_otp.expiry", 180);
        String lvl = context.getAuthenticationSession()
                             .getAuthNote(HumifortisRiskAuthenticator.NOTE_RISK_LEVEL);
        if (lvl == null) return base;
        return switch (lvl.toUpperCase(Locale.ROOT)) {
            case "CRITICAL" -> Math.min(base, 60);
            case "HIGH"     -> Math.min(base, 120);
            default         -> base;
        };
    }

    private int resolveMaxAttempts(AuthenticationFlowContext context) {
        String lvl = context.getAuthenticationSession()
                             .getAuthNote(HumifortisRiskAuthenticator.NOTE_RISK_LEVEL);
        if (lvl == null) return DEFAULT_MAX_ATTEMPTS;
        return switch (lvl.toUpperCase(Locale.ROOT)) {
            case "CRITICAL", "HIGH" -> 2;
            default                 -> DEFAULT_MAX_ATTEMPTS;
        };
    }

    private void invalidateOtp(AuthenticationFlowContext context) {
        context.getAuthenticationSession().setAuthNote(NOTE_EMAIL_OTP_HASH,   "USED");
        context.getAuthenticationSession().setAuthNote(NOTE_EMAIL_OTP_EXPIRY, "0");
    }

    String generateOtp() {
        return String.format("%06d", new SecureRandom().nextInt(1_000_000));
    }

    String maskEmail(String email) {
        if (email == null || !email.contains("@")) return "***";
        String[] p = email.split("@");
        return (p[0].length() > 2 ? p[0].substring(0, 2) : "*") + "***@" + p[1];
    }

    String getClientIp(AuthenticationFlowContext context) {
        try {
            String hdr = HumifortisRiskEvaluator.envOrDefault(ENV_TRUSTED_PROXY, "none").trim();
            if ("none".equalsIgnoreCase(hdr) || hdr.isBlank()) {
                var c = context.getSession().getContext().getConnection();
                return c != null ? c.getRemoteAddr() : "unknown";
            }
            var headers = context.getSession().getContext().getRequestHeaders();
            if (headers == null) {
                var c = context.getSession().getContext().getConnection();
                return c != null ? c.getRemoteAddr() : "unknown";
            }
            String val = headers.getHeaderString(hdr);
            if (val == null || val.isBlank()) {
                var c = context.getSession().getContext().getConnection();
                return c != null ? c.getRemoteAddr() : "unknown";
            }
            String ip = val.split(",")[0].trim();
            return isValidIp(ip) ? ip : (context.getSession().getContext().getConnection() != null
                    ? context.getSession().getContext().getConnection().getRemoteAddr() : "unknown");
        } catch (Exception e) { return "unknown"; }
    }

    private boolean isValidIp(String ip) {
        if (ip == null || ip.isBlank()) return false;
        return ip.matches("^(\\d{1,3}\\.){3}\\d{1,3}(:\\d+)?$|^[0-9a-fA-F:]+$");
    }

    private List<MfaMethod> parseFallbackOrder(String raw) {
        List<MfaMethod> r = new ArrayList<>();
        for (String s : raw.split(",")) {
            try { r.add(MfaMethod.valueOf(s.trim().toUpperCase(Locale.ROOT))); }
            catch (IllegalArgumentException ignored) {}
        }
        if (r.isEmpty()) r.add(MfaMethod.EMAIL_OTP);
        return r;
    }

    String getConfig(AuthenticatorConfigModel cfg, String key, String def) {
        if (cfg == null || cfg.getConfig() == null) return def;
        String v = cfg.getConfig().get(key);
        return (v == null || v.isBlank()) ? def : v;
    }

    int getIntConfig(AuthenticatorConfigModel cfg, String key, int def) {
        try { return Integer.parseInt(getConfig(cfg, key, String.valueOf(def))); }
        catch (Exception e) { return def; }
    }

    boolean getBoolConfig(AuthenticatorConfigModel cfg, String key, boolean def) {
        try { return Boolean.parseBoolean(getConfig(cfg, key, String.valueOf(def))); }
        catch (Exception e) { return def; }
    }

    @Override public boolean requiresUser()                                               { return true; }
    @Override public boolean configuredFor(KeycloakSession s, RealmModel r, UserModel u) { return true; }
    @Override public void setRequiredActions(KeycloakSession s, RealmModel r, UserModel u){}
    @Override public void close() {}
}

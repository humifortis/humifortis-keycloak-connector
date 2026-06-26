package tech.humifortis.keycloak.auth;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.*;
import tech.humifortis.keycloak.HumifortisCache;

import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for HumifortisStepUpRouter (pure-logic only).
 * Lives in the auth package to access package-private methods and inner enum.
 */
@ExtendWith(MockitoExtension.class)
class HumifortisStepUpRouterTest {

    private HumifortisStepUpRouter router;

    @Mock UserModel                user;
    @Mock SubjectCredentialManager creds;

    /** Creates a real AuthenticatorConfigModel with the given key=value entries. */
    private static AuthenticatorConfigModel config(String... kvPairs) {
        AuthenticatorConfigModel m = new AuthenticatorConfigModel();
        java.util.Map<String, String> map = new java.util.HashMap<>();
        for (int i = 0; i < kvPairs.length - 1; i += 2) {
            map.put(kvPairs[i], kvPairs[i + 1]);
        }
        m.setConfig(map);
        return m;
    }

    @BeforeEach
    void setUp() {
        router = new HumifortisStepUpRouter();
        HumifortisCache.getInstance().clear();
    }

    // ═════════════════════════════════════════════════════════════════════════
    // METHOD RESOLUTION
    // ═════════════════════════════════════════════════════════════════════════

    @Test
    void resolveMethod_REQUIRE_EMAIL_OTP_always_email() {
        var m = router.resolveMethod("REQUIRE_EMAIL_OTP", user, "EMAIL_OTP,TOTP", "EMAIL_OTP", null);
        assertEquals(HumifortisStepUpRouter.MfaMethod.EMAIL_OTP, m);
    }

    @Test
    void resolveMethod_null_returns_defaultMethod() {
        var m = router.resolveMethod(null, user, "EMAIL_OTP,TOTP", "EMAIL_OTP", null);
        assertEquals(HumifortisStepUpRouter.MfaMethod.EMAIL_OTP, m);
    }

    @Test
    void resolveMethod_blank_returns_defaultMethod() {
        var m = router.resolveMethod("  ", user, "EMAIL_OTP,TOTP", "EMAIL_OTP", null);
        assertEquals(HumifortisStepUpRouter.MfaMethod.EMAIL_OTP, m);
    }

    @Test
    void resolveMethod_unknown_action_returns_defaultMethod() {
        var m = router.resolveMethod("FOOBAR", user, "EMAIL_OTP,TOTP", "EMAIL_OTP", null);
        assertEquals(HumifortisStepUpRouter.MfaMethod.EMAIL_OTP, m);
    }

    @Test
    void resolveMethod_ALLOW_misrouted_returns_defaultMethod() {
        var m = router.resolveMethod("ALLOW", user, "EMAIL_OTP", "TOTP", null);
        assertEquals(HumifortisStepUpRouter.MfaMethod.TOTP, m);
    }

    @Test
    void resolveMethod_REQUIRE_WEBAUTHN_enrolled_returns_webauthn() {
        when(user.credentialManager()).thenReturn(creds);
        CredentialModel waCred = new CredentialModel();
        waCred.setType("webauthn");
        when(creds.getStoredCredentialsStream()).thenReturn(Stream.of(waCred));

        var m = router.resolveMethod("REQUIRE_WEBAUTHN", user, "EMAIL_OTP", "EMAIL_OTP", null);
        assertEquals(HumifortisStepUpRouter.MfaMethod.WEBAUTHN, m);
    }

    @Test
    void resolveMethod_REQUIRE_WEBAUTHN_not_enrolled_falls_back_email() {
        when(user.credentialManager()).thenReturn(creds);
        when(creds.getStoredCredentialsStream()).thenReturn(Stream.empty());

        var m = router.resolveMethod("REQUIRE_WEBAUTHN", user, "EMAIL_OTP", "EMAIL_OTP", null);
        assertEquals(HumifortisStepUpRouter.MfaMethod.EMAIL_OTP, m);
    }

    @Test
    void resolveMethod_REQUIRE_TOTP_enrolled_returns_totp() {
        when(user.credentialManager()).thenReturn(creds);
        CredentialModel otpCred = new CredentialModel();
        otpCred.setType("otp");
        when(creds.getStoredCredentialsStream()).thenReturn(Stream.of(otpCred));

        var m = router.resolveMethod("REQUIRE_TOTP", user, "EMAIL_OTP", "EMAIL_OTP", null);
        assertEquals(HumifortisStepUpRouter.MfaMethod.TOTP, m);
    }

    @Test
    void resolveMethod_REQUIRE_TOTP_not_enrolled_no_enroll_falls_back_email() {
        when(user.credentialManager()).thenReturn(creds);
        when(creds.getStoredCredentialsStream()).thenReturn(Stream.empty());

        var m = router.resolveMethod("REQUIRE_TOTP", user, "EMAIL_OTP", "EMAIL_OTP", null);
        assertEquals(HumifortisStepUpRouter.MfaMethod.EMAIL_OTP, m);
    }

    @Test
    void resolveMethod_REQUIRE_MFA_email_available() {
        when(user.isEmailVerified()).thenReturn(true);
        when(user.getEmail()).thenReturn("alice@example.com");

        var m = router.resolveMethod("REQUIRE_MFA", user, "EMAIL_OTP,TOTP", "EMAIL_OTP", null);
        assertEquals(HumifortisStepUpRouter.MfaMethod.EMAIL_OTP, m);
    }

    @Test
    void resolveMethodSafely_exceptionInResolve_returns_defaultMethod() {
        when(user.credentialManager()).thenThrow(new RuntimeException("DB down"));
        var m = router.resolveMethodSafely("REQUIRE_TOTP", user, "EMAIL_OTP,TOTP", "EMAIL_OTP", null);
        assertEquals(HumifortisStepUpRouter.MfaMethod.EMAIL_OTP, m,
                "Must fall back to defaultMethod on exception (fail-secure)");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // isEnrolled / canSendEmail
    // ═════════════════════════════════════════════════════════════════════════

    @Test
    void isEnrolled_TOTP_true_when_otp_credential_present() {
        when(user.credentialManager()).thenReturn(creds);
        CredentialModel c = new CredentialModel();
        c.setType("otp");
        when(creds.getStoredCredentialsStream()).thenReturn(Stream.of(c));
        assertTrue(router.isEnrolled(user, HumifortisStepUpRouter.MfaMethod.TOTP));
    }

    @Test
    void isEnrolled_TOTP_false_when_no_otp_credential() {
        when(user.credentialManager()).thenReturn(creds);
        when(creds.getStoredCredentialsStream()).thenReturn(Stream.empty());
        assertFalse(router.isEnrolled(user, HumifortisStepUpRouter.MfaMethod.TOTP));
    }

    @Test
    void isEnrolled_WEBAUTHN_true_for_webauthn_passwordless() {
        when(user.credentialManager()).thenReturn(creds);
        CredentialModel c = new CredentialModel();
        c.setType("webauthn-passwordless");
        when(creds.getStoredCredentialsStream()).thenReturn(Stream.of(c));
        assertTrue(router.isEnrolled(user, HumifortisStepUpRouter.MfaMethod.WEBAUTHN));
    }

    @Test
    void canSendEmail_trueWhenVerifiedAndEmailSet() {
        when(user.isEmailVerified()).thenReturn(true);
        when(user.getEmail()).thenReturn("alice@example.com");
        assertTrue(router.canSendEmail(user));
    }

    @Test
    void canSendEmail_falseWhenNotVerified() {
        when(user.isEmailVerified()).thenReturn(false);
        assertFalse(router.canSendEmail(user));
    }

    @Test
    void canSendEmail_falseWhenEmailNull() {
        when(user.isEmailVerified()).thenReturn(true);
        when(user.getEmail()).thenReturn(null);
        assertFalse(router.canSendEmail(user));
    }

    @Test
    void canSendEmail_falseWhenEmailBlank() {
        when(user.isEmailVerified()).thenReturn(true);
        when(user.getEmail()).thenReturn("  ");
        assertFalse(router.canSendEmail(user));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // generateOtp / maskEmail
    // ═════════════════════════════════════════════════════════════════════════

    @Test
    void generateOtp_is6Digits() {
        String otp = router.generateOtp();
        assertEquals(6, otp.length());
        assertTrue(otp.matches("[0-9]{6}"));
    }

    @Test
    void generateOtp_neverNullOrEmpty() {
        for (int i = 0; i < 10; i++) {
            String otp = router.generateOtp();
            assertNotNull(otp);
            assertFalse(otp.isBlank());
            assertTrue(otp.matches("[0-9]{6}"), "OTP format: " + otp);
        }
    }

    @Test
    void maskEmail_masksLocalPart() {
        assertEquals("al***@example.com", router.maskEmail("alice@example.com"));
    }

    @Test
    void maskEmail_shortLocalPart() {
        assertEquals("****@x.com", router.maskEmail("a@x.com"));
    }

    @Test
    void maskEmail_nullInput_returnsStars() {
        assertEquals("***", router.maskEmail(null));
    }

    @Test
    void maskEmail_noAtSign_returnsStars() {
        assertEquals("***", router.maskEmail("notanemail"));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // HMAC crypto
    // ═════════════════════════════════════════════════════════════════════════

    @Test
    void computeHmac_deterministic() {
        String h1 = router.computeHmac("123456", "sess-1", "uid-1", "my-secret");
        String h2 = router.computeHmac("123456", "sess-1", "uid-1", "my-secret");
        assertEquals(h1, h2, "HMAC must be deterministic");
    }

    @Test
    void computeHmac_differentOtpDifferentHash() {
        String h1 = router.computeHmac("111111", "sess-1", "uid-1", "secret");
        String h2 = router.computeHmac("222222", "sess-1", "uid-1", "secret");
        assertNotEquals(h1, h2, "Different OTP must produce different HMAC");
    }

    @Test
    void computeHmac_differentSessionDifferentHash() {
        String h1 = router.computeHmac("123456", "sess-A", "uid-1", "secret");
        String h2 = router.computeHmac("123456", "sess-B", "uid-1", "secret");
        assertNotEquals(h1, h2, "Different session must produce different HMAC");
    }

    @Test
    void computeHmac_nullSecret_usesSha256Fallback() {
        assertDoesNotThrow(() -> router.computeHmac("000000", "s", "u", null));
    }

    @Test
    void constantTimeEquals_sameValues_returnsTrue() {
        String stored = router.computeHmac("654321", "sid", "uid", "secret");
        assertTrue(router.constantTimeEquals(stored, stored));
    }

    @Test
    void constantTimeEquals_differentValues_returnsFalse() {
        String h1 = router.computeHmac("111111", "sid", "uid", "secret");
        String h2 = router.computeHmac("222222", "sid", "uid", "secret");
        assertFalse(router.constantTimeEquals(h1, h2));
    }

    @Test
    void constantTimeEquals_nullA_returnsFalse() {
        assertFalse(router.constantTimeEquals(null, "abc"));
    }

    @Test
    void constantTimeEquals_nullB_returnsFalse() {
        assertFalse(router.constantTimeEquals("abc", null));
    }

    @Test
    void constantTimeEquals_bothNull_returnsFalse() {
        assertFalse(router.constantTimeEquals(null, null));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Config helpers
    // ═════════════════════════════════════════════════════════════════════════

    @Test
    void getConfig_nullCfg_returnsDefault() {
        assertEquals("DEFAULT", router.getConfig(null, "key", "DEFAULT"));
    }

    @Test
    void getConfig_presentKey_returnsValue() {
        AuthenticatorConfigModel m = config("email_otp.expiry", "300");
        assertEquals("300", router.getConfig(m, "email_otp.expiry", "180"));
    }

    @Test
    void getConfig_blankValue_returnsDefault() {
        AuthenticatorConfigModel m = config("key", "  ");
        assertEquals("DEFAULT", router.getConfig(m, "key", "DEFAULT"));
    }

    @Test
    void getIntConfig_validValue() {
        AuthenticatorConfigModel m = config("email_otp.expiry", "60");
        assertEquals(60, router.getIntConfig(m, "email_otp.expiry", 180));
    }

    @Test
    void getIntConfig_invalidValue_returnsDefault() {
        AuthenticatorConfigModel m = config("email_otp.expiry", "bad");
        assertEquals(180, router.getIntConfig(m, "email_otp.expiry", 180));
    }

    @Test
    void getBoolConfig_true() {
        AuthenticatorConfigModel m = config("allow.enrollment", "true");
        assertTrue(router.getBoolConfig(m, "allow.enrollment", false));
    }

    @Test
    void getBoolConfig_false() {
        AuthenticatorConfigModel m = config("allow.enrollment", "false");
        assertFalse(router.getBoolConfig(m, "allow.enrollment", true));
    }
}

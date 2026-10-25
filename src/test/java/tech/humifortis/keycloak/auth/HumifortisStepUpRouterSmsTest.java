package tech.humifortis.keycloak.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;

import tech.humifortis.keycloak.HumifortisError;

/** The text message as a step-up channel: which factor the router picks and what it does when a code cannot be delivered. */
class HumifortisStepUpRouterSmsTest {

    private static final HumifortisStepUpRouter.MfaMethod EMAIL = HumifortisStepUpRouter.MfaMethod.EMAIL_OTP;
    private static final HumifortisStepUpRouter.MfaMethod SMS = HumifortisStepUpRouter.MfaMethod.SMS_OTP;

    /** A router that records the code challenges it is asked for; a channel listed in {@code failing} cannot deliver. */
    private static class Recording extends HumifortisStepUpRouter {
        final boolean text;
        final List<MfaMethod> challenged = new ArrayList<>();
        final List<MfaMethod> failing;

        Recording(boolean text, MfaMethod... failing) {
            this.text = text;
            this.failing = List.of(failing);
        }

        @Override boolean canText(UserModel user) { return text; }

        @Override
        void challengeCodeOtp(AuthenticationFlowContext context, AuthenticatorConfigModel cfg, MfaMethod channel) {
            challenged.add(channel);
            if (failing.contains(channel)) {
                throw new HumifortisEmailException(HumifortisError.SERVICE_HTTP_ERROR, channel + " cannot deliver");
            }
        }
    }

    private static UserModel user(boolean verifiedEmail, boolean totp) {
        UserModel u = mock(UserModel.class);
        SubjectCredentialManager creds = mock(SubjectCredentialManager.class);
        lenient().when(u.getId()).thenReturn("u1");
        lenient().when(u.getUsername()).thenReturn("alice");
        lenient().when(u.isEmailVerified()).thenReturn(verifiedEmail);
        lenient().when(u.getEmail()).thenReturn(verifiedEmail ? "alice@demo.local" : null);
        lenient().when(u.credentialManager()).thenReturn(creds);
        CredentialModel otp = new CredentialModel();
        otp.setType("otp");
        lenient().when(creds.getStoredCredentialsStream()).thenAnswer(i -> totp ? Stream.of(otp) : Stream.<CredentialModel>empty());
        return u;
    }

    private static AuthenticationFlowContext flow(UserModel user, String action) {
        var context = mock(AuthenticationFlowContext.class, RETURNS_DEEP_STUBS);
        when(context.getUser()).thenReturn(user);
        when(context.getAuthenticationSession().getAuthNote(HumifortisRiskAuthenticator.NOTE_RISK_ACTION)).thenReturn(action);
        lenient().when(context.getConnection().getRemoteAddr()).thenReturn("203.0.113.9");
        return context;
    }

    @Test
    void aPersonWithoutAVerifiedEmail_gettingAnEmailCode_isTextedInstead() {
        Recording router = new Recording(true);
        var context = flow(user(false, false), "REQUIRE_EMAIL_OTP");
        router.authenticate(context);
        assertEquals(List.of(SMS), router.challenged);
        verify(context.getAuthenticationSession()).setAuthNote(HumifortisStepUpRouter.NOTE_MFA_METHOD, "SMS_OTP");
        verify(context, never()).failure(any(AuthenticationFlowError.class), any());
    }

    @Test
    void aPersonWithoutAVerifiedEmailOrANumber_isRefused_neverLetThrough() {
        Recording router = new Recording(false);
        var context = flow(user(false, false), "REQUIRE_MFA");
        router.authenticate(context);
        assertTrue(router.challenged.isEmpty());
        verify(context).failure(eq(AuthenticationFlowError.ACCESS_DENIED), any());
    }

    @Test
    void aVerifiedEmailStaysTheFirstChoice() {
        Recording router = new Recording(true);
        router.authenticate(flow(user(true, false), "REQUIRE_MFA"));
        assertEquals(List.of(EMAIL), router.challenged, "SMS is the last of the default order");
    }

    @Test
    void aFailedEmailDelivery_fallsBackToTheText() {
        Recording router = new Recording(true, EMAIL);
        var context = flow(user(true, false), "REQUIRE_MFA");
        router.authenticate(context);
        assertEquals(List.of(EMAIL, SMS), router.challenged);
        verify(context.getAuthenticationSession()).setAuthNote(HumifortisStepUpRouter.NOTE_MFA_METHOD, "SMS_OTP");
        verify(context, never()).failure(any(AuthenticationFlowError.class), any());
    }

    @Test
    void aFailedTextDelivery_fallsBackToTheEmailCode() {
        Recording router = new Recording(true, SMS);
        // the only enrolled-by-availability order here is email first, so the text is reached through a unverified-email
        // person whose email becomes the fallback: use a person with a verified email and a forced text
        UserModel u = user(true, false);
        var context = flow(u, "REQUIRE_MFA");
        when(context.getAuthenticatorConfig()).thenReturn(config("fallback.order", "SMS_OTP,EMAIL_OTP", "default.method", "SMS_OTP"));
        router.authenticate(context);
        assertEquals(List.of(SMS, EMAIL), router.challenged);
    }

    @Test
    void aFailedTextWithNothingElse_isRefused() {
        Recording router = new Recording(true, SMS);
        var context = flow(user(false, false), "REQUIRE_MFA");
        router.authenticate(context);
        assertEquals(List.of(SMS), router.challenged);
        verify(context).failure(eq(AuthenticationFlowError.ACCESS_DENIED), any());
    }

    @Test
    void anEnrolledAuthenticatorAppIsTriedBeforeAnotherChannel_whenADeliveryFails() {
        var context = flow(user(true, true), "REQUIRE_EMAIL_OTP");
        // the app is run by Keycloak's own form: the router hands the challenge to it
        org.keycloak.authentication.Authenticator keycloakOtp = mock(org.keycloak.authentication.Authenticator.class);
        HumifortisStepUpRouter withOtp = new Recording(true, EMAIL) {
            @Override
            org.keycloak.authentication.Authenticator otp(AuthenticationFlowContext c) { return keycloakOtp; }
        };
        withOtp.authenticate(context);
        verify(keycloakOtp).authenticate(context);
    }

    @Test
    void theFactorHumifortisRequired_isTheOneChallenged_whateverTheRoutersOwnOrder() {
        Recording router = new Recording(true);
        var context = flow(user(true, false), "REQUIRE_MFA");
        when(context.getAuthenticationSession().getAuthNote(HumifortisRiskAuthenticator.NOTE_REQUIRED_FACTOR)).thenReturn("SMS_OTP");
        router.authenticate(context);
        assertEquals(List.of(SMS), router.challenged, "e-mail would be the router's own first choice");
    }

    @Test
    void anUnknownRequiredFactor_isIgnored_andTheRouterPicksByItsOwnOrder() {
        assertEquals(null, HumifortisStepUpRouter.requiredMethod("PUSH"));
        assertEquals(null, HumifortisStepUpRouter.requiredMethod(" "));
        assertEquals(HumifortisStepUpRouter.MfaMethod.TOTP, HumifortisStepUpRouter.requiredMethod("totp"));
    }

    @Test
    void withoutAFactorFromHumifortis_thePersonsOwnAuthenticatorComesBeforeTheEmailCode() {
        org.keycloak.authentication.Authenticator keycloakOtp = mock(org.keycloak.authentication.Authenticator.class);
        HumifortisStepUpRouter withOtp = new Recording(true) {
            @Override
            org.keycloak.authentication.Authenticator otp(AuthenticationFlowContext c) { return keycloakOtp; }
        };
        var context = flow(user(true, true), "REQUIRE_MFA");
        withOtp.authenticate(context);
        verify(keycloakOtp).authenticate(context);
    }

    private static AuthenticatorConfigModel config(String... kv) {
        AuthenticatorConfigModel m = new AuthenticatorConfigModel();
        java.util.Map<String, String> map = new java.util.HashMap<>();
        for (int i = 0; i < kv.length - 1; i += 2) map.put(kv[i], kv[i + 1]);
        m.setConfig(map);
        return m;
    }
}

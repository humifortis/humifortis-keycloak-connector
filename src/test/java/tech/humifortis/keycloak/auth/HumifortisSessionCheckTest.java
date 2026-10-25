package tech.humifortis.keycloak.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/** The reuse of a single-sign-on session: when it is evaluated and what a decision does to it. */
class HumifortisSessionCheckTest {

    private static class Check extends HumifortisSessionCheck {
        final HumifortisRiskEvaluator.EvaluateResponse answer;
        int evaluations;

        Check(HumifortisRiskEvaluator.EvaluateResponse answer) { this.answer = answer; }

        @Override
        HumifortisRiskEvaluator.EvaluateResponse evaluate(KeycloakSession s, RealmModel r, UserModel u, String flowId) {
            evaluations++;
            return answer;
        }
    }

    private static HumifortisRiskEvaluator.EvaluateResponse decision(String action, String mode) {
        var d = new HumifortisRiskEvaluator.EvaluateResponse();
        d.action = action;
        d.enforced_action = action;
        d.mode = mode;
        d.risk_level = "HIGH";
        return d;
    }

    private static RequiredActionContext context(String sso, String decided) {
        var ctx = mock(RequiredActionContext.class, RETURNS_DEEP_STUBS);
        when(ctx.getUser()).thenReturn(mock(UserModel.class));
        when(ctx.getRealm().getName()).thenReturn("demo");
        when(ctx.getAuthenticationSession().getAuthNote("SSO_AUTH")).thenReturn(sso);
        when(ctx.getAuthenticationSession().getAuthNote(HumifortisRiskAuthenticator.NOTE_RISK_ACTION)).thenReturn(decided);
        return ctx;
    }

    @Test
    void aPasswordSignIn_isNotEvaluatedAgain() {
        Check check = new Check(decision("DENY", "enforce"));
        var ctx = context("true", "ALLOW");
        check.evaluateTriggers(ctx);
        assertEquals(0, check.evaluations);
    }

    @Test
    void aSignInThatIsNotTheCookie_isLeftAlone() {
        Check check = new Check(decision("DENY", "enforce"));
        check.evaluateTriggers(context(null, null));
        assertEquals(0, check.evaluations);
    }

    @Test
    void anAllow_addsNothing() {
        Check check = new Check(decision("ALLOW", "enforce"));
        var ctx = context("true", null);
        check.evaluateTriggers(ctx);
        assertEquals(1, check.evaluations);
        verify(ctx.getAuthenticationSession(), never()).addRequiredAction(anyString());
    }

    @Test
    void aDeny_addsTheChallenge() {
        Check check = new Check(decision("DENY", "enforce"));
        var ctx = context("true", null);
        check.evaluateTriggers(ctx);
        verify(ctx.getAuthenticationSession()).addRequiredAction(HumifortisSessionCheck.PROVIDER_ID);
    }

    @Test
    void aStepUp_endsTheSessionToo() {
        Check check = new Check(decision("REQUIRE_MFA", "enforce"));
        var ctx = context("true", null);
        check.evaluateTriggers(ctx);
        verify(ctx.getAuthenticationSession()).addRequiredAction(HumifortisSessionCheck.PROVIDER_ID);
    }

    @Test
    void inDryRun_nothingIsRefused() {
        Check check = new Check(decision("DENY", "dry_run"));
        var ctx = context("true", null);
        check.evaluateTriggers(ctx);
        assertEquals(1, check.evaluations);
        verify(ctx.getAuthenticationSession(), never()).addRequiredAction(anyString());
    }

    @Test
    void theReuseIsEvaluatedOncePerAuthenticationSession() {
        Check check = new Check(decision("ALLOW", "enforce"));
        var ctx = context("true", null);
        when(ctx.getAuthenticationSession().getAuthNote(HumifortisSessionCheck.NOTE_SESSION_CHECKED)).thenReturn("true");
        check.evaluateTriggers(ctx);
        assertEquals(0, check.evaluations);
    }

    @Test
    void aFaultNeverStopsTheSignIn() {
        Check check = new Check(null) {
            @Override
            HumifortisRiskEvaluator.EvaluateResponse evaluate(KeycloakSession s, RealmModel r, UserModel u, String f) {
                throw new IllegalStateException("boom");
            }
        };
        var ctx = context("true", null);
        check.evaluateTriggers(ctx);
        verify(ctx.getAuthenticationSession(), never()).addRequiredAction(any(String.class));
    }
}

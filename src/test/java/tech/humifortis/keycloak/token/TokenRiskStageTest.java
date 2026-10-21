package tech.humifortis.keycloak.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Test;

import tech.humifortis.keycloak.auth.HumifortisRiskEvaluator;

class TokenRiskStageTest {

    private static HumifortisRiskEvaluator.EvaluateResponse answer(String action, String enforced, String mode) {
        HumifortisRiskEvaluator.EvaluateResponse d = new HumifortisRiskEvaluator.EvaluateResponse();
        d.action = action;
        d.enforced_action = enforced;
        d.mode = mode;
        return d;
    }

    @Test
    void aDenyRefuses() {
        var v = TokenRiskStage.decide(answer("DENY", "DENY", "enforce"), null);
        assertTrue(v.refuse());
        assertEquals("DENY", v.applied());
    }

    @Test
    void aStepUpRefuses_noFactorCanBeAskedAtTheTokenEndpoint() {
        assertTrue(TokenRiskStage.decide(answer("REQUIRE_MFA", "REQUIRE_MFA", "enforce"), null).refuse());
        // the factor resolved against the person's own methods is the one that counts
        assertTrue(TokenRiskStage.decide(answer("REQUIRE_WEBAUTHN", "REQUIRE_TOTP", "enforce"), null).refuse());
    }

    @Test
    void anAllowGoesThrough() {
        assertFalse(TokenRiskStage.decide(answer("ALLOW", "ALLOW", "enforce"), null).refuse());
    }

    @Test
    void dryRunAndShadowNeverRefuse() {
        assertFalse(TokenRiskStage.decide(answer("DENY", "DENY", "dry_run"), null).refuse());
        assertFalse(TokenRiskStage.decide(answer("REQUIRE_MFA", "REQUIRE_MFA", "shadow"), null).refuse());
    }

    @Test
    void noAnswerIsFailOpenUnlessTheClientSaysDeny() {
        assertFalse(TokenRiskStage.decide(null, null).refuse());
        assertFalse(TokenRiskStage.decide(null, "allow").refuse());
        var denied = TokenRiskStage.decide(null, "deny");
        assertTrue(denied.refuse());
        assertEquals("DENY", denied.applied());
    }

    @Test
    void theRefusalIsRecognisedByItsErrorDetail_neverACredentialFailure() {
        assertTrue(TokenRiskStage.isRefusal(Map.of("client_policy_error_detail", "humifortis_risk")));
        assertFalse(TokenRiskStage.isRefusal(Map.of("client_policy_error_detail", "something_else")));
        assertFalse(TokenRiskStage.isRefusal(Map.of()));
        assertFalse(TokenRiskStage.isRefusal(null));
    }
}

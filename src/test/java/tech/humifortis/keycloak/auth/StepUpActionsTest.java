package tech.humifortis.keycloak.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

import org.junit.jupiter.api.Test;

class StepUpActionsTest {

    @Test
    void everyStepUpTheServerCanReturnIsKnown() {
        // humifortis-core policy/engine.rego human_mfa_actions
        assertEquals(Set.of("REQUIRE_MFA", "REQUIRE_WEBAUTHN", "REQUIRE_TOTP", "REQUIRE_EMAIL_OTP"), StepUpActions.ALL);
        for (String a : StepUpActions.ALL) assertTrue(StepUpActions.isStepUp(a), a);
    }

    @Test
    void otherActionsAreNotStepUps() {
        for (String a : new String[] {"ALLOW", "DENY", "LOCK_ACCOUNT", "NOTIFY_USER", "", null}) {
            assertFalse(StepUpActions.isStepUp(a), String.valueOf(a));
        }
    }
}

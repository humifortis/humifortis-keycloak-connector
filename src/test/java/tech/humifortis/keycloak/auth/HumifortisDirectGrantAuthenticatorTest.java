package tech.humifortis.keycloak.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Test;

import jakarta.ws.rs.core.Response;

class HumifortisDirectGrantAuthenticatorTest {

    @Test
    void aDenyIsRefused() {
        assertTrue(HumifortisDirectGrantAuthenticator.refuses("DENY", "enforce"));
        assertTrue(HumifortisDirectGrantAuthenticator.refuses("LOCK_ACCOUNT", "enforce"));
    }

    @Test
    void everyStepUpIsRefused_noSecondFactorCanBeAskedInThisFlow() {
        for (String action : StepUpActions.ALL) {
            assertTrue(HumifortisDirectGrantAuthenticator.refuses(action, "enforce"), action);
        }
    }

    @Test
    void anAllowGoesThrough() {
        assertFalse(HumifortisDirectGrantAuthenticator.refuses("ALLOW", "enforce"));
        assertFalse(HumifortisDirectGrantAuthenticator.refuses("NOTIFY_USER", "enforce"), "a side effect alone is an allow");
    }

    @Test
    void dryRunAndShadowNeverRefuse() {
        assertFalse(HumifortisDirectGrantAuthenticator.refuses("DENY", "dry_run"));
        assertFalse(HumifortisDirectGrantAuthenticator.refuses("REQUIRE_MFA", "shadow"));
    }

    @Test
    void theRefusalIsA401WithTheRiskDescription() {
        Response r = HumifortisDirectGrantAuthenticator.refusal();
        assertEquals(401, r.getStatus());
        assertEquals("application/json", r.getMediaType().toString());
        assertEquals(Map.of("error", "access_denied", "error_description", "humifortis_risk"), r.getEntity());
    }
}

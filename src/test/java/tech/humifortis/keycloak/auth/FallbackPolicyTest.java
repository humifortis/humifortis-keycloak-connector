package tech.humifortis.keycloak.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import tech.humifortis.keycloak.auth.FallbackPolicy.Outcome;
import tech.humifortis.keycloak.auth.FallbackPolicy.TenantPolicy;

class FallbackPolicyTest {

    @AfterEach
    void clear() { FallbackPolicy.clearCache(); }

    @Test
    void builtInDefault_stepUpForPrivilegedAllowForOthers() {
        assertEquals(Outcome.STEP_UP, FallbackPolicy.resolve((Outcome) null, null, true, true).outcome());
        assertEquals(Outcome.ALLOW, FallbackPolicy.resolve((Outcome) null, null, false, true).outcome());
        assertEquals("default", FallbackPolicy.resolve((Outcome) null, null, false, true).source());
    }

    @Test
    void privilegedWithoutAnyStepUpMethodIsDeniedByDefault() {
        FallbackPolicy.Decision d = FallbackPolicy.resolve((Outcome) null, null, true, false);
        assertEquals(Outcome.DENY, d.outcome());
        assertTrue(d.stepUpUnavailable());
    }

    @Test
    void precedence_envOverTenantOverDefault() {
        TenantPolicy tenant = new TenantPolicy(Outcome.DENY, Outcome.DENY, Outcome.ALLOW, Outcome.DENY);
        assertEquals("env", FallbackPolicy.resolve(Outcome.ALLOW, tenant, true, true).source());
        assertEquals(Outcome.ALLOW, FallbackPolicy.resolve(Outcome.ALLOW, tenant, true, true).outcome());
        assertEquals("tenant_cache", FallbackPolicy.resolve(null, tenant, false, true).source());
        assertEquals(Outcome.DENY, FallbackPolicy.resolve(null, tenant, false, true).outcome());
    }

    @Test
    void stepUpTheUserCannotPerformBecomesTheNoMfaOutcome() {
        TenantPolicy tenant = new TenantPolicy(Outcome.STEP_UP, Outcome.STEP_UP, Outcome.ALLOW, Outcome.DENY);
        assertEquals(Outcome.ALLOW, FallbackPolicy.resolve(null, tenant, false, false).outcome());
        assertEquals(Outcome.DENY, FallbackPolicy.resolve(null, tenant, true, false).outcome());
        assertEquals(Outcome.STEP_UP, FallbackPolicy.resolve(null, tenant, true, true).outcome());
        // an operator forcing step-up still cannot step up a user without a method
        assertEquals(Outcome.ALLOW, FallbackPolicy.resolve(Outcome.STEP_UP, null, false, false).outcome());
    }

    @Test
    void tenantPolicyIsCachedFromTheResponse() {
        FallbackPolicy.remember("t1", Map.of("default", "step_up", "privileged", "deny", "no_mfa", "deny"), "shadow");
        FallbackPolicy.Decision d = FallbackPolicy.resolve(null, "t1", false, true);
        assertEquals(Outcome.STEP_UP, d.outcome());
        assertEquals("tenant_cache", d.source());
        assertEquals(Outcome.DENY, FallbackPolicy.resolve(null, "t1", true, true).outcome());
        assertEquals(Outcome.DENY, FallbackPolicy.resolve(null, "t1", false, false).outcome());
        assertEquals("shadow", FallbackPolicy.cachedMode("t1"));
        assertNull(FallbackPolicy.cachedMode("other"));
    }

    @Test
    void anEmptyOrInvalidPolicyIsNotCached() {
        FallbackPolicy.remember("t1", Map.of(), null);
        FallbackPolicy.remember("t2", Map.of("default", "perhaps"), null);
        assertEquals("default", FallbackPolicy.resolve(null, "t1", false, true).source());
        assertEquals("default", FallbackPolicy.resolve(null, "t2", false, true).source());
        assertFalse(FallbackPolicy.resolve(null, "t1", false, true).stepUpUnavailable());
    }
}

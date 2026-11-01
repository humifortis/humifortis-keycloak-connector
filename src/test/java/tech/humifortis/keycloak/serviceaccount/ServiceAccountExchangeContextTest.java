package tech.humifortis.keycloak.serviceaccount;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** MA-2: the audience a machine exchanges its token for is judged like a scope, against a declared baseline only. */
class ServiceAccountExchangeContextTest {

    private static final Instant NOW = Instant.parse("2026-10-21T12:00:00Z");

    @Test
    void anAudienceOutsideTheDeclaredBaselineIsAScopeTheBaselineLacks() {
        Map<String, String> attrs = Map.of(ServiceAccountContext.ATTR_BASELINE_AUDIENCES, "billing, reports");
        Map<String, String> out = ServiceAccountContext.resolveExchange(attrs, "10.0.0.1", null, "payroll", NOW);
        assertEquals("aud:payroll", out.get(ServiceAccountContext.KEY_REQUESTED_SCOPES));
        assertEquals("aud:billing,aud:reports", out.get(ServiceAccountContext.KEY_HISTORICAL_SCOPES));
    }

    @Test
    void anAudienceInsideTheBaselineIsListedOnBothSides() {
        Map<String, String> attrs = Map.of(ServiceAccountContext.ATTR_BASELINE_AUDIENCES, "billing");
        Map<String, String> out = ServiceAccountContext.resolveExchange(attrs, null, null, "billing", NOW);
        assertEquals("aud:billing", out.get(ServiceAccountContext.KEY_REQUESTED_SCOPES));
        assertEquals("aud:billing", out.get(ServiceAccountContext.KEY_HISTORICAL_SCOPES));
    }

    @Test
    void nothingIsJudgedWithoutADeclaredBaseline() {
        Map<String, String> out = ServiceAccountContext.resolveExchange(Map.of(), null, "read", "payroll", NOW);
        assertNull(out.get(ServiceAccountContext.KEY_REQUESTED_SCOPES), "a baseline never declared is not guessed");
        assertNull(out.get(ServiceAccountContext.KEY_HISTORICAL_SCOPES));
    }

    @Test
    void scopesAreJudgedOnlyWhenAScopeBaselineIsDeclared() {
        Map<String, String> attrs = Map.of(ServiceAccountContext.ATTR_BASELINE_AUDIENCES, "billing");
        Map<String, String> out = ServiceAccountContext.resolveExchange(attrs, null, "admin", "billing", NOW);
        assertFalse(out.get(ServiceAccountContext.KEY_REQUESTED_SCOPES).contains("admin"), "the scope baseline is absent: the scope is not compared");

        Map<String, String> both = Map.of(ServiceAccountContext.ATTR_BASELINE_AUDIENCES, "billing", ServiceAccountContext.ATTR_BASELINE_SCOPES, "read");
        Map<String, String> out2 = ServiceAccountContext.resolveExchange(both, null, "admin", "billing", NOW);
        assertEquals("admin,aud:billing", out2.get(ServiceAccountContext.KEY_REQUESTED_SCOPES));
        assertEquals("aud:billing,read", out2.get(ServiceAccountContext.KEY_HISTORICAL_SCOPES));
    }

    @Test
    void theOtherExpectationsStillApply() {
        Map<String, String> attrs = Map.of(ServiceAccountContext.ATTR_SOURCE_ALLOWLIST, "10.0.0.0/8", ServiceAccountContext.ATTR_BASELINE_AUDIENCES, "billing");
        Map<String, String> out = ServiceAccountContext.resolveExchange(attrs, "192.168.1.5", null, "billing", NOW);
        assertEquals("false", out.get(ServiceAccountContext.KEY_SOURCE_ALLOWLIST_MATCH));
        assertTrue(out.containsKey(ServiceAccountContext.KEY_REQUESTED_SCOPES));
    }
}

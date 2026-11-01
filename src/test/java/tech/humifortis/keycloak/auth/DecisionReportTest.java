package tech.humifortis.keycloak.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.Map;

import org.junit.jupiter.api.Test;

import tech.humifortis.keycloak.model.HumifortisEvent;

class DecisionReportTest {

    private static Map<String, Object> report(String requested, String enforced, String mode) {
        HumifortisEvent e = DecisionReport.build(DecisionReport.DECISION_ENFORCED, "user:keycloak:demo:u1", DecisionReport.USER, "flow-1", "demo",
                requested, enforced, mode, Map.of("decision_rule", "baseline_medium", "blank", " "));
        assertEquals("decision_enforced", e.getEventType());
        assertEquals("user:keycloak:demo:u1", e.getEntityId());
        assertEquals("flow-1", e.getFlowId());
        assertNotNull(e.getEventId());
        return e.getMetadata();
    }

    @Test
    void anEnforcedDecisionReportsWhatThePersonExperienced() {
        Map<String, Object> allow = report("ALLOW", "ALLOW", "enforce");
        assertEquals("allow", allow.get("outcome"));
        assertEquals("true", allow.get("applied"));

        Map<String, Object> stepUp = report("REQUIRE_WEBAUTHN", "REQUIRE_EMAIL_OTP", "enforce");
        assertEquals("step_up", stepUp.get("outcome"));
        assertEquals("REQUIRE_WEBAUTHN", stepUp.get("requested_action"));
        assertEquals("REQUIRE_EMAIL_OTP", stepUp.get("enforced_action"), "the factor actually asked");
        assertEquals("REQUIRE_EMAIL_OTP", stepUp.get("step_up_action"));

        assertEquals("step_up", report("REQUIRE_TOTP", null, "enforce").get("outcome"), "TOTP is a step-up");
        assertEquals("deny", report("DENY", "DENY", "enforce").get("outcome"));
        assertEquals("deny", report("LOCK_ACCOUNT", null, "enforce").get("outcome"));
        assertEquals("allow", report("NOTIFY_USER", null, "enforce").get("outcome"), "an unknown action is executed as an allow");
    }

    @Test
    void inDryRunAndShadowThePersonIsLetInAndTheWouldOutcomeIsKept() {
        for (String mode : new String[] {"dry_run", "shadow"}) {
            Map<String, Object> m = report("DENY", "DENY", mode);
            assertEquals("allow", m.get("outcome"), mode);
            assertEquals("deny", m.get("would_outcome"), mode);
            assertEquals("false", m.get("applied"), mode);
            assertEquals(mode, m.get("mode"));
        }
    }

    @Test
    void blankContextIsDropped() {
        Map<String, Object> m = report("ALLOW", "ALLOW", "enforce");
        assertEquals("baseline_medium", m.get("decision_rule"));
        assertFalse(m.containsKey("blank"));
    }
}

package tech.humifortis.keycloak.auth;

import com.google.gson.Gson;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The local decision source, without Keycloak (docs/risk-as-data.spec.md, D4, D10, D11, D13, D17, D18): the notes, the
 * four conditions as pure functions of the notes, the setting and what the last-step reporter derives.
 */
class LocalDecisionSourceTest {

    private static final Gson GSON = new Gson();

    /** A map-backed authentication session. */
    static final class MapNotes implements ContextNotes.Notes {
        final Map<String, String> m = new HashMap<>();
        @Override public String get(String key) { return m.get(key); }
        @Override public void set(String key, String value) { m.put(key, value); }
        @Override public void remove(String key) { m.remove(key); }
    }

    private static EvaluationContext context(String json) {
        return GSON.fromJson(json, EvaluationContext.class);
    }

    private static final String CONTEXT = """
            {"context_version":"1.0","record_id":"rec-1",
             "attributes":[
               {"name":"network.is_tor","value":true,"tier":1},
               {"name":"network.country_mismatch","value":"FR","tier":1},
               {"name":"user.email","value":"alice@example.com","tier":1,"sensitive":true},
               {"name":"device.first_seen","unavailable":true,"tier":2},
               {"name":"geo.city","value":"Paris","tier":1}],
             "signals":[{"rule":"new_country"},{"rule":"impossible_travel"},{"rule":"experimental","shadow":true}],
             "risk":{"score":71,"level":"high"},
             "decision":{"action":"REQUIRE_MFA","enforced_action":"REQUIRE_MFA","policy_source":"platform","mandatory":false,
               "reasons":[{"rule":"new_country","title":"New country","rationale":"first sign-in from DE"}]}}""";

    private MapNotes written(boolean enforcing) {
        MapNotes n = new MapNotes();
        ContextNotes.write(n, context(CONTEXT), enforcing, DecisionSource.DEFAULT_ATTRIBUTES);
        n.set(HumifortisRiskAuthenticator.NOTE_RISK_ACTION, "REQUIRE_MFA");
        return n;
    }

    // ── the notes ─────────────────────────────────────────────────────────────

    @Test
    void notesCarryTheContextAndNothingSensitive() {
        MapNotes n = written(true);
        assertEquals("1.0", n.get(ContextNotes.VERSION));
        assertEquals("true", n.get(ContextNotes.ENFORCING));
        assertEquals("HIGH", n.get(ContextNotes.LEVEL));
        assertEquals("new_country,impossible_travel", n.get(ContextNotes.RULES), "a shadow rule is never in the notes");
        assertEquals("rec-1", n.get(ContextNotes.RECORD));
        assertEquals("[\"New country: first sign-in from DE\"]", n.get(ContextNotes.REASONS));
        assertEquals("true", n.get(ContextNotes.ATTR_PREFIX + "network.is_tor"));
        // outside the allowlist, sensitive, or unavailable: not written, so a condition on it never matches
        assertNull(n.get(ContextNotes.ATTR_PREFIX + "geo.city"), "not in the allowlist");
        assertNull(n.get(ContextNotes.ATTR_PREFIX + "user.email"), "sensitive");
        assertNull(n.get(ContextNotes.ATTR_PREFIX + "device.first_seen"), "unavailable is not a value");
    }

    @Test
    void notesAreBounded() {
        StringBuilder signals = new StringBuilder();
        for (int i = 0; i < 40; i++) signals.append(i == 0 ? "" : ",").append("{\"rule\":\"r").append(i).append("\"}");
        StringBuilder reasons = new StringBuilder();
        for (int i = 0; i < 9; i++) reasons.append(i == 0 ? "" : ",").append("{\"rule\":\"x\",\"title\":\"").append("t".repeat(300)).append("\"}");
        EvaluationContext c = context("{\"context_version\":\"1.0\",\"signals\":[" + signals + "],\"risk\":{\"level\":\"LOW\"},"
                + "\"decision\":{\"action\":\"ALLOW\",\"reasons\":[" + reasons + "]}}");
        MapNotes n = new MapNotes();
        ContextNotes.write(n, c, true, List.of());
        assertEquals(ContextNotes.MAX_RULES, n.get(ContextNotes.RULES).split(",").length);
        List<?> out = GSON.fromJson(n.get(ContextNotes.REASONS), List.class);
        assertEquals(ContextNotes.MAX_REASONS, out.size());
        assertEquals(ContextNotes.MAX_REASON_CHARS, ((String) out.get(0)).length());
    }

    @Test
    void everyEvaluationClearsTheNotesAndWritesThemWhole() {
        MapNotes n = written(true);
        n.set(ContextNotes.REPORT, ContextNotes.REPORT_PENDING);
        ContextNotes.clear(n);
        assertTrue(n.m.keySet().stream().noneMatch(k -> k.startsWith("HUMIFORTIS_CTX") || k.equals(ContextNotes.REASONS)),
                "nothing of the earlier pass is left: " + n.m.keySet());
        // a second write with fewer attributes does not keep the first one's
        MapNotes again = written(true);
        ContextNotes.write(again, context("{\"context_version\":\"1.0\",\"risk\":{\"level\":\"LOW\"},\"decision\":{\"action\":\"ALLOW\"}}"), true, DecisionSource.DEFAULT_ATTRIBUTES);
        assertNull(again.get(ContextNotes.ATTR_PREFIX + "network.is_tor"));
        assertEquals("", again.get(ContextNotes.RULES));
    }

    // ── a context that cannot be used (D11) ───────────────────────────────────

    @Test
    void aMissingOrUnknownContextIsNotUsable() {
        assertFalse(EvaluationContext.usable(null));
        assertFalse(EvaluationContext.usable(context("{}")));
        assertFalse(EvaluationContext.usable(context("{\"context_version\":\"2.0\",\"risk\":{\"level\":\"LOW\"},\"decision\":{}}")), "another major");
        assertFalse(EvaluationContext.usable(context("{\"context_version\":\"1.0\",\"decision\":{}}")), "no risk level");
        assertFalse(EvaluationContext.usable(context("{\"context_version\":\"1.0\",\"risk\":{\"level\":\"\"},\"decision\":{}}")));
        assertTrue(EvaluationContext.usable(context(CONTEXT)));
        assertTrue(EvaluationContext.usable(context("{\"context_version\":\"1.7\",\"risk\":{\"level\":\"LOW\"},\"decision\":{}}")), "an additive minor");
    }

    // ── the four conditions ───────────────────────────────────────────────────

    @Test
    void platformDecision() {
        MapNotes n = written(true);
        assertTrue(ContextConditions.platformDecision(n, ContextConditions.OUTCOME_STEP_UP));
        assertFalse(ContextConditions.platformDecision(n, ContextConditions.OUTCOME_DENY));

        n.set(HumifortisRiskAuthenticator.NOTE_RISK_ACTION, "DENY");
        assertTrue(ContextConditions.platformDecision(n, ContextConditions.OUTCOME_DENY), "the baseline CRITICAL deny reaches the flow");
        assertFalse(ContextConditions.platformDecision(n, ContextConditions.OUTCOME_STEP_UP), "a deny is not a challenge");

        n.set(HumifortisRiskAuthenticator.NOTE_RISK_ACTION, "ALLOW");
        assertFalse(ContextConditions.platformDecision(n, ContextConditions.OUTCOME_STEP_UP));
        assertFalse(ContextConditions.platformDecision(n, ContextConditions.OUTCOME_DENY));
    }

    @Test
    void nothingMatchesInDryRunAndShadow() {
        MapNotes n = written(false);   // ENFORCING=false
        assertFalse(ContextConditions.platformDecision(n, ContextConditions.OUTCOME_STEP_UP));
        assertFalse(ContextConditions.riskLevelAtLeast(n, "LOW"));
        assertFalse(ContextConditions.ruleFired(n, "new_country"));
        assertFalse(ContextConditions.attributeEquals(n, "network.is_tor", "true"));
    }

    @Test
    void withNoNotesTheStepUpConditionAsksForAChallengeAndNothingElseMatches() {
        MapNotes n = new MapNotes();   // the risk authenticator did not run, or the flow is mis-ordered
        assertTrue(ContextConditions.platformDecision(n, ContextConditions.OUTCOME_STEP_UP), "friction, never a silent allow");
        assertFalse(ContextConditions.platformDecision(n, ContextConditions.OUTCOME_DENY), "and never a deny from nothing");
        assertFalse(ContextConditions.riskLevelAtLeast(n, "LOW"));
        assertFalse(ContextConditions.ruleFired(n, "new_country"));
        assertFalse(ContextConditions.attributeEquals(n, "network.is_tor", "true"));
    }

    @Test
    void theServerSourceKeepsItsBehaviour() {
        MapNotes n = new MapNotes();   // no context notes: the server source
        n.set(HumifortisRiskAuthenticator.NOTE_RISK_ACTION, "REQUIRE_MFA");
        assertTrue(ContextConditions.platformDecision(n, ContextConditions.OUTCOME_STEP_UP));
        n.set(HumifortisRiskAuthenticator.NOTE_RISK_ACTION, "ALLOW");
        assertFalse(ContextConditions.platformDecision(n, ContextConditions.OUTCOME_STEP_UP));
        n.set(HumifortisRiskAuthenticator.NOTE_RISK_ACTION, "SOMETHING_NEW");
        assertTrue(ContextConditions.platformDecision(n, ContextConditions.OUTCOME_STEP_UP), "an unknown action asks for a challenge");
        // an older flow that only has the level
        MapNotes old = new MapNotes();
        old.set(HumifortisRiskAuthenticator.NOTE_RISK_LEVEL, "HIGH");
        assertTrue(ContextConditions.platformDecision(old, ContextConditions.OUTCOME_STEP_UP));
        old.set(HumifortisRiskAuthenticator.NOTE_RISK_LEVEL, "LOW");
        assertFalse(ContextConditions.platformDecision(old, ContextConditions.OUTCOME_STEP_UP));
    }

    @Test
    void riskLevelAtLeast() {
        MapNotes n = written(true);   // HIGH
        assertTrue(ContextConditions.riskLevelAtLeast(n, "HIGH"));
        assertTrue(ContextConditions.riskLevelAtLeast(n, "medium"));
        assertFalse(ContextConditions.riskLevelAtLeast(n, "CRITICAL"));
        assertFalse(ContextConditions.riskLevelAtLeast(n, "NONSENSE"), "an unknown level never matches");
        assertFalse(ContextConditions.riskLevelAtLeast(n, null));
    }

    @Test
    void ruleFiredIsAnExactName() {
        MapNotes n = written(true);
        assertTrue(ContextConditions.ruleFired(n, "new_country"));
        assertTrue(ContextConditions.ruleFired(n, "impossible_travel"));
        assertFalse(ContextConditions.ruleFired(n, "new"), "no prefix match");
        assertFalse(ContextConditions.ruleFired(n, "country"), "no contains");
        assertFalse(ContextConditions.ruleFired(n, "experimental"), "a shadow rule never fired for the flow");
        assertFalse(ContextConditions.ruleFired(n, ""));
    }

    @Test
    void attributeEqualsOnlyForWhatWasWritten() {
        MapNotes n = written(true);
        assertTrue(ContextConditions.attributeEquals(n, "network.is_tor", "true"));
        assertTrue(ContextConditions.attributeEquals(n, "network.is_tor", "TRUE"), "booleans compare without case");
        assertFalse(ContextConditions.attributeEquals(n, "network.is_tor", "false"));
        assertTrue(ContextConditions.attributeEquals(n, "network.country_mismatch", "FR"));
        assertFalse(ContextConditions.attributeEquals(n, "network.country_mismatch", "fr"), "text is exact");
        assertFalse(ContextConditions.attributeEquals(n, "geo.city", "Paris"), "outside the allowlist");
        assertFalse(ContextConditions.attributeEquals(n, "user.email", "alice@example.com"), "sensitive: never offered");
        assertFalse(ContextConditions.attributeEquals(n, "device.first_seen", "true"), "unavailable never matches");
    }

    // ── the setting ───────────────────────────────────────────────────────────

    @Test
    void onlyTheWordLocalSelectsTheLocalSource() {
        assertTrue(DecisionSource.isLocal("local"));
        assertTrue(DecisionSource.isLocal(" LOCAL "));
        assertFalse(DecisionSource.isLocal(null));
        assertFalse(DecisionSource.isLocal(""));
        assertFalse(DecisionSource.isLocal("server"));
        assertFalse(DecisionSource.isLocal("locall"), "a typo never changes who decides");
    }

    @Test
    void theExecutionConfigurationOfAFlowWinsOverTheEnvironment() {
        assertTrue(DecisionSource.isLocalFor(Map.of(DecisionSource.CONFIG_KEY, "local")));
        assertTrue(DecisionSource.isLocalFor(Map.of(DecisionSource.CONFIG_KEY, " LOCAL ")));
        assertFalse(DecisionSource.isLocalFor(Map.of(DecisionSource.CONFIG_KEY, "server")));
        // inherit, unknown or absent: the environment decides (not set in the test: server)
        assertFalse(DecisionSource.isLocalFor(Map.of(DecisionSource.CONFIG_KEY, "inherit")));
        assertFalse(DecisionSource.isLocalFor(Map.of(DecisionSource.CONFIG_KEY, "locall")), "a typo never changes who decides");
        assertFalse(DecisionSource.isLocalFor(null));
        assertEquals("/evaluate", DecisionSource.evaluatePath(false));
        assertTrue(DecisionSource.evaluatePath(true).startsWith("/evaluate?include=context&attributes=network.is_anonymous"));
    }

    @Test
    void theAllowlistDefaultsToNonSensitiveAttributes() {
        assertEquals(DecisionSource.DEFAULT_ATTRIBUTES, DecisionSource.parseAllowlist(null));
        assertEquals(DecisionSource.DEFAULT_ATTRIBUTES, DecisionSource.parseAllowlist(" , "));
        assertEquals(List.of("a.b", "c.d"), DecisionSource.parseAllowlist(" a.b, c.d ,a.b"));
        for (String name : DecisionSource.DEFAULT_ATTRIBUTES) {
            assertFalse(name.contains("ip_address") || name.contains("email") || name.contains("user_agent"), name);
        }
    }

    // ── what the last-step reporter derives ───────────────────────────────────

    @Test
    void theReporterDerivesWhatTheFlowApplied() {
        assertEquals("ALLOW", HumifortisDecisionReport.enforcedAction("REQUIRE_MFA", false), "the flow let the person through");
        assertEquals("REQUIRE_MFA", HumifortisDecisionReport.enforcedAction("REQUIRE_MFA", true));
        assertEquals("REQUIRE_WEBAUTHN", HumifortisDecisionReport.enforcedAction("REQUIRE_WEBAUTHN", true));
        assertEquals("REQUIRE_MFA", HumifortisDecisionReport.enforcedAction("ALLOW", true), "a flow stricter than the platform");
        assertEquals("ALLOW", HumifortisDecisionReport.enforcedAction("DENY", false), "a flow looser than the platform");
        // the report just before Deny access says what the flow is about to apply
        assertEquals("DENY", HumifortisDecisionReport.denyAction("DENY"));
        assertEquals("LOCK_ACCOUNT", HumifortisDecisionReport.denyAction("LOCK_ACCOUNT"));
        assertEquals("DENY", HumifortisDecisionReport.denyAction("REQUIRE_MFA"), "a deny step is a denial whatever was asked");
        assertEquals("deny", DecisionReport.outcomeOf(HumifortisDecisionReport.denyAction("DENY")));
        assertTrue(HumifortisDecisionReport.SECOND_FACTORS.contains("auth-otp-form"));
        assertTrue(HumifortisDecisionReport.SECOND_FACTORS.contains("humifortis-step-up-router"));
        assertFalse(HumifortisDecisionReport.SECOND_FACTORS.contains("auth-username-password-form"), "the password is the first factor");
    }
}

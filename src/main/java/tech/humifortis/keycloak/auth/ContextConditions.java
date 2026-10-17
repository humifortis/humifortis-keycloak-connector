package tech.humifortis.keycloak.auth;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * The four tests a Keycloak flow can make on the evaluation context, as pure functions of the session notes
 * (docs/risk-as-data.spec.md, D4). The set is closed: there is no {@code contains}, no prefix match and no AND/OR
 * builder, because that would be a second rule engine inside Keycloak. Anything richer is a Sigma rule in Humifortis
 * and the flow tests the one thing that matters: <em>rule Y fired</em>. Flows combine the conditions with Keycloak's
 * own flow structure.
 *
 * <p>An unknown never matches: a missing note, an unknown level, a rule or attribute that was not written. The
 * exception is the platform-decision condition, which in front of missing notes asks for a step-up (D11): friction,
 * never a silent allow.</p>
 */
final class ContextConditions {

    static final String OUTCOME_STEP_UP = "step_up";
    static final String OUTCOME_DENY = "deny";

    private static final List<String> LEVELS = List.of("MINIMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL");

    private ContextConditions() {}

    /** True when the notes of the evaluation are there and this login is under the local decision source. */
    static boolean hasContext(ContextNotes.Notes n) {
        return n.get(ContextNotes.VERSION) != null;
    }

    /** Whether the platform's verdict applies: false in {@code dry_run} and {@code shadow} (D10). */
    static boolean enforcing(ContextNotes.Notes n) {
        return "true".equals(n.get(ContextNotes.ENFORCING));
    }

    /**
     * <em>The platform's decision is X.</em> {@code outcome} is {@link #OUTCOME_STEP_UP} or {@link #OUTCOME_DENY}.
     * Under the local source it reads the platform action the connector wrote; in {@code dry_run} and {@code shadow}
     * it never matches. With no notes at all (the risk authenticator did not run) a step-up condition matches and a
     * deny condition does not.
     */
    static boolean platformDecision(ContextNotes.Notes n, String outcome) {
        boolean denyOutcome = OUTCOME_DENY.equals(outcome);
        String action = n.get(HumifortisRiskAuthenticator.NOTE_RISK_ACTION);
        if (action == null || action.isBlank()) {
            String level = n.get(HumifortisRiskAuthenticator.NOTE_RISK_LEVEL);
            if (level == null) return !denyOutcome;          // nothing ran: ask for a step-up, never a silent allow
            return !denyOutcome && isElevated(level);          // an older flow with only the level
        }
        if (hasContext(n) && !enforcing(n)) return false;
        if (denyOutcome) return "DENY".equals(action) || "LOCK_ACCOUNT".equals(action);
        if (StepUpActions.isStepUp(action)) return true;
        return switch (action) {
            case "ALLOW", "DENY", "LOCK_ACCOUNT" -> false;      // a deny is handled by a deny condition, not by a challenge
            default -> true;                                    // an unknown action asks for a challenge
        };
    }

    /** <em>Risk level at least X.</em> An unknown level, or none, never matches. */
    static boolean riskLevelAtLeast(ContextNotes.Notes n, String minimum) {
        if (!hasContext(n) || !enforcing(n)) return false;
        int have = LEVELS.indexOf(upper(n.get(ContextNotes.LEVEL)));
        int need = LEVELS.indexOf(upper(minimum));
        return have >= 0 && need >= 0 && have >= need;
    }

    /** <em>Rule Y fired.</em> An exact rule name; a shadow rule is never in the notes. */
    static boolean ruleFired(ContextNotes.Notes n, String rule) {
        if (!hasContext(n) || !enforcing(n) || rule == null || rule.isBlank()) return false;
        String rules = n.get(ContextNotes.RULES);
        return rules != null && Arrays.asList(rules.split(",")).contains(rule.trim());
    }

    /**
     * <em>Attribute Z equals V.</em> Only an allowlisted attribute is ever written, so any other name does not match.
     * The comparison is exact for text and case-insensitive for booleans.
     */
    static boolean attributeEquals(ContextNotes.Notes n, String name, String value) {
        if (!hasContext(n) || !enforcing(n) || name == null || name.isBlank() || value == null) return false;
        String have = n.get(ContextNotes.ATTR_PREFIX + name.trim());
        if (have == null) return false;
        String want = value.trim();
        return have.equals(want) || (isBool(have) && isBool(want) && have.equalsIgnoreCase(want));
    }

    private static boolean isElevated(String level) {
        String l = upper(level);
        return "HIGH".equals(l) || "MEDIUM".equals(l) || "CRITICAL".equals(l);
    }

    private static boolean isBool(String s) {
        return "true".equalsIgnoreCase(s) || "false".equalsIgnoreCase(s);
    }

    private static String upper(String s) {
        return s == null ? "" : s.trim().toUpperCase(Locale.ROOT);
    }
}

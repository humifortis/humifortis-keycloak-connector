package tech.humifortis.keycloak.auth;

import com.google.gson.Gson;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * The evaluation context as authentication-session notes (docs/risk-as-data.spec.md, D13 and D18).
 *
 * <p>The notes are small and allowlisted: the level and score, the enforcing flag, at most 20 fired rule names, at most
 * 5 reasons of at most 200 characters, and only the attributes of the allowlist. Only the Humifortis risk authenticator
 * writes them; it clears all of them at the start of every evaluation and writes them whole, so a half-written set
 * from an earlier pass can never be read. Keycloak's authentication-session notes are held by the server: a login
 * request cannot set them.</p>
 */
final class ContextNotes {

    static final String VERSION      = "HUMIFORTIS_CTX_VERSION";
    static final String ENFORCING    = "HUMIFORTIS_CTX_ENFORCING";
    static final String LEVEL        = "HUMIFORTIS_CTX_LEVEL";
    static final String SCORE        = "HUMIFORTIS_CTX_SCORE";
    static final String RULES        = "HUMIFORTIS_CTX_RULES";
    static final String REASONS      = "HUMIFORTIS_REASONS";
    static final String RECORD       = "HUMIFORTIS_CTX_RECORD";
    static final String ATTR_PREFIX  = "HUMIFORTIS_CTX_ATTR_";
    static final String ATTR_KEYS    = "HUMIFORTIS_CTX_ATTR_KEYS";
    static final String WOULD_ACTION = "HUMIFORTIS_WOULD_ACTION";
    /** The note that says the report of this login is still to be made by the last-step reporter, and its value while it is. */
    static final String REPORT       = "HUMIFORTIS_CTX_REPORT";
    static final String REPORT_PENDING = "pending";
    /** What the reporter needs to report the decision of this login. */
    static final String REPORT_MODE     = "HUMIFORTIS_CTX_REPORT_MODE";
    static final String REPORT_RULE     = "HUMIFORTIS_CTX_REPORT_RULE";
    static final String REPORT_SOURCE   = "HUMIFORTIS_CTX_REPORT_POLICY_SOURCE";

    static final int MAX_RULES = 20;
    static final int MAX_REASONS = 5;
    static final int MAX_REASON_CHARS = 200;
    static final int MAX_VALUE_CHARS = 128;

    private static final Gson GSON = new Gson();
    private static final List<String> FIXED = List.of(VERSION, ENFORCING, LEVEL, SCORE, RULES, REASONS, RECORD, ATTR_KEYS,
            WOULD_ACTION, REPORT, REPORT_MODE, REPORT_RULE, REPORT_SOURCE);

    /** The notes of one authentication session: the Keycloak session in production, a map in tests. */
    interface Notes {
        String get(String key);
        void set(String key, String value);
        void remove(String key);
    }

    private ContextNotes() {}

    /** Removes every note of the context, the attribute notes included. */
    static void clear(Notes notes) {
        String keys = notes.get(ATTR_KEYS);
        if (keys != null && !keys.isBlank()) {
            for (String k : keys.split(",")) notes.remove(k);
        }
        for (String k : FIXED) notes.remove(k);
    }

    /** Clears, then writes the context whole. {@code enforcing} is false in {@code dry_run} and {@code shadow}. */
    static void write(Notes notes, EvaluationContext c, boolean enforcing, List<String> allowlist) {
        clear(notes);
        notes.set(VERSION, c.contextVersion);
        notes.set(ENFORCING, String.valueOf(enforcing));
        notes.set(LEVEL, c.risk.level.toUpperCase(Locale.ROOT));
        notes.set(SCORE, String.valueOf(c.risk.score));
        if (c.recordId != null && !c.recordId.isBlank()) notes.set(RECORD, c.recordId);
        if (c.decision.wouldAction != null && !c.decision.wouldAction.isBlank()) notes.set(WOULD_ACTION, c.decision.wouldAction);

        List<String> rules = new ArrayList<>();
        if (c.signals != null) {
            for (EvaluationContext.Signal s : c.signals) {
                if (s == null || s.shadow || s.rule == null || s.rule.isBlank() || rules.contains(s.rule)) continue;
                rules.add(s.rule);
                if (rules.size() >= MAX_RULES) break;
            }
        }
        notes.set(RULES, String.join(",", rules));

        List<String> reasons = new ArrayList<>();
        if (c.decision.reasons != null) {
            for (EvaluationContext.Reason r : c.decision.reasons) {
                if (r == null) continue;
                reasons.add(cut(reasonText(r), MAX_REASON_CHARS));
                if (reasons.size() >= MAX_REASONS) break;
            }
        }
        notes.set(REASONS, GSON.toJson(reasons));

        List<String> written = new ArrayList<>();
        if (c.attributes != null) {
            for (EvaluationContext.Attr a : c.attributes) {
                // an attribute outside the allowlist, a sensitive one, or one the event did not resolve is never written:
                // a condition on it does not match (unknown never reads as a value)
                if (a == null || a.name == null || a.unavailable || a.sensitive || a.value == null) continue;
                if (allowlist == null || !allowlist.contains(a.name)) continue;
                String key = ATTR_PREFIX + a.name;
                notes.set(key, cut(String.valueOf(a.value), MAX_VALUE_CHARS));
                written.add(key);
            }
        }
        if (!written.isEmpty()) notes.set(ATTR_KEYS, String.join(",", written));
    }

    private static String reasonText(EvaluationContext.Reason r) {
        String title = r.title != null && !r.title.isBlank() ? r.title : r.rule;
        if (title == null) title = "";
        return r.rationale != null && !r.rationale.isBlank() ? title + ": " + r.rationale : title;
    }

    private static String cut(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max);
    }
}

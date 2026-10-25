package tech.humifortis.keycloak.auth;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * What a login gets when Humifortis cannot answer (timeout, outage, misconfiguration).
 *
 * <p>Resolution, first match wins:</p>
 * <ol>
 *   <li>{@code HUMIFORTIS_FALLBACK} — the operator's override;</li>
 *   <li>the tenant's policy, as last returned by {@code /evaluate} (kept in memory: a stale
 *       policy is better than none);</li>
 *   <li>built-in: step-up for privileged users, allow for everyone else.</li>
 * </ol>
 * A step-up the user cannot perform (no second factor and no email OTP) becomes the policy's
 * {@code no_mfa} outcome — deny for privileged users by default, allow otherwise.
 */
public final class FallbackPolicy {

    public enum Outcome {
        ALLOW, STEP_UP, DENY;

        static Outcome parse(String raw) {
            if (raw == null || raw.isBlank()) return null;
            return switch (raw.trim().toLowerCase(Locale.ROOT).replace('-', '_')) {
                case "allow" -> ALLOW;
                case "step_up", "stepup", "mfa" -> STEP_UP;
                case "deny" -> DENY;
                default -> null;
            };
        }

        public String wire() { return name().toLowerCase(Locale.ROOT); }
    }

    /** The tenant policy as sent in the {@code fallback_policy} field of an /evaluate response. */
    public record TenantPolicy(Outcome defaultOutcome, Outcome privileged, Outcome noMfa, Outcome privilegedNoMfa) {
        static TenantPolicy from(Map<String, String> wire) {
            if (wire == null || wire.isEmpty()) return null;
            Outcome def = Outcome.parse(wire.get("default"));
            Outcome priv = Outcome.parse(wire.get("privileged"));
            if (def == null && priv == null) return null;
            return new TenantPolicy(
                    def != null ? def : Outcome.ALLOW,
                    priv != null ? priv : Outcome.STEP_UP,
                    orElse(Outcome.parse(wire.get("no_mfa")), Outcome.ALLOW),
                    orElse(Outcome.parse(wire.get("privileged_no_mfa")), Outcome.DENY));
        }
    }

    /** The outcome and where it came from (env | tenant_cache | default). */
    public record Decision(Outcome outcome, String source, boolean stepUpUnavailable) {}

    private static final Map<String, TenantPolicy> TENANT_CACHE = new ConcurrentHashMap<>();
    private static final Map<String, String> MODE_CACHE = new ConcurrentHashMap<>();

    private FallbackPolicy() {}

    /** Remembers the tenant's policy from a successful /evaluate response. */
    public static void remember(String tenantId, Map<String, String> wire, String mode) {
        if (tenantId == null) return;
        TenantPolicy p = TenantPolicy.from(wire);
        if (p != null) TENANT_CACHE.put(tenantId, p);
        if (mode != null && !mode.isBlank()) MODE_CACHE.put(tenantId, mode.trim().toLowerCase(Locale.ROOT));
    }

    /** The tenant's enforcement mode (enforce | dry_run | shadow) as last returned, or null. */
    public static String cachedMode(String tenantId) {
        return tenantId == null ? null : MODE_CACHE.get(tenantId);
    }

    static TenantPolicy cached(String tenantId) {
        return tenantId == null ? null : TENANT_CACHE.get(tenantId);
    }

    static void clearCache() { TENANT_CACHE.clear(); MODE_CACHE.clear(); }

    public static Decision resolve(String envOverride, String tenantId, boolean privileged, boolean canStepUp) {
        return resolve(Outcome.parse(envOverride), cached(tenantId), privileged, canStepUp);
    }

    static Decision resolve(Outcome env, TenantPolicy tenant, boolean privileged, boolean canStepUp) {
        Outcome outcome;
        String source;
        if (env != null) {
            outcome = env;
            source = "env";
        } else if (tenant != null) {
            outcome = privileged ? tenant.privileged() : tenant.defaultOutcome();
            source = "tenant_cache";
        } else {
            outcome = privileged ? Outcome.STEP_UP : Outcome.ALLOW;
            source = "default";
        }
        if (outcome == Outcome.STEP_UP && !canStepUp) {
            Outcome noMfa = tenant != null
                    ? (privileged ? tenant.privilegedNoMfa() : tenant.noMfa())
                    : (privileged ? Outcome.DENY : Outcome.ALLOW);
            return new Decision(noMfa == Outcome.STEP_UP ? Outcome.DENY : noMfa, source, true);
        }
        return new Decision(outcome, source, false);
    }

    private static Outcome orElse(Outcome o, Outcome fallback) {
        return o != null ? o : fallback;
    }
}

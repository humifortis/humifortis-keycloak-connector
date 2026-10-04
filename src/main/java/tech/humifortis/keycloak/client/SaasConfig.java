package tech.humifortis.keycloak.client;

import java.util.Locale;
import java.util.Map;

import org.jboss.logging.Logger;

/**
 * The connector's configuration — one place, read from the environment (zero-config defaults,
 * one-line opt-ins). Every component reads its settings from here.
 *
 * <table>
 *   <tr><th>Variable</th><th>Default</th><th>Meaning</th></tr>
 *   <tr><td>HUMIFORTIS_API_URL</td><td>https://api.humifortis.educosmic.tech</td><td>API endpoint</td></tr>
 *   <tr><td>HUMIFORTIS_API_KEY</td><td>(required)</td><td>API key; without it every login falls back</td></tr>
 *   <tr><td>HUMIFORTIS_TENANT_ID</td><td>realm name</td><td>tenant</td></tr>
 *   <tr><td>HUMIFORTIS_TIMEOUT_MS</td><td>800</td><td>timeout of ONE attempt</td></tr>
 *   <tr><td>HUMIFORTIS_EVALUATE_BUDGET_MS</td><td>1500</td><td>total time a login may wait for a decision, retries included</td></tr>
 *   <tr><td>HUMIFORTIS_FALLBACK</td><td>(tenant policy)</td><td>allow | step_up | deny when Humifortis cannot answer — overrides the tenant policy</td></tr>
 *   <tr><td>HUMIFORTIS_EVENT_QUEUE_SIZE</td><td>10000</td><td>events buffered while the API is unreachable</td></tr>
 * </table>
 *
 * <p>{@code HUMIFORTIS_FALLBACK_ALLOW} is deprecated: {@code false} means {@code HUMIFORTIS_FALLBACK=deny}.</p>
 */
public class SaasConfig {
    private static final Logger logger = Logger.getLogger(SaasConfig.class);

    public static final String DEFAULT_API_URL = "https://api.humifortis.educosmic.tech";
    static final int DEFAULT_ATTEMPT_TIMEOUT_MS = 800;
    static final int DEFAULT_EVALUATE_BUDGET_MS = 1500;
    static final int DEFAULT_EVENT_QUEUE_SIZE = 10_000;

    private static volatile SaasConfig fromEnv;

    private final String apiUrl;
    private final String apiKey;
    private final String tenantId;
    private final int timeoutMs;
    private final int evaluateBudgetMs;
    private final String fallbackOverride;
    private final int eventQueueSize;
    private final boolean insecureSsl;
    private final String insecureSslCertSha256;
    private final boolean allowInsecureHttp;

    public SaasConfig() {
        this(System.getenv());
    }

    public SaasConfig(Map<String, String> env) {
        this.apiUrl = trimTrailingSlash(getEnvOrDefault(env, "HUMIFORTIS_API_URL", DEFAULT_API_URL));
        this.apiKey = emptyToNull(env.get("HUMIFORTIS_API_KEY"));
        this.tenantId = emptyToNull(env.get("HUMIFORTIS_TENANT_ID"));
        this.timeoutMs = positiveInt(env, "HUMIFORTIS_TIMEOUT_MS", DEFAULT_ATTEMPT_TIMEOUT_MS);
        this.evaluateBudgetMs = positiveInt(env, "HUMIFORTIS_EVALUATE_BUDGET_MS", DEFAULT_EVALUATE_BUDGET_MS);
        this.eventQueueSize = positiveInt(env, "HUMIFORTIS_EVENT_QUEUE_SIZE", DEFAULT_EVENT_QUEUE_SIZE);
        this.fallbackOverride = resolveFallbackOverride(env);
        this.insecureSsl = HttpClientFactory.isInsecureSslEnabled(env.get("INSECURE_SSL"));
        this.insecureSslCertSha256 = emptyToNull(env.get("HUMIFORTIS_INSECURE_SSL_CERT_SHA256"));
        this.allowInsecureHttp = "true".equalsIgnoreCase(env.get("HUMIFORTIS_ALLOW_INSECURE_HTTP"));
    }

    /** The configuration of this process (the environment does not change while it runs). */
    public static SaasConfig fromEnv() {
        SaasConfig c = fromEnv;
        if (c == null) {
            synchronized (SaasConfig.class) {
                if (fromEnv == null) fromEnv = new SaasConfig();
                c = fromEnv;
            }
        }
        return c;
    }

    private static String resolveFallbackOverride(Map<String, String> env) {
        String explicit = emptyToNull(env.get("HUMIFORTIS_FALLBACK"));
        if (explicit != null) {
            String v = explicit.trim().toLowerCase(Locale.ROOT).replace('-', '_');
            if (v.equals("allow") || v.equals("step_up") || v.equals("deny")) return v;
            logger.warnf("[Humifortis] HUMIFORTIS_FALLBACK=%s is not allow|step_up|deny — ignored", explicit);
            return null;
        }
        String legacy = emptyToNull(env.get("HUMIFORTIS_FALLBACK_ALLOW"));
        if (legacy != null) {
            logger.warn("[Humifortis] HUMIFORTIS_FALLBACK_ALLOW is deprecated — use HUMIFORTIS_FALLBACK=allow|step_up|deny");
            // true was the old default (fail open): the tenant policy now decides
            return "false".equalsIgnoreCase(legacy.trim()) ? "deny" : null;
        }
        return null;
    }

    private static int positiveInt(Map<String, String> env, String key, int defaultValue) {
        String raw = emptyToNull(env.get(key));
        if (raw == null) return defaultValue;
        try {
            int v = Integer.parseInt(raw.trim());
            if (v > 0) return v;
        } catch (NumberFormatException ignored) {
            // fall through
        }
        logger.warnf("[Humifortis] %s=%s is not a positive integer — using %d", key, raw, defaultValue);
        return defaultValue;
    }

    private static String getEnvOrDefault(Map<String, String> env, String key, String defaultValue) {
        String value = env.get(key);
        return value != null && !value.isBlank() ? value.trim() : defaultValue;
    }

    private static String trimTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    private static String emptyToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    public String getApiUrl() { return apiUrl; }

    /** Null when not configured — every caller treats that as "cannot evaluate". */
    public String getApiKey() { return apiKey; }

    public boolean hasApiKey() { return apiKey != null; }

    /** The tenant: HUMIFORTIS_TENANT_ID, else the realm name. */
    public String tenantIdOr(String realmName) { return tenantId != null ? tenantId : realmName; }

    /** Timeout of one HTTP attempt. */
    public int getTimeoutMs() { return timeoutMs; }

    /** Total time a login waits for a decision, retries included. */
    public int getEvaluateBudgetMs() { return evaluateBudgetMs; }

    /** allow | step_up | deny forced by the operator, or null (the tenant policy decides). */
    public String getFallbackOverride() { return fallbackOverride; }

    public int getEventQueueSize() { return eventQueueSize; }

    public boolean isInsecureSsl() { return insecureSsl; }

    public String getInsecureSslCertSha256() { return insecureSslCertSha256; }

    /** Plain http:// is refused unless explicitly allowed (internal development hops only). */
    public boolean isEndpointAllowed() {
        String url = apiUrl.toLowerCase(Locale.ROOT);
        return url.startsWith("https://") || (allowInsecureHttp && url.startsWith("http://"));
    }

    public boolean isSecureEndpoint() {
        return apiUrl.toLowerCase(Locale.ROOT).startsWith("https://");
    }
}

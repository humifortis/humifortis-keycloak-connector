package tech.humifortis.keycloak.auth;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;

import tech.humifortis.keycloak.model.Risk;

/**
 * Calls POST /api/v1/evaluate on Humifortis Core with the full authentication context.
 *
 * <p>Design: connector sends RAW context (IP, UA, roles, session, MFA status).
 * The server does ALL enrichment (GeoIP, UA parsing, device fingerprint, risk scoring,
 * playbook evaluation). This keeps the connector thin and the logic centralized.</p>
 *
 * <p>The server's playbook decision is stored in {@link #LAST_DECISION} (ThreadLocal)
 * so {@link HumifortisRiskAuthenticator} can enforce it without re-calling the API.</p>
 *
 * <h3>Circuit breaker</h3>
 * Opens after {@code CIRCUIT_OPEN_THRESHOLD} consecutive failures; stays open
 * {@code CIRCUIT_OPEN_DURATION_MS} ms before allowing a probe request through.
 *
 * <h3>Configuration (env vars)</h3>
 * <ul>
 *   <li>{@code HUMIFORTIS_API_URL}    — default {@code https://api.humifortis.com}</li>
 *   <li>{@code HUMIFORTIS_API_KEY}    — required</li>
 *   <li>{@code HUMIFORTIS_TIMEOUT_MS} — default 2000</li>
 *   <li>{@code HUMIFORTIS_TENANT_ID}  — default realm name</li>
 *   <li>{@code INSECURE_SSL=true}     — skip TLS verification (dev/test only)</li>
 * </ul>
 */
public class HumifortisRiskEvaluator {

    private static final Logger logger = Logger.getLogger(HumifortisRiskEvaluator.class);

    static final String ENV_API_URL    = "HUMIFORTIS_API_URL";
    static final String ENV_API_KEY    = "HUMIFORTIS_API_KEY";
    static final String ENV_TIMEOUT_MS = "HUMIFORTIS_TIMEOUT_MS";
    static final String ENV_TENANT_ID  = "HUMIFORTIS_TENANT_ID";

    static final String DEFAULT_API_URL   = "https://api.humifortis.com";
    static final int    DEFAULT_TIMEOUT_MS = 2000;
    static final String FAIL_OPEN_REASON   = "Humifortis unavailable - fail open";

    // ── Circuit breaker (shared across all evaluator instances) ─────────────
    private static volatile int  consecutiveFailures = 0;
    private static volatile long circuitOpenUntil    = 0;
    private static final int  CIRCUIT_OPEN_THRESHOLD   = 3;
    private static final long CIRCUIT_OPEN_DURATION_MS = 10_000;

    // ── Shared insecure HttpClient (created once via double-checked locking) ─
    private static volatile HttpClient INSECURE_CLIENT;
    private static final Object INSECURE_LOCK = new Object();

    /** Thread-local that carries the latest server decision to the authenticator. */
    public static final ThreadLocal<EvaluateResponse> LAST_DECISION = new ThreadLocal<>();

    private final HttpClient      httpClient;
    private final KeycloakSession session;
    private final Gson            gson;

    public HumifortisRiskEvaluator(KeycloakSession session) {
        this.session = session;
        this.gson    = new GsonBuilder().create();

        if ("true".equalsIgnoreCase(System.getenv("INSECURE_SSL"))) {
            if (INSECURE_CLIENT == null) {
                synchronized (INSECURE_LOCK) {
                    if (INSECURE_CLIENT == null) INSECURE_CLIENT = buildInsecureClient();
                }
            }
            this.httpClient = INSECURE_CLIENT;
        } else {
            this.httpClient = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofMillis(DEFAULT_TIMEOUT_MS))
                    .build();
        }
    }

    private static HttpClient buildInsecureClient() {
        try {
            TrustManager[] trustAll = {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    public void checkClientTrusted(X509Certificate[] c, String a) {}
                    public void checkServerTrusted(X509Certificate[] c, String a) {}
                }
            };
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, trustAll, new SecureRandom());
            return HttpClient.newBuilder()
                    .sslContext(ctx)
                    .connectTimeout(Duration.ofMillis(DEFAULT_TIMEOUT_MS))
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create insecure SSL HttpClient", e);
        }
    }

    // =========================================================================
    // PUBLIC EVALUATE — entry point called by HumifortisRiskAuthenticator
    // =========================================================================

    public Risk evaluate(RealmModel realm, UserModel knownUser) {
        if (knownUser == null) {
            logger.warnf("[HumifortisRiskEvaluator] User is null — fail open");
            return failOpen();
        }
        if (isCircuitOpen()) {
            logger.debugf("[HumifortisRiskEvaluator] Circuit OPEN — fail open");
            return failOpen();
        }

        String apiUrl   = envOrDefault(ENV_API_URL, DEFAULT_API_URL);
        String apiKey   = System.getenv(ENV_API_KEY);
        int    timeout  = parseTimeout(System.getenv(ENV_TIMEOUT_MS));
        String tenantId = envOrDefault(ENV_TENANT_ID, realm.getName());
        String entityId = buildEntityId(realm, knownUser);

        if (apiKey == null || apiKey.isBlank()) {
            logger.warnf("[HumifortisRiskEvaluator] API key missing (entity=%s) — fail open", entityId);
            return failOpen();
        }

        boolean insecureSsl = "true".equalsIgnoreCase(System.getenv("INSECURE_SSL"));
        if (!apiUrl.toLowerCase(Locale.ROOT).startsWith("https://") && !insecureSsl) {
            logger.warnf("[HumifortisRiskEvaluator] Non-HTTPS URL (entity=%s) — fail open", entityId);
            return failOpen();
        }

        try {
            // Build payload
            EventPayload event = new EventPayload();
            event.entity_id   = entityId;
            event.entity_type = "user";
            event.event_type  = "auth_login_success";
            event.timestamp   = Instant.now().toString();
            event.metadata    = buildMetadata(realm, knownUser);

            EvaluateRequestPayload payload = new EvaluateRequestPayload();
            payload.event             = event;
            payload.available_methods = detectAvailableMethods(knownUser);

            String url = apiUrl + "/evaluate";
            logger.debugf("[HumifortisRiskEvaluator] POST %s entity=%s", url, entityId);

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Accept",       "application/json")
                    .header("Content-Type", "application/json")
                    .header("X-API-Key",    apiKey)
                    .header("X-Tenant-ID",  tenantId)
                    .timeout(Duration.ofMillis(timeout))
                    .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(payload)))
                    .build();

            HttpResponse<String> response =
                    httpClient.send(req, HttpResponse.BodyHandlers.ofString());

            int status = response.statusCode();
            logger.debugf("[HumifortisRiskEvaluator] HTTP %d", status);

            if (status < 200 || status >= 300) {
                logger.warnf("[HumifortisRiskEvaluator] HTTP error %d (entity=%s) — fail open",
                        status, entityId);
                recordFailure();
                return failOpen();
            }

            EvaluateResponse decision = gson.fromJson(response.body(), EvaluateResponse.class);
            LAST_DECISION.set(decision);
            recordSuccess();

            String riskLevel = decision.risk_level != null ? decision.risk_level : "MINIMAL";
            String reason    = buildReason(decision);

            logger.debugf("[HumifortisRiskEvaluator] level=%s action=%s rule=%s score=%.1f",
                    riskLevel, decision.action, decision.playbook_rule, decision.risk_score);

            return mapRiskLevel(riskLevel, reason);

        } catch (Exception e) {
            logger.warnf("[HumifortisRiskEvaluator] Exception (entity=%s): %s",
                    entityId, e.getMessage());
            recordFailure();
            return failOpen();
        }
    }

    // =========================================================================
    // CONTEXT COLLECTION — raw data sent to server for enrichment
    // =========================================================================

    private Map<String, Object> buildMetadata(RealmModel realm, UserModel user) {
        Map<String, Object> meta = new HashMap<>();

        // IP address — forwarded to server for GeoIP lookup
        safeCollect(meta, "ip", () -> {
            var conn = session.getContext().getConnection();
            return conn != null ? conn.getRemoteAddr() : null;
        });

        // User-Agent (raw string) — server does browser/OS parsing
        safeCollect(meta, "user_agent", () -> {
            var headers = session.getContext().getRequestHeaders();
            if (headers == null) return null;
            String ua = headers.getHeaderString("User-Agent");
            return (ua != null && !ua.isBlank()) ? ua : null;
        });

        // Auth session data
        safeCollect(meta, "session_id", () -> {
            var as = session.getContext().getAuthenticationSession();
            return (as != null && as.getParentSession() != null)
                    ? as.getParentSession().getId() : null;
        });

        safeCollect(meta, "identity_provider", () -> {
            var as = session.getContext().getAuthenticationSession();
            String idp = as != null ? as.getAuthNote("identity_provider") : null;
            return (idp != null && !idp.isBlank()) ? idp : "local";
        });

        // User attributes
        if (user.getUsername() != null) meta.put("username", user.getUsername());
        if (user.getEmail()    != null) meta.put("email",    user.getEmail());

        safeCollect(meta, "account_age_days", () -> {
            if (user.getCreatedTimestamp() == null) return null;
            return String.valueOf(ChronoUnit.DAYS.between(
                    Instant.ofEpochMilli(user.getCreatedTimestamp()), Instant.now()));
        });

        safeCollect(meta, "user_roles", () -> {
            List<String> roles = user.getRoleMappingsStream()
                    .map(r -> r.getName()).toList();
            if (roles.isEmpty()) return null;
            meta.put("is_privileged",
                    String.valueOf(roles.stream().anyMatch(this::isPrivilegedRole)));
            return String.join(",", roles);
        });

        safeCollect(meta, "mfa_enrolled", () -> {
            boolean hasMfa = user.credentialManager().getStoredCredentialsStream()
                    .anyMatch(c -> "otp".equals(c.getType())
                            || "webauthn".equals(c.getType())
                            || "webauthn-passwordless".equals(c.getType()));
            return String.valueOf(hasMfa);
        });

        safeCollect(meta, "active_session_count", () ->
                String.valueOf(session.sessions().getUserSessionsStream(realm, user).count()));

        meta.put("realm", realm.getName());
        return meta;
    }

    /** Helper: runs collector, silently skips on exception or null result. */
    private void safeCollect(Map<String, Object> meta, String key,
                             java.util.concurrent.Callable<Object> collector) {
        try {
            Object value = collector.call();
            if (value != null) meta.put(key, value);
        } catch (Exception e) {
            logger.debugf("[HumifortisRiskEvaluator] %s collection failed: %s", key, e.getMessage());
        }
    }

    private List<String> detectAvailableMethods(UserModel user) {
        List<String> methods = new ArrayList<>();
        try {
            user.credentialManager().getStoredCredentialsStream().forEach(cred -> {
                switch (cred.getType()) {
                    case "otp"                   -> methods.add("TOTP");
                    case "webauthn"              -> methods.add("WEBAUTHN");
                    case "webauthn-passwordless" -> methods.add("WEBAUTHN_PASSWORDLESS");
                }
            });
        } catch (Exception e) {
            logger.debugf("[HumifortisRiskEvaluator] MFA methods detection failed: %s", e.getMessage());
        }
        if (methods.isEmpty()) methods.add("EMAIL_OTP");
        return methods;
    }

    private boolean isPrivilegedRole(String name) {
        return name != null && Set.of(
                "admin", "realm-admin", "manage-users", "manage-realm",
                "manage-clients", "manage-identity-providers", "impersonation",
                "create-realm", "manage-authorization"
        ).contains(name);
    }

    // =========================================================================
    // CIRCUIT BREAKER
    // =========================================================================

    private static boolean isCircuitOpen() {
        if (consecutiveFailures < CIRCUIT_OPEN_THRESHOLD) return false;
        return System.currentTimeMillis() <= circuitOpenUntil;
    }

    private static void recordSuccess() { consecutiveFailures = 0; }

    private static void recordFailure() {
        consecutiveFailures++;
        if (consecutiveFailures >= CIRCUIT_OPEN_THRESHOLD) {
            circuitOpenUntil = System.currentTimeMillis() + CIRCUIT_OPEN_DURATION_MS;
            logger.warnf("[HumifortisRiskEvaluator] Circuit OPENED — %d failures, retry in %dms",
                    consecutiveFailures, CIRCUIT_OPEN_DURATION_MS);
        }
    }

    // =========================================================================
    // RISK MAPPING
    // =========================================================================

    public static Risk mapRiskLevel(String riskLevel, String reason) {
        return switch (riskLevel.toUpperCase(Locale.ROOT)) {
            case "MINIMAL"  -> Risk.of(Risk.Score.NONE,       reason);
            case "LOW"      -> Risk.of(Risk.Score.VERY_SMALL, reason);
            case "MEDIUM"   -> Risk.of(Risk.Score.MEDIUM,     reason);
            case "HIGH"     -> Risk.of(Risk.Score.HIGH,       reason);
            case "CRITICAL" -> Risk.of(Risk.Score.EXTREME,    reason);
            default         -> Risk.of(Risk.Score.NONE,       reason);
        };
    }

    private static Risk failOpen() {
        return Risk.of(Risk.Score.NONE, FAIL_OPEN_REASON);
    }

    private static String buildReason(EvaluateResponse d) {
        StringBuilder sb = new StringBuilder();
        if (d.playbook_rule != null && !d.playbook_rule.isBlank())
            sb.append("rule:").append(d.playbook_rule);
        if (d.derived_signals != null && !d.derived_signals.isEmpty())
            sb.append(" signals:").append(String.join(",", d.derived_signals));
        return sb.isEmpty() ? "Humifortis decision" : sb.toString();
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    private static String buildEntityId(RealmModel realm, UserModel user) {
        String userId  = user.getId() != null  ? user.getId()  : user.getUsername();
        String realmId = realm.getId() != null ? realm.getId() : realm.getName();
        return String.format("user:keycloak:%s:%s", realmId, userId);
    }

    public static String envOrDefault(String key, String defaultValue) {
        String val = System.getenv(key);
        return (val == null || val.isBlank()) ? defaultValue : val;
    }

    private static int parseTimeout(String raw) {
        if (raw == null || raw.isBlank()) return DEFAULT_TIMEOUT_MS;
        try { return Integer.parseInt(raw); } catch (NumberFormatException e) { return DEFAULT_TIMEOUT_MS; }
    }

    // =========================================================================
    // DTOs — request / response shapes for /api/v1/evaluate
    // =========================================================================

    private static class EvaluateRequestPayload {
        public EventPayload event;
        public List<String> available_methods;
    }

    private static class EventPayload {
        public String              entity_id;
        public String              entity_type;
        public String              event_type;
        public String              timestamp;
        public Map<String, Object> metadata;
    }

    /**
     * Server /evaluate response — public so HumifortisRiskAuthenticator can reference it
     * without re-deserializing. Geo fields come from the server (server does GeoIP).
     */
    public static class EvaluateResponse {
        public String       entity_id;
        public double       risk_score;
        public String       risk_level;
        /** Primary enforcement action: ALLOW | REQUIRE_MFA | REQUIRE_WEBAUTHN | DENY | LOCK_ACCOUNT */
        public String       action;
        /** Full list of actions (primary + side-effects: REVOKE_OTHER_SESSIONS, NOTIFY_USER…) */
        public List<String> actions;
        @SerializedName("playbook_rule")        public String       playbook_rule;
        @SerializedName("enforced_action")      public String       enforced_action;
        @SerializedName("fallback_reason")      public String       fallback_reason;
        @SerializedName("derived_signals")      public List<String> derived_signals;
        @SerializedName("contributing_factors") public List<String> contributing_factors;
        @SerializedName("device_is_new")        public boolean      device_is_new;
        @SerializedName("device_age_hours")     public int          device_age_hours;
        @SerializedName("device_is_trusted")    public boolean      device_is_trusted;
        /** GeoIP resolved by the server — used for email notifications */
        @SerializedName("geo_country")          public String       geo_country;
        @SerializedName("geo_city")             public String       geo_city;
        /** Enforcement mode: enforce | dry_run | shadow */
        @SerializedName("mode")                 public String       mode;
    }
}


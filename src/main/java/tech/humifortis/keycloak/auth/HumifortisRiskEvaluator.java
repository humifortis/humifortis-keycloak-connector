package tech.humifortis.keycloak.auth;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;

import tech.humifortis.keycloak.client.HttpClientFactory;
import tech.humifortis.keycloak.model.Risk;
import tech.humifortis.keycloak.user.UserContextExtractor;
import tech.humifortis.keycloak.user.UserContextSnapshot;

/**
 * Calls POST /api/v1/evaluate on Humifortis Core with the full authentication context.
 *
 * <p>Design: connector sends RAW context (IP, UA, roles, session, MFA status).
 * The server does ALL enrichment (GeoIP, UA parsing, device fingerprint, risk scoring,
 * playbook evaluation). This keeps the connector thin and the logic centralized.</p>
 *
 * <p>The server's playbook decision is returned explicitly with the mapped risk result
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

    private final HttpClient          httpClient;
    private final KeycloakSession     session;
    private final Gson                gson;
    private final UserContextExtractor userContextExtractor;

    public HumifortisRiskEvaluator(KeycloakSession session) {
        this.session = session;
        this.gson    = new GsonBuilder().create();
        this.userContextExtractor = new UserContextExtractor();
        this.httpClient = HttpClientFactory.create(
                DEFAULT_TIMEOUT_MS,
                HttpClientFactory.isInsecureSslEnabled(System.getenv("INSECURE_SSL")),
                envOrDefault("HUMIFORTIS_INSECURE_SSL_CERT_SHA256", null)
        );
    }

    // =========================================================================
    // PUBLIC EVALUATE — entry point called by HumifortisRiskAuthenticator
    // =========================================================================

    public Risk evaluate(RealmModel realm, UserModel knownUser) {
        return evaluate(realm, knownUser, null);
    }

    /**
     * Evaluates the risk for a user in the given realm, passing the Keycloak auth session ID
     * as flow_id so the credential-verified event is grouped with the enforcement events.
     *
     * @param flowId  Keycloak root auth session ID (code_id) — may be null for non-browser flows.
     */
    public Risk evaluate(RealmModel realm, UserModel knownUser, String flowId) {
        return evaluateDetailed(realm, knownUser, flowId).risk();
    }

    EvaluationResult evaluateDetailed(RealmModel realm, UserModel knownUser, String flowId) {
        if (knownUser == null) {
            logger.warnf("[HumifortisRiskEvaluator] User is null — fail open");
            return new EvaluationResult(failOpen(), null);
        }
        if (isCircuitOpen()) {
            logger.debugf("[HumifortisRiskEvaluator] Circuit OPEN — fail open");
            return new EvaluationResult(failOpen(), null);
        }

        String apiUrl   = envOrDefault(ENV_API_URL, DEFAULT_API_URL);
        String apiKey   = System.getenv(ENV_API_KEY);
        int    timeout  = parseTimeout(System.getenv(ENV_TIMEOUT_MS));
        String tenantId = envOrDefault(ENV_TENANT_ID, realm.getName());
        String entityId = buildEntityId(realm, knownUser);

        if (apiKey == null || apiKey.isBlank()) {
            logger.warnf("[HumifortisRiskEvaluator] API key missing (entity=%s) — fail open", entityId);
            return new EvaluationResult(failOpen(), null);
        }

        if (!apiUrl.toLowerCase(Locale.ROOT).startsWith("https://")) {
            logger.warnf("[HumifortisRiskEvaluator] Non-HTTPS URL (entity=%s) — fail open", entityId);
            return new EvaluationResult(failOpen(), null);
        }

        try {
            // Build payload
            EventPayload event = new EventPayload();
            event.entity_id   = entityId;
            event.entity_type = "user"; // must match entity_type sent by HumifortisEventListener so /evaluate reads the same Redis risk key as /events
            event.event_type  = "auth_credential_verified"; // credentials confirmed; session NOT yet established
            event.timestamp   = Instant.now().toString();
            event.flow_id     = flowId; // propagate Keycloak auth session id — groups with enforcement events
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
                return new EvaluationResult(failOpen(), null);
            }

            EvaluateResponse decision = gson.fromJson(response.body(), EvaluateResponse.class);
            recordSuccess();

            String riskLevel = decision.risk_level != null ? decision.risk_level : "MINIMAL";
            String reason    = buildReason(decision);

            logger.debugf("[HumifortisRiskEvaluator] level=%s action=%s rule=%s score=%.1f",
                    riskLevel, decision.action, decision.playbook_rule, decision.risk_score);

            return new EvaluationResult(mapRiskLevel(riskLevel, reason), decision);

        } catch (Exception e) {
            logger.warnf("[HumifortisRiskEvaluator] Exception (entity=%s): %s",
                    entityId, e.getMessage());
            recordFailure();
            return new EvaluationResult(failOpen(), null);
        }
    }

    // =========================================================================
    // CONTEXT COLLECTION — raw data sent to server for enrichment
    // =========================================================================

    private Map<String, Object> buildMetadata(RealmModel realm, UserModel user) {
        Map<String, Object> meta = new HashMap<>();
        UserContextSnapshot userContext = userContextExtractor.extract(session, realm, user);

        // IP address — real client IP after nginx real_ip_module resolves CF-Connecting-IP
        safeCollect(meta, "ip", () -> {
            var conn = session.getContext().getConnection();
            return conn != null ? conn.getRemoteAddr() : null;
        });

        // Cloudflare geo-country (free, instant, available when CF is the proxy).
        // Sent as "geo_country" so the Go enricher skips MaxMind country lookup
        // and uses MaxMind only for city + ASN (which CF free plan doesn't provide).
        // Values: ISO 3166-1 alpha-2 (e.g. "CA"), "XX"=unknown, "T1"=Tor — we skip both.
        safeCollect(meta, "geo_country", () -> {
            var headers = session.getContext().getRequestHeaders();
            if (headers == null) return null;
            String cc = headers.getHeaderString("CF-IPCountry");
            if (cc == null || cc.isBlank() || "XX".equals(cc) || "T1".equals(cc)) return null;
            meta.put("geo_country_source", "cloudflare");
            return cc;
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

        // Device signals — collected by HumifortisDeviceCollectorAuthenticator (step before this one)
        safeCollect(meta, "device_id", () -> {
            var as = session.getContext().getAuthenticationSession();
            return as != null ? as.getAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_ID) : null;
        });
        safeCollect(meta, "device_signals", () -> {
            var as = session.getContext().getAuthenticationSession();
            return as != null ? as.getAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_SIGNALS) : null;
        });
        safeCollect(meta, "device_tz", () -> {
            var as = session.getContext().getAuthenticationSession();
            return as != null ? as.getAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_TZ) : null;
        });
        safeCollect(meta, "device_screen", () -> {
            var as = session.getContext().getAuthenticationSession();
            return as != null ? as.getAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_SCREEN) : null;
        });
        safeCollect(meta, "device_lang", () -> {
            var as = session.getContext().getAuthenticationSession();
            return as != null ? as.getAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_LANG) : null;
        });
        safeCollect(meta, "device_color_depth", () -> {
            var as = session.getContext().getAuthenticationSession();
            return as != null ? as.getAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_COLOR_DEPTH) : null;
        });
        safeCollect(meta, "device_cpu_cores", () -> {
            var as = session.getContext().getAuthenticationSession();
            return as != null ? as.getAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_CPU_CORES) : null;
        });
        safeCollect(meta, "device_memory_gb", () -> {
            var as = session.getContext().getAuthenticationSession();
            return as != null ? as.getAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_MEMORY_GB) : null;
        });
        safeCollect(meta, "device_touch", () -> {
            var as = session.getContext().getAuthenticationSession();
            return as != null ? as.getAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_TOUCH) : null;
        });
        safeCollect(meta, "device_platform", () -> {
            var as = session.getContext().getAuthenticationSession();
            return as != null ? as.getAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_PLATFORM) : null;
        });
        safeCollect(meta, "device_connection", () -> {
            var as = session.getContext().getAuthenticationSession();
            return as != null ? as.getAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_CONNECTION) : null;
        });
        // GPU signals — used by enricher.go to compute device.server_fp (T1 replay detection)
        safeCollect(meta, "device_webgl_vendor", () -> {
            var as = session.getContext().getAuthenticationSession();
            return as != null ? as.getAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_WEBGL_VENDOR) : null;
        });
        safeCollect(meta, "device_webgl_renderer", () -> {
            var as = session.getContext().getAuthenticationSession();
            return as != null ? as.getAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_WEBGL_RENDERER) : null;
        });
        // FP hash: SHA-256 of full components JSON (replaces truncated blob)
        safeCollect(meta, "device_fp_hash", () -> {
            var as = session.getContext().getAuthenticationSession();
            return as != null ? as.getAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_FP_HASH) : null;
        });
        // Binding result: server-validated anti-replay check ("valid"|"stale"|"mismatch"|"absent"|"error")
        safeCollect(meta, "device_fp_binding_valid", () -> {
            var as = session.getContext().getAuthenticationSession();
            return as != null ? as.getAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_BINDING_RESULT) : null;
        });

        // Browser trust token — HttpOnly cookie set after previous MFA success.
        // Hashed server-side to SHA-256 hex before sending (plain value never leaves the browser).
        // Enables browser_token_valid signal in the risk pipeline on subsequent logins.
        safeCollect(meta, "trust_token_hash", () -> {
            try {
                var cookies = session.getContext().getHttpRequest().getHttpHeaders().getCookies();
                if (cookies == null) return null;
                jakarta.ws.rs.core.Cookie c = cookies.get("hf_trust");
                if (c == null || c.getValue() == null || c.getValue().isBlank()) return null;
                return sha256Hex(c.getValue());
            } catch (Exception e) {
                logger.debugf("[HumifortisRiskEvaluator] trust_token_hash read failed: %s", e.getMessage());
                return null;
            }
        });
        // v2.2 passive discriminators
        safeCollect(meta, "device_touch_points", () -> {
            var as = session.getContext().getAuthenticationSession();
            return as != null ? as.getAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_TOUCH_POINTS) : null;
        });
        safeCollect(meta, "device_orientation", () -> {
            var as = session.getContext().getAuthenticationSession();
            return as != null ? as.getAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_ORIENTATION) : null;
        });
        safeCollect(meta, "device_hash_perf_ms", () -> {
            var as = session.getContext().getAuthenticationSession();
            return as != null ? as.getAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_HASH_PERF_MS) : null;
        });
        safeCollect(meta, "device_load_ms", () -> {
            var as = session.getContext().getAuthenticationSession();
            return as != null ? as.getAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_LOAD_MS) : null;
        });
        // v2.3 Math / FPU fingerprint
        safeCollect(meta, "device_math_hash", () -> {
            var as = session.getContext().getAuthenticationSession();
            return as != null ? as.getAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_MATH_HASH) : null;
        });
        safeCollect(meta, "device_fpu_class", () -> {
            var as = session.getContext().getAuthenticationSession();
            return as != null ? as.getAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_FPU_CLASS) : null;
        });
        safeCollect(meta, "device_math_anomaly", () -> {
            var as = session.getContext().getAuthenticationSession();
            return as != null ? as.getAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_MATH_ANOMALY) : null;
        });
        safeCollect(meta, "device_math_exec_ms", () -> {
            var as = session.getContext().getAuthenticationSession();
            return as != null ? as.getAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_MATH_EXEC_MS) : null;
        });
        safeCollect(meta, "device_math_consistency", () -> {
            var as = session.getContext().getAuthenticationSession();
            return as != null ? as.getAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_MATH_CONSISTENCY) : null;
        });

        // User attributes
        if (userContext.username() != null) meta.put("username", userContext.username());
        if (userContext.email()    != null) meta.put("email",    userContext.email());

        // email_verified — required for EMAIL_OTP safety (unverified email is attackable)
        meta.put("email_verified", String.valueOf(userContext.emailVerified()));

        // mfa_methods — enrolled methods as comma-separated string for feature engine
        // (distinct from available_methods which includes EMAIL_OTP derived from email_verified)
        if (!userContext.mfaMethods().isEmpty()) {
            meta.put("mfa_methods", String.join(",", userContext.mfaMethods()));
        }
        if (userContext.accountAgeDays() != null) {
            meta.put("account_age_days", String.valueOf(userContext.accountAgeDays()));
        }
        if (!userContext.roleNames().isEmpty()) {
            meta.put("user_roles", String.join(",", userContext.roleNames()));
        }
        meta.put("is_privileged", String.valueOf(userContext.privileged()));
        meta.put("mfa_enrolled", String.valueOf(userContext.mfaEnrolled()));
        meta.put("active_session_count", String.valueOf(userContext.activeSessionCount()));

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
        try {
            List<String> methods = new ArrayList<>(userContextExtractor.extractMfaMethods(user));
            if (methods.isEmpty()) methods.add("EMAIL_OTP");
            return methods;
        } catch (Exception e) {
            logger.debugf("[HumifortisRiskEvaluator] MFA methods detection failed: %s", e.getMessage());
            return List.of("EMAIL_OTP");
        }
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

    // Package-private so HumifortisStepUpRouter can build entity IDs without duplication.
    static String buildEntityId(RealmModel realm, UserModel user) {
        // Standard entity_id format: user:keycloak:{realmName}:{keycloakUserUUID}
        // This matches exactly what E2E tests use via ENV.USERS.alice.entityId and
        // what the risk engine stores risk state under — ensuring consistent Redis keys
        // between SPI evaluations and API-level test injections / resets.
        String userId    = user.getId() != null && !user.getId().isBlank() ? user.getId() : "unknown";
        String realmName = realm.getName() != null && !realm.getName().isBlank()
                ? realm.getName()
                : (realm.getId() != null ? realm.getId() : "unknown");
        return String.format("user:keycloak:%s:%s", realmName, userId);
    }

    public static String envOrDefault(String key, String defaultValue) {
        String val = System.getenv(key);
        return (val == null || val.isBlank()) ? defaultValue : val;
    }

    // ── SHA-256 hex helper ────────────────────────────────────────────────────
    // Package-private: used by HumifortisStepUpRouter to hash the cookie value before
    // sending to the server and before setting the cookie in the browser.
    static String sha256Hex(String input) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(64);
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 failed", e);
        }
    }

    // ── Browser token registration ────────────────────────────────────────────

    /**
     * Parses a User-Agent string into a human-readable device label.
     * Pattern: "Desktop-Chrome-149, macOS 10.15"
     */
    static String parseDeviceName(String ua) {
        if (ua == null || ua.isBlank()) return "Unknown Device";

        // Device type
        String deviceType = "Desktop";
        if (ua.contains("Mobile") || ua.contains("Android") ||
                ua.contains("iPhone") || ua.contains("iPad")) {
            deviceType = "Mobile";
        }

        // Browser (order matters: Edge before Chrome)
        String browser = "Browser";
        String browserVer = "";
        java.util.regex.Matcher m;
        if ((m = java.util.regex.Pattern.compile("Edg/([0-9]+)").matcher(ua)).find()) {
            browser = "Edge"; browserVer = m.group(1);
        } else if ((m = java.util.regex.Pattern.compile("Firefox/([0-9]+)").matcher(ua)).find()) {
            browser = "Firefox"; browserVer = m.group(1);
        } else if ((m = java.util.regex.Pattern.compile("Chrome/([0-9]+)").matcher(ua)).find()) {
            browser = "Chrome"; browserVer = m.group(1);
        } else if (ua.contains("Version/") && ua.contains("Safari")) {
            m = java.util.regex.Pattern.compile("Version/([0-9]+)").matcher(ua);
            if (m.find()) browserVer = m.group(1);
            browser = "Safari";
        }

        // OS / Platform
        String os = "Unknown OS";
        if ((m = java.util.regex.Pattern.compile("Windows NT ([0-9.]+)").matcher(ua)).find()) {
            String v = m.group(1);
            os = "Windows " + (v.startsWith("10") ? "10/11" : v);
        } else if ((m = java.util.regex.Pattern.compile("Mac OS X ([0-9_]+)").matcher(ua)).find()) {
            os = "macOS " + m.group(1).replace('_', '.');
        } else if (ua.contains("Android")) {
            m = java.util.regex.Pattern.compile("Android ([0-9.]+)").matcher(ua);
            os = m.find() ? "Android " + m.group(1) : "Android";
        } else if (ua.contains("iPhone") || ua.contains("iPad")) {
            m = java.util.regex.Pattern.compile("OS ([0-9_]+)").matcher(ua);
            os = m.find() ? "iOS " + m.group(1).replace('_', '.') : "iOS";
        } else if (ua.contains("Linux")) {
            os = "Linux";
        }

        String browserPart = browser + (browserVer.isEmpty() ? "" : "-" + browserVer);
        return deviceType + "-" + browserPart + ", " + os;
    }

    /**
     * Extracts the OS/platform family from a User-Agent string.
     * Returns "macOS", "Windows", "Linux", "Android", "iOS", or "Unknown".
     */
    static String parsePlatform(String ua) {
        if (ua == null || ua.isBlank()) return "Unknown";
        if (ua.contains("Mac OS X"))  return "macOS";
        if (ua.contains("Windows"))   return "Windows";
        if (ua.contains("iPhone") || ua.contains("iPad")) return "iOS";
        if (ua.contains("Android"))   return "Android";
        if (ua.contains("Linux"))     return "Linux";
        return "Unknown";
    }

    /**
     * Registers a browser token hash with the server after successful MFA.
     * Fire-and-forget (CompletableFuture) — never blocks the auth flow.
     *
     * @param canonicalEntityId  e.g. "user:keycloak:demo:uuid"
     * @param tokenHash          SHA-256 hex of the HttpOnly cookie value
     * @param tenantId           Humifortis tenant ID (from env var or realm name)
     * @param deviceId           Stable FingerprintJS visitorId — when provided, ensures one
     *                           trusted_devices row per physical device (token rotates on MFA).
     *                           When null/empty, legacy behaviour: one row per token.
     * @param deviceName         Human-readable label, e.g. "Desktop-Chrome-149, macOS 10.15"
     * @param platform           OS family, e.g. "macOS"
     * @param ipAddress          End-user IP at trust time
     */
    public void registerTrustTokenAsync(String canonicalEntityId, String tokenHash, String tenantId,
                                        String deviceId, String deviceName, String platform, String ipAddress) {
        String apiUrl = envOrDefault(ENV_API_URL, DEFAULT_API_URL);
        String apiKey = System.getenv(ENV_API_KEY);
        if (apiKey == null || apiKey.isBlank()) {
            logger.warnf("[HumifortisRiskEvaluator] registerTrustToken: API key missing");
            return;
        }
        TrustTokenPayload payload = new TrustTokenPayload();
        payload.entity_id = canonicalEntityId;
        payload.token_hash = tokenHash;
        payload.ttl_days = 30;
        payload.device_id = isBlank(deviceId) ? null : deviceId;
        payload.device_name = isBlank(deviceName) ? null : deviceName;
        payload.platform = isBlank(platform) ? null : platform;
        payload.ip_address = isBlank(ipAddress) ? null : ipAddress;
        String body = gson.toJson(payload);
        String url = apiUrl + "/devices/trust";

        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Content-Type", "application/json")
                    .header("X-API-Key",    apiKey)
                    .header("X-Tenant-ID",  tenantId)
                    .timeout(Duration.ofMillis(DEFAULT_TIMEOUT_MS))
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            java.util.concurrent.CompletableFuture.runAsync(() -> {
                try {
                    HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
                    if (resp.statusCode() == 201) {
                        logger.infof("[HumifortisRiskEvaluator] Browser token registered for entity=%s",
                                canonicalEntityId);
                    } else {
                        logger.warnf("[HumifortisRiskEvaluator] registerTrustToken HTTP %d: %s",
                                resp.statusCode(), resp.body());
                    }
                } catch (Exception e) {
                    logger.warnf("[HumifortisRiskEvaluator] registerTrustToken async failed: %s",
                            e.getMessage());
                }
            });
        } catch (Exception e) {
            logger.warnf("[HumifortisRiskEvaluator] registerTrustToken setup failed: %s", e.getMessage());
        }
    }

    private static int parseTimeout(String raw) {
        if (raw == null || raw.isBlank()) return DEFAULT_TIMEOUT_MS;
        try { return Integer.parseInt(raw); } catch (NumberFormatException e) { return DEFAULT_TIMEOUT_MS; }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
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
        public String              flow_id;   // Keycloak auth session id — groups all events of one login attempt
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
        // ─── Verified-Unblock (admin-initiated step-up) ──────────────────────
        /**
         * Set to REQUIRE_MFA_VERIFICATION when a DENY was downgraded to a step-up MFA
         * because an admin opened a verification window. Distinct from a normal
         * risk-based MFA — the connector binds the resulting MFA to the challenge.
         */
        @SerializedName("verification_reason")          public String verification_reason;
        /** Challenge id to echo back in auth_mfa_success so the server can bind + clear the block. */
        @SerializedName("verification_challenge_id")    public String verification_challenge_id;
        /** Minimum AAL required to satisfy the challenge (AAL2 default, AAL3 for WebAuthn). */
        @SerializedName("verification_required_level")  public String verification_required_level;
    }

    record EvaluationResult(Risk risk, EvaluateResponse decision) {}

    private static class TrustTokenPayload {
        String entity_id;
        String token_hash;
        int ttl_days;
        String device_id;
        String device_name;
        String platform;
        String ip_address;
    }
}

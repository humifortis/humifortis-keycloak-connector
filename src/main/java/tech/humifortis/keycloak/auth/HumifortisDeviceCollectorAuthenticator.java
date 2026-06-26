package tech.humifortis.keycloak.auth;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;

/**
 * Device Collector Authenticator — transparent step that runs immediately after the
 * Username/Password form.
 *
 * <h3>Mechanism</h3>
 * <ol>
 *   <li>{@code authenticate()} generates a session-scoped nonce, stores it as an AuthNote,
 *       and embeds it in the FTL template as {@code ${deviceNonce}}. The nonce enables
 *       anti-replay binding validation in {@code action()}.</li>
 *   <li>The JS bundle runs, collects device signals, computes
 *       {@code binding = SHA-256(nonce:timestamp:visitorId)}, and auto-submits.</li>
 *   <li>{@code action()} validates the binding server-side (recomputes and compares),
 *       then stores all signals as AuthNotes for downstream SPI.</li>
 * </ol>
 *
 * <h3>Anti-replay binding (v2.1)</h3>
 * <ul>
 *   <li>Each page load gets a unique UUID nonce → captured POST bodies cannot be replayed.</li>
 *   <li>Timestamp delta check (MAX_COLLECTOR_AGE_MS) → stale submissions rejected.</li>
 *   <li>Binding ties device_id to the nonce → tampering after collection is detectable.</li>
 *   <li>Binding result stored as {@link #NOTE_BINDING_RESULT} for downstream scoring.</li>
 * </ul>
 *
 * <h3>Resilience</h3>
 * <ul>
 *   <li>Binding failure is NEVER blocking — recorded but flow always continues (fail-open).</li>
 *   <li>JS disabled → safety timer submits empty form → flow continues normally.</li>
 * </ul>
 */
public class HumifortisDeviceCollectorAuthenticator implements Authenticator {

    private static final Logger logger =
            Logger.getLogger(HumifortisDeviceCollectorAuthenticator.class);

    /** Maximum age (ms) between nonce issuance and form submission. */
    private static final long MAX_COLLECTOR_AGE_MS = 30_000L;

    // ── AuthNote keys ─────────────────────────────────────────────────────────

    /** FingerprintJS stable visitorId. */
    public static final String NOTE_DEVICE_ID             = "HUMIFORTIS_DEVICE_ID";
    /** Structured JSON subset of FP high-entropy components (canvas, audio, counts). */
    public static final String NOTE_DEVICE_SIGNALS        = "HUMIFORTIS_DEVICE_SIGNALS";
    /** SHA-256 of full FP components JSON (replaces truncated blob). */
    public static final String NOTE_DEVICE_FP_HASH        = "HUMIFORTIS_DEVICE_FP_HASH";
    /** IANA timezone string — e.g. "America/Montreal". */
    public static final String NOTE_DEVICE_TZ             = "HUMIFORTIS_DEVICE_TZ";
    /** Screen resolution — e.g. "1920x1080". */
    public static final String NOTE_DEVICE_SCREEN         = "HUMIFORTIS_DEVICE_SCREEN";
    /** Browser language tag — e.g. "fr-CA". */
    public static final String NOTE_DEVICE_LANG           = "HUMIFORTIS_DEVICE_LANG";
    /** Screen color depth — e.g. "24". */
    public static final String NOTE_DEVICE_COLOR_DEPTH    = "HUMIFORTIS_DEVICE_COLOR_DEPTH";
    /** CPU logical cores — e.g. "8". */
    public static final String NOTE_DEVICE_CPU_CORES      = "HUMIFORTIS_DEVICE_CPU_CORES";
    /** Device memory estimate in GB — e.g. "8". Chrome/Edge only. */
    public static final String NOTE_DEVICE_MEMORY_GB      = "HUMIFORTIS_DEVICE_MEMORY_GB";
    /** Touch capability — "true" / "false". */
    public static final String NOTE_DEVICE_TOUCH          = "HUMIFORTIS_DEVICE_TOUCH";
    /** Platform OS string (UACH or UA-derived) — e.g. "Windows", "macOS", "iOS". */
    public static final String NOTE_DEVICE_PLATFORM       = "HUMIFORTIS_DEVICE_PLATFORM";
    /** Network connection type — "wifi", "cellular", "ethernet". Chrome/Edge only. */
    public static final String NOTE_DEVICE_CONNECTION     = "HUMIFORTIS_DEVICE_CONNECTION";
    /** WebGL GPU vendor — "Intel Inc.", "NVIDIA Corporation", "Apple". T2: hard to spoof. */
    public static final String NOTE_DEVICE_WEBGL_VENDOR   = "HUMIFORTIS_DEVICE_WEBGL_VENDOR";
    /** WebGL renderer string — "Intel Iris Xe Graphics", "Apple M2". T3: spoofable via extension. */
    public static final String NOTE_DEVICE_WEBGL_RENDERER = "HUMIFORTIS_DEVICE_WEBGL_RENDERER";
    /** Time from page load to FP completion in ms — bot detection signal. */
    public static final String NOTE_DEVICE_LOAD_MS        = "HUMIFORTIS_DEVICE_LOAD_MS";

    // ── v2.2 passive discriminators ───────────────────────────────────────────

    /** Actual maxTouchPoints count: 0=desktop, 1=pen, 5=phone, 10=high-end tablet. */
    public static final String NOTE_DEVICE_TOUCH_POINTS  = "HUMIFORTIS_DEVICE_TOUCH_POINTS";
    /** Screen orientation type — "portrait-primary" | "landscape-primary". */
    public static final String NOTE_DEVICE_ORIENTATION   = "HUMIFORTIS_DEVICE_ORIENTATION";
    /** SubtleCrypto SHA-256 benchmark ms — bot/VM detection (1-15ms=normal, >50ms=VM). */
    public static final String NOTE_DEVICE_HASH_PERF_MS  = "HUMIFORTIS_DEVICE_HASH_PERF_MS";

    // ── Anti-replay binding AuthNote keys ─────────────────────────────────────

    /** Session-scoped UUID nonce generated by authenticate() — single-use, stored server-side. */
    static final String NOTE_DEVICE_NONCE     = "HUMIFORTIS_DEVICE_NONCE";
    /** Unix ms timestamp when authenticate() issued the nonce — used for stale check. */
    static final String NOTE_NONCE_ISSUED_AT  = "HUMIFORTIS_NONCE_ISSUED_AT";
    /** SHA-256(nonce:timestamp:visitorId) computed by JS, validated by action(). */
    public static final String NOTE_DEVICE_BINDING   = "HUMIFORTIS_DEVICE_BINDING";
    /** Unix ms when the JS collection ran (from device_timestamp POST field). */
    public static final String NOTE_DEVICE_TIMESTAMP = "HUMIFORTIS_DEVICE_TIMESTAMP";
    /**
     * Server-validated binding result — stored for downstream risk scoring.
     * Values: "valid" | "stale" | "mismatch" | "absent" | "error"
     */
    public static final String NOTE_BINDING_RESULT   = "HUMIFORTIS_BINDING_RESULT";

    private static final String TEMPLATE = "humifortis-device-collector.ftl";

    // =========================================================================
    // AUTHENTICATE — generate nonce, serve transparent collection page
    // =========================================================================

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // Generate a session-scoped UUID nonce for anti-replay binding.
        // The nonce is embedded in the FTL as ${deviceNonce} and read by the JS bundle.
        // action() recomputes SHA-256(nonce:timestamp:visitorId) and compares with submitted binding.
        String nonce = UUID.randomUUID().toString();
        context.getAuthenticationSession().setAuthNote(NOTE_DEVICE_NONCE,    nonce);
        context.getAuthenticationSession().setAuthNote(NOTE_NONCE_ISSUED_AT, String.valueOf(System.currentTimeMillis()));

        logger.debugf("[DeviceCollector] authenticate — nonce=%s... realm=%s user=%s",
                nonce.substring(0, 8),
                context.getRealm().getName(),
                context.getUser() != null ? context.getUser().getUsername() : "?");

        Response challenge = context.form()
                .setAttribute("deviceNonce", nonce)   // → ${deviceNonce} in FTL
                .createForm(TEMPLATE);
        context.forceChallenge(challenge);
    }

    // =========================================================================
    // ACTION — validate binding, store AuthNotes, continue flow
    // =========================================================================

    @Override
    public void action(AuthenticationFlowContext context) {
        if (context.getHttpRequest() == null) {
            logger.warnf("[DeviceCollector] action() called with null HttpRequest — skipping");
            context.success();
            return;
        }

        MultivaluedMap<String, String> params = context.getHttpRequest().getDecodedFormParameters();
        if (params == null) {
            logger.warnf("[DeviceCollector] getDecodedFormParameters() returned null — skipping");
            context.success();
            return;
        }

        // ── STABLE
        String deviceId          = params.getFirst("device_id");
        String deviceSignals     = params.getFirst("device_signals");
        String deviceFpHash      = params.getFirst("device_fp_hash");
        // ── BINDING (v2.1)
        String deviceTimestamp   = params.getFirst("device_timestamp");
        String deviceBinding     = params.getFirst("device_binding");
        // ── CONTEXTUAL
        String deviceTz          = params.getFirst("device_tz");
        String deviceScreen      = params.getFirst("device_screen");
        String deviceLang        = params.getFirst("device_lang");
        String deviceColorDepth  = params.getFirst("device_color_depth");
        // ── HARDWARE
        String deviceCpuCores    = params.getFirst("device_cpu_cores");
        String deviceMemoryGb    = params.getFirst("device_memory_gb");
        String deviceTouch       = params.getFirst("device_touch");
        String devicePlatform    = params.getFirst("device_platform");
        String deviceConnection  = params.getFirst("device_connection");
        // ── GPU
        String deviceWebglVendor   = params.getFirst("device_webgl_vendor");
        String deviceWebglRenderer = params.getFirst("device_webgl_renderer");
        // ── BEHAVIORAL
        String deviceLoadMs      = params.getFirst("device_load_ms");
        // ── PASSIVE DISCRIMINATORS (v2.2)
        String deviceTouchPoints = params.getFirst("device_touch_points");
        String deviceOrientation = params.getFirst("device_orientation");
        String deviceHashPerfMs  = params.getFirst("device_hash_perf_ms");

        // ── ANTI-REPLAY BINDING VALIDATION ───────────────────────────────────
        // Recompute binding server-side from the stored nonce + submitted timestamp + deviceId.
        // Result is stored as NOTE_BINDING_RESULT and sent to /evaluate via RiskEvaluator.
        // NEVER blocks authentication — always fail-open.
        String bindingResult = validateBinding(context, deviceTimestamp, deviceBinding, deviceId);

        // ── STORE ALL SIGNALS AS AUTH NOTES ──────────────────────────────────
        setNote(context, NOTE_DEVICE_ID,             deviceId);
        setNote(context, NOTE_DEVICE_SIGNALS,        deviceSignals);
        setNote(context, NOTE_DEVICE_FP_HASH,        deviceFpHash);
        setNote(context, NOTE_DEVICE_BINDING,        deviceBinding);
        setNote(context, NOTE_DEVICE_TIMESTAMP,      deviceTimestamp);
        setNote(context, NOTE_DEVICE_TZ,             deviceTz);
        setNote(context, NOTE_DEVICE_SCREEN,         deviceScreen);
        setNote(context, NOTE_DEVICE_LANG,           deviceLang);
        setNote(context, NOTE_DEVICE_COLOR_DEPTH,    deviceColorDepth);
        setNote(context, NOTE_DEVICE_CPU_CORES,      deviceCpuCores);
        setNote(context, NOTE_DEVICE_MEMORY_GB,      deviceMemoryGb);
        setNote(context, NOTE_DEVICE_TOUCH,          deviceTouch);
        setNote(context, NOTE_DEVICE_PLATFORM,       devicePlatform);
        setNote(context, NOTE_DEVICE_CONNECTION,     deviceConnection);
        setNote(context, NOTE_DEVICE_WEBGL_VENDOR,   deviceWebglVendor);
        setNote(context, NOTE_DEVICE_WEBGL_RENDERER, deviceWebglRenderer);
        setNote(context, NOTE_DEVICE_LOAD_MS,        deviceLoadMs);
        setNote(context, NOTE_DEVICE_TOUCH_POINTS,   deviceTouchPoints);
        setNote(context, NOTE_DEVICE_ORIENTATION,    deviceOrientation);
        setNote(context, NOTE_DEVICE_HASH_PERF_MS,   deviceHashPerfMs);
        // Binding result is always set (even "absent") so downstream SPI can read it
        context.getAuthenticationSession().setAuthNote(NOTE_BINDING_RESULT, bindingResult);

        // ── EVENT DETAILS (survives auth session close) ───────────────────────
        if (context.getEvent() != null) {
            eventDetail(context, "device_id",             deviceId);
            eventDetail(context, "device_binding_result", bindingResult);
            eventDetail(context, "device_fp_hash",        deviceFpHash);
            eventDetail(context, "device_tz",             deviceTz);
            eventDetail(context, "device_screen",         deviceScreen);
            eventDetail(context, "device_lang",           deviceLang);
            eventDetail(context, "device_color_depth",    deviceColorDepth);
            eventDetail(context, "device_cpu_cores",      deviceCpuCores);
            eventDetail(context, "device_memory_gb",      deviceMemoryGb);
            eventDetail(context, "device_touch",          deviceTouch);
            eventDetail(context, "device_platform",       devicePlatform);
            eventDetail(context, "device_connection",     deviceConnection);
            eventDetail(context, "device_webgl_vendor",   deviceWebglVendor);
            eventDetail(context, "device_webgl_renderer", deviceWebglRenderer);
            eventDetail(context, "device_load_ms",        deviceLoadMs);
            eventDetail(context, "device_touch_points",   deviceTouchPoints);
            eventDetail(context, "device_orientation",    deviceOrientation);
            eventDetail(context, "device_hash_perf_ms",   deviceHashPerfMs);
        }

        logger.debugf("[DeviceCollector] collected — device_id=%s binding=%s platform=%s cpu=%s webgl=%s load_ms=%s",
                nvl(deviceId, "(none)"), bindingResult,
                nvl(devicePlatform, "?"), nvl(deviceCpuCores, "?"),
                nvl(deviceWebglVendor, "?"), nvl(deviceLoadMs, "?"));

        context.success();
    }

    // =========================================================================
    // ANTI-REPLAY BINDING VALIDATION
    // =========================================================================

    /**
     * Validates the anti-replay binding submitted by the JS collector.
     *
     * <p>Algorithm:
     * <pre>
     *   expected = SHA-256(server_nonce + ":" + client_timestamp_ms + ":" + device_id)
     *   valid if: expected == submitted_binding AND |server_now - client_ts| &lt; 30s
     * </pre>
     *
     * <p>Returns one of: {@code "valid"} | {@code "stale"} | {@code "mismatch"} |
     * {@code "absent"} | {@code "error"}
     *
     * <p>NEVER throws — binding failure is always fail-open.
     */
    private String validateBinding(AuthenticationFlowContext context,
                                   String timestampMs, String submittedBinding, String deviceId) {
        try {
            if (!notBlank(submittedBinding) || !notBlank(timestampMs)) return "absent";

            String storedNonce  = context.getAuthenticationSession().getAuthNote(NOTE_DEVICE_NONCE);
            if (!notBlank(storedNonce)) return "error";

            long clientTs  = Long.parseLong(timestampMs);
            long serverNow = System.currentTimeMillis();
            if (Math.abs(serverNow - clientTs) > MAX_COLLECTOR_AGE_MS) {
                logger.debugf("[DeviceCollector] binding stale — delta=%dms", Math.abs(serverNow - clientTs));
                return "stale";
            }

            // Recompute: SHA-256(nonce:timestamp:visitorId)  — same formula as JS
            String input    = storedNonce + ":" + timestampMs + ":" + nvl(deviceId, "");
            String expected = sha256Hex(input);
            if (expected == null) return "error";

            boolean valid = expected.equalsIgnoreCase(submittedBinding);
            logger.debugf("[DeviceCollector] binding %s — delta=%dms",
                    valid ? "VALID" : "MISMATCH", Math.abs(serverNow - clientTs));
            return valid ? "valid" : "mismatch";

        } catch (NumberFormatException e) {
            logger.debugf("[DeviceCollector] binding timestamp parse error: %s", e.getMessage());
            return "error";
        } catch (Exception e) {
            logger.debugf("[DeviceCollector] binding validation error: %s", e.getMessage());
            return "error";
        }
    }

    /**
     * Computes SHA-256 of the input string and returns lowercase hex.
     * Returns null if MessageDigest fails (should never happen in practice).
     */
    private static String sha256Hex(String input) {
        try {
            MessageDigest md   = MessageDigest.getInstance("SHA-256");
            byte[]         hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder  sb   = new StringBuilder(hash.length * 2);
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    private void setNote(AuthenticationFlowContext context, String key, String value) {
        if (notBlank(value)) {
            context.getAuthenticationSession().setAuthNote(key, value);
        }
    }

    private void eventDetail(AuthenticationFlowContext context, String key, String value) {
        if (notBlank(value)) {
            context.getEvent().detail(key, value);
        }
    }

    private static boolean notBlank(String s) { return s != null && !s.isBlank(); }

    private static String nvl(String value, String fallback) {
        return notBlank(value) ? value : fallback;
    }

    // =========================================================================
    // SPI boilerplate
    // =========================================================================

    @Override public boolean requiresUser()                                               { return true;  }
    @Override public boolean configuredFor(KeycloakSession s, RealmModel r, UserModel u) { return true;  }
    @Override public void setRequiredActions(KeycloakSession s, RealmModel r, UserModel u) {}
    @Override public void close() {}
}

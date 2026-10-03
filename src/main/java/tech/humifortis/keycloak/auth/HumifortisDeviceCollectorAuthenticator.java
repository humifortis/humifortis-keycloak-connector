package tech.humifortis.keycloak.auth;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.UUID;

/**
 * Device Collector — the flow step that gathers the browser's device signals, right after the
 * username/password form. It works with any login theme and never blocks a login.
 *
 * <h3>Two ways the signals arrive (see {@link DeviceSignals})</h3>
 * <ol>
 *   <li><b>Default:</b> this step renders a short auto-submitting page
 *       ({@code humifortis-device-collector.ftl}) that runs {@code humifortis-device.bundle.js}
 *       and posts the {@code device_*} fields to {@link #action}.</li>
 *   <li><b>Opt-in, recommended:</b> the login theme loads the same script on the login page
 *       ({@code scripts=js/humifortis-device.bundle.js} in its theme.properties). The fields then
 *       come with the username/password POST: this step stores them and continues WITHOUT any
 *       extra page — and a failed login carries them too (see HumifortisEventListener).</li>
 * </ol>
 *
 * <h3>Anti-replay binding</h3>
 * {@code binding = SHA-256(nonce:timestamp:visitorId)}, recomputed server-side. The nonce is a
 * UUID rendered into the collector page, or the auth session's tab id on the login page. The
 * verdict (valid | stale | mismatch | absent | error) is stored as {@link #NOTE_BINDING_RESULT}
 * and scored by Humifortis Core; it never blocks authentication.
 */
public class HumifortisDeviceCollectorAuthenticator implements Authenticator {

    private static final Logger logger =
            Logger.getLogger(HumifortisDeviceCollectorAuthenticator.class);

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

    // ── v2.3 Math / FPU fingerprint ───────────────────────────────────────────

    /** SHA-256 of stable-stringified Math results — FPU drift detection cross-session. */
    public static final String NOTE_DEVICE_MATH_HASH        = "HUMIFORTIS_DEVICE_MATH_HASH";
    /** Inferred FPU instruction set: "arm64" | "x86_64" | "unknown". Multi-signal classifier. */
    public static final String NOTE_DEVICE_FPU_CLASS        = "HUMIFORTIS_DEVICE_FPU_CLASS";
    /** "1" if Math results contain NaN/Infinity — headless or instrumented JS engine. */
    public static final String NOTE_DEVICE_MATH_ANOMALY     = "HUMIFORTIS_DEVICE_MATH_ANOMALY";
    /** Math.sin(1) execution time in µs (string, 3 dp) — VM jitter signal. Value IS µs. */
    public static final String NOTE_DEVICE_MATH_EXEC_MS     = "HUMIFORTIS_DEVICE_MATH_EXEC_MS";
    /** abs(sin²+cos²−1) deviation — detects patched/broken Math engines. Float string, 6 dp. */
    public static final String NOTE_DEVICE_MATH_CONSISTENCY = "HUMIFORTIS_DEVICE_MATH_CONSISTENCY";

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
        // Opt-in path: the login page already ran the collector script, so its signals came with
        // the username/password POST that is being processed right now — no extra page.
        DeviceSignals fromLogin = DeviceSignals.fromForm(formOf(context));
        if (fromLogin != null) {
            store(context, fromLogin, fromLogin.validateBinding(context.getAuthenticationSession().getTabId(), System.currentTimeMillis()), "login page");
            context.success();
            return;
        }

        // Default path: render the collector page with a fresh anti-replay nonce.
        String nonce = UUID.randomUUID().toString();
        context.getAuthenticationSession().setAuthNote(NOTE_DEVICE_NONCE, nonce);
        context.getAuthenticationSession().setAuthNote(NOTE_NONCE_ISSUED_AT, String.valueOf(System.currentTimeMillis()));
        Response challenge = context.form()
                .setAttribute("deviceNonce", nonce) // →  in the template
                .createForm(TEMPLATE);
        context.forceChallenge(challenge);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        DeviceSignals signals = DeviceSignals.fromForm(formOf(context));
        if (signals == null) {
            // JavaScript disabled or the script failed: the page's safety timer posted an empty form
            context.getAuthenticationSession().setAuthNote(NOTE_BINDING_RESULT, DeviceSignals.ABSENT);
            logger.debugf("[DeviceCollector] no device signals submitted — continuing (fail-open)");
            context.success();
            return;
        }
        String nonce = context.getAuthenticationSession().getAuthNote(NOTE_DEVICE_NONCE);
        store(context, signals, signals.validateBinding(nonce, System.currentTimeMillis()), "collector page");
        context.success();
    }

    private void store(AuthenticationFlowContext context, DeviceSignals signals, String binding, String via) {
        signals.storeAsNotes(context.getAuthenticationSession(), binding);
        if (context.getEvent() != null) {
            signals.writeEventDetails((k, v) -> context.getEvent().detail(k, v), binding, false);
        }
        logger.debugf("[DeviceCollector] device signals from the %s — device_id=%s binding=%s", via, signals.deviceId(), binding);
    }

    private static MultivaluedMap<String, String> formOf(AuthenticationFlowContext context) {
        try {
            if (context.getHttpRequest() == null) return null;
            if (!"POST".equalsIgnoreCase(context.getHttpRequest().getHttpMethod())) return null;
            return context.getHttpRequest().getDecodedFormParameters();
        } catch (Exception e) {
            return null; // not a form request — fail-open
        }
    }

    // =========================================================================
    // SPI boilerplate
    // =========================================================================

    @Override public boolean requiresUser()                                               { return true;  }
    @Override public boolean configuredFor(KeycloakSession s, RealmModel r, UserModel u) { return true;  }
    @Override public void setRequiredActions(KeycloakSession s, RealmModel r, UserModel u) {}
    @Override public void close() {}
}

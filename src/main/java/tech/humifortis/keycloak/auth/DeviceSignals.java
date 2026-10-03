package tech.humifortis.keycloak.auth;

import static tech.humifortis.keycloak.auth.HumifortisDeviceCollectorAuthenticator.*;

import jakarta.ws.rs.core.MultivaluedMap;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.BiConsumer;

/**
 * The device signals a browser submits — the ONE place they are read, validated and stored.
 *
 * <p>The same {@code device_*} form fields (written by {@code humifortis-device.bundle.js}) arrive
 * through one of two pages:
 * <ul>
 *   <li><b>the device-collector page</b> — the {@code humifortis-device-collector} flow step, after the
 *       password (default, works with any login theme). Anti-replay nonce: a server nonce rendered
 *       into that page.</li>
 *   <li><b>the login page itself</b> — opt-in, when the login theme loads the bundle
 *       ({@code scripts=js/humifortis-device.bundle.js} in theme.properties). The signals then come
 *       with the username/password POST, so a FAILED login carries them too, and the collector step
 *       has nothing left to ask. Anti-replay nonce: the auth session's tab id, which Keycloak puts
 *       in the login form's action URL.</li>
 * </ul>
 *
 * <p>Everything here is fail-open: a missing or malformed field never blocks authentication.
 */
public final class DeviceSignals {

    /** Maximum age of a submission (client timestamp vs server clock) before it is "stale". */
    static final long MAX_AGE_MS = 30_000L;

    /** Binding verdicts — read by Humifortis Core (device.fp_binding_valid). */
    public static final String VALID = "valid", STALE = "stale", MISMATCH = "mismatch", ABSENT = "absent", ERROR = "error";

    /** Form field → auth-note key, in a stable order. */
    static final Map<String, String> FIELDS;
    static {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("device_id", NOTE_DEVICE_ID);
        m.put("device_signals", NOTE_DEVICE_SIGNALS);
        m.put("device_fp_hash", NOTE_DEVICE_FP_HASH);
        m.put("device_binding", NOTE_DEVICE_BINDING);
        m.put("device_timestamp", NOTE_DEVICE_TIMESTAMP);
        m.put("device_tz", NOTE_DEVICE_TZ);
        m.put("device_screen", NOTE_DEVICE_SCREEN);
        m.put("device_lang", NOTE_DEVICE_LANG);
        m.put("device_color_depth", NOTE_DEVICE_COLOR_DEPTH);
        m.put("device_cpu_cores", NOTE_DEVICE_CPU_CORES);
        m.put("device_memory_gb", NOTE_DEVICE_MEMORY_GB);
        m.put("device_touch", NOTE_DEVICE_TOUCH);
        m.put("device_platform", NOTE_DEVICE_PLATFORM);
        m.put("device_connection", NOTE_DEVICE_CONNECTION);
        m.put("device_webgl_vendor", NOTE_DEVICE_WEBGL_VENDOR);
        m.put("device_webgl_renderer", NOTE_DEVICE_WEBGL_RENDERER);
        m.put("device_load_ms", NOTE_DEVICE_LOAD_MS);
        m.put("device_touch_points", NOTE_DEVICE_TOUCH_POINTS);
        m.put("device_orientation", NOTE_DEVICE_ORIENTATION);
        m.put("device_hash_perf_ms", NOTE_DEVICE_HASH_PERF_MS);
        m.put("device_math_hash", NOTE_DEVICE_MATH_HASH);
        m.put("device_fpu_class", NOTE_DEVICE_FPU_CLASS);
        m.put("device_math_anomaly", NOTE_DEVICE_MATH_ANOMALY);
        m.put("device_math_exec_ms", NOTE_DEVICE_MATH_EXEC_MS);
        m.put("device_math_consistency", NOTE_DEVICE_MATH_CONSISTENCY);
        FIELDS = Collections.unmodifiableMap(m);
        java.util.List<String> ev = new java.util.ArrayList<>();
        for (String field : m.keySet()) {
            if (!field.equals("device_binding") && !field.equals("device_timestamp") && !field.equals("device_signals")) ev.add(field);
        }
        ev.add("device_binding_result");
        EVENT_FIELDS = Collections.unmodifiableList(ev);
    }

    /**
     * The device details forwarded to Humifortis with an event: every signal except the binding
     * material and the raw component map, plus the server's binding verdict.
     */
    public static final java.util.List<String> EVENT_FIELDS;

    /** The binding material is verified here and never forwarded. */
    private static final java.util.Set<String> BINDING_FIELDS = java.util.Set.of("device_binding", "device_timestamp");

    private final Map<String, String> values;

    private DeviceSignals(Map<String, String> values) {
        this.values = values;
    }

    /**
     * Reads the device fields of a form POST. Returns {@code null} when the request carries no
     * device signal at all (the page did not run the collector script).
     */
    public static DeviceSignals fromForm(MultivaluedMap<String, String> form) {
        if (form == null) return null;
        Map<String, String> v = new LinkedHashMap<>();
        for (String field : FIELDS.keySet()) {
            String value = form.getFirst(field);
            if (value != null && !value.isBlank()) v.put(field, value.trim());
        }
        return v.containsKey("device_id") ? new DeviceSignals(v) : null;
    }

    public String get(String field) {
        return values.get(field);
    }

    public String deviceId() {
        return values.get("device_id");
    }

    /**
     * Recomputes the anti-replay binding: {@code SHA-256(nonce:timestamp:deviceId)} must equal the
     * submitted binding, and the submission must be fresh. Never throws.
     */
    public String validateBinding(String nonce, long nowMs) {
        try {
            String binding = values.get("device_binding"), ts = values.get("device_timestamp");
            if (binding == null || ts == null) return ABSENT;
            if (nonce == null || nonce.isBlank()) return ERROR;
            long clientTs = Long.parseLong(ts);
            if (Math.abs(nowMs - clientTs) > MAX_AGE_MS) return STALE;
            String expected = sha256Hex(nonce + ":" + ts + ":" + deviceId());
            return expected != null && expected.equalsIgnoreCase(binding) ? VALID : MISMATCH;
        } catch (NumberFormatException e) {
            return ERROR;
        } catch (Exception e) {
            return ERROR;
        }
    }

    /** Stores every signal (and the binding verdict) as auth notes — what the risk evaluator reads. */
    public void storeAsNotes(AuthenticationSessionModel session, String bindingResult) {
        values.forEach((field, value) -> session.setAuthNote(FIELDS.get(field), value));
        session.setAuthNote(NOTE_BINDING_RESULT, bindingResult);
    }

    /**
     * Writes the signals as event details ({@code device_*} keys) plus {@code device_binding_result}.
     * {@code includeRawSignals} adds the {@code device_signals} component map (up to ~2 KB) — sent to
     * Humifortis, but kept out of details Keycloak itself may persist.
     */
    public void writeEventDetails(BiConsumer<String, String> detail, String bindingResult, boolean includeRawSignals) {
        values.forEach((field, value) -> {
            if (BINDING_FIELDS.contains(field)) return;
            if (!includeRawSignals && field.equals("device_signals")) return;
            detail.accept(field, value);
        });
        detail.accept("device_binding_result", bindingResult);
    }

    static String sha256Hex(String input) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }
}

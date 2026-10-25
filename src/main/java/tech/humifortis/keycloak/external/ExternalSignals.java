package tech.humifortis.keycloak.external;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.jboss.logging.Logger;
import org.keycloak.models.UserModel;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Signals from outside the identity provider (docs/sso-and-external-idp-e2e.spec.md, P15, SG-1..SG-3). Each one sits behind
 * its own environment setting, is off without it, and fails open: a signal that cannot be read is absent, never a refusal.
 *
 * <pre>
 * HUMIFORTIS_SIM_SWAP_URL            a CAMARA SIM-swap check: POST {"phoneNumber":"+1...","maxAge":240} -> {"swapped":true|false}
 * HUMIFORTIS_SIM_SWAP_MAX_AGE_HOURS  how recent a swap counts (default 240, ten days)
 * HUMIFORTIS_NUMBER_VERIFICATION_URL a CAMARA number-verification check: POST {"phoneNumber":"+1..."} -> {"devicePhoneNumberVerified":true|false}
 * HUMIFORTIS_DEVICE_POSTURE_URL      an MDM compliance API: POST {"deviceId":"..."} -> {"status":"compliant|non_compliant|unknown"}
 * each of them: HUMIFORTIS_..._TOKEN (optional bearer token); https:// only, or http:// with HUMIFORTIS_ALLOW_INSECURE_HTTP=true
 * </pre>
 *
 * <p>What the signals do: a number that changed hands recently is not texted (the code would go to whoever holds the new SIM)
 * and the fact is evidence on the account; a number that was never verified is verified before the first text, and the
 * result is remembered on the user; the compliance of the device is an attribute the rules and the tenant's policies read.
 * Answers are kept five minutes: the sign-in never waits twice for the same question.</p>
 */
public final class ExternalSignals {

    private static final Logger LOG = Logger.getLogger(ExternalSignals.class);

    public static final String ENV_SIM_SWAP = "HUMIFORTIS_SIM_SWAP_URL";
    public static final String ENV_NUMBER_VERIFICATION = "HUMIFORTIS_NUMBER_VERIFICATION_URL";
    public static final String ENV_DEVICE_POSTURE = "HUMIFORTIS_DEVICE_POSTURE_URL";
    static final String ENV_SIM_SWAP_MAX_AGE = "HUMIFORTIS_SIM_SWAP_MAX_AGE_HOURS";
    static final int DEFAULT_MAX_AGE_HOURS = 240;
    static final long CACHE_MS = 300_000L;
    static final Duration TIMEOUT = Duration.ofMillis(1500);

    /** The user attribute that remembers the number that was verified. */
    public static final String ATTR_VERIFIED_NUMBER = "humifortis.verified_number";

    /** Posture values reported to core. */
    public static final String POSTURE_COMPLIANT = "compliant";
    public static final String POSTURE_NON_COMPLIANT = "non_compliant";
    public static final String POSTURE_UNKNOWN = "unknown";

    /** One question to an external service: the body posted as JSON, the JSON answer (or an exception). */
    public interface Transport {
        JsonObject post(String url, String token, Map<String, Object> body) throws Exception;
    }

    private static final Gson GSON = new Gson();
    private static final HttpClient CLIENT = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();
    private static final Transport HTTP = (url, token, body) -> {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url)).timeout(TIMEOUT)
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(body)));
        if (token != null && !token.isBlank()) request.header("Authorization", "Bearer " + token.trim());
        HttpResponse<String> response = CLIENT.send(request.build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() / 100 != 2) throw new IllegalStateException("HTTP " + response.statusCode());
        return JsonParser.parseString(response.body()).getAsJsonObject();
    };

    private record Cached(JsonObject value, long expires) {}

    private final Map<String, String> env;
    private final Transport transport;
    private final java.util.function.LongSupplier clock;
    private final ConcurrentHashMap<String, Cached> cache = new ConcurrentHashMap<>();

    public ExternalSignals(Map<String, String> env, Transport transport, java.util.function.LongSupplier clock) {
        this.env = env;
        this.transport = transport;
        this.clock = clock;
    }

    private static final ExternalSignals SHARED = new ExternalSignals(System.getenv(), HTTP, System::currentTimeMillis);

    /** The process-wide instance, reading the process environment. */
    public static ExternalSignals shared() {
        return SHARED;
    }

    /** The URL of a setting, or null when it is not set or not allowed. */
    String url(String name) {
        String url = env.get(name);
        if (url == null || url.isBlank()) return null;
        String lower = url.trim().toLowerCase(Locale.ROOT);
        boolean https = lower.startsWith("https://");
        boolean http = lower.startsWith("http://") && "true".equalsIgnoreCase(env.get("HUMIFORTIS_ALLOW_INSECURE_HTTP"));
        return https || http ? url.trim() : null;
    }

    private JsonObject ask(String setting, Map<String, Object> body, String cacheKey) {
        String url = url(setting);
        if (url == null) return null;
        long now = clock.getAsLong();
        Cached hit = cache.get(setting + "|" + cacheKey);
        if (hit != null && hit.expires() > now) return hit.value();
        try {
            JsonObject answer = transport.post(url, env.get(setting.replace("_URL", "_TOKEN")), body);
            if (cache.size() > 10_000) cache.clear();
            cache.put(setting + "|" + cacheKey, new Cached(answer, now + CACHE_MS));
            return answer;
        } catch (Exception e) {
            LOG.debugf("[Humifortis] %s unavailable (fail-open): %s", setting, e.getMessage());
            return null; // a failure is not cached: the next sign-in asks again
        }
    }

    private static Boolean flag(JsonObject answer, String field) {
        if (answer == null || !answer.has(field) || !answer.get(field).isJsonPrimitive() || !answer.get(field).getAsJsonPrimitive().isBoolean()) return null;
        return answer.get(field).getAsBoolean();
    }

    /** Whether the number changed hands recently; null when no check is configured or it did not answer. */
    public Boolean simSwappedRecently(String phone) {
        if (phone == null) return null;
        int maxAge = DEFAULT_MAX_AGE_HOURS;
        try {
            String raw = env.get(ENV_SIM_SWAP_MAX_AGE);
            if (raw != null && !raw.isBlank()) maxAge = Math.max(1, Integer.parseInt(raw.trim()));
        } catch (NumberFormatException ignored) {
            // the default stands
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("phoneNumber", phone);
        body.put("maxAge", maxAge);
        return flag(ask(ENV_SIM_SWAP, body, phone), "swapped");
    }

    /** Whether the number is the one of the device making the request; null when no check is configured or it did not answer. */
    public Boolean numberVerified(String phone) {
        if (phone == null) return null;
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("phoneNumber", phone);
        return flag(ask(ENV_NUMBER_VERIFICATION, body, phone), "devicePhoneNumberVerified");
    }

    /** The compliance of a device: compliant | non_compliant | unknown; null when no check is configured or it did not answer. */
    public String devicePosture(String deviceId) {
        if (deviceId == null || deviceId.isBlank()) return null;
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("deviceId", deviceId);
        JsonObject answer = ask(ENV_DEVICE_POSTURE, body, deviceId);
        if (answer == null || !answer.has("status") || !answer.get("status").isJsonPrimitive()) return null;
        String status = answer.get("status").getAsString().trim().toLowerCase(Locale.ROOT).replace('-', '_');
        return switch (status) {
            case POSTURE_COMPLIANT, POSTURE_NON_COMPLIANT, POSTURE_UNKNOWN -> status;
            default -> null;
        };
    }

    /**
     * Whether this person may be texted at this number: not when the number changed hands recently, and not before the number
     * was verified (a verified number is remembered on the user). A check that is off or did not answer lets the text go.
     */
    public boolean mayText(UserModel user, String phone) {
        if (phone == null) return false;
        if (Boolean.TRUE.equals(simSwappedRecently(phone))) {
            LOG.infof("[Humifortis] SIM swap on the number of %s: no text message is sent", user != null ? user.getUsername() : "?");
            return false;
        }
        if (url(ENV_NUMBER_VERIFICATION) == null || user == null) return true;
        if (phone.equals(user.getFirstAttribute(ATTR_VERIFIED_NUMBER))) return true;
        Boolean verified = numberVerified(phone);
        if (verified == null) return true; // not answering is not a refusal
        if (verified) {
            try {
                user.setSingleAttribute(ATTR_VERIFIED_NUMBER, phone);
            } catch (RuntimeException e) {
                LOG.debugf("[Humifortis] the verified number could not be remembered: %s", e.getMessage());
            }
        }
        return verified;
    }
}

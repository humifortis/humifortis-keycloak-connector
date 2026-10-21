package tech.humifortis.keycloak.auth;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

import org.keycloak.models.UserModel;

import com.google.gson.Gson;

/**
 * The text-message channel of the step-up router. Humifortis does not send texts itself: it posts one JSON message to the
 * operator's own gateway, which delivers it.
 *
 * <pre>
 * HUMIFORTIS_SMS_GATEWAY_URL        where to post: https://... (http:// only with HUMIFORTIS_ALLOW_INSECURE_HTTP=true)
 * HUMIFORTIS_SMS_GATEWAY_TOKEN      optional bearer token sent as Authorization
 * HUMIFORTIS_SMS_PHONE_ATTRIBUTE    the user attribute holding the number (default phoneNumber)
 * </pre>
 *
 * The request is {@code POST <url>} with {@code {"to":"+15145550100","message":"..."}}; any 2xx answer is a delivery
 * accepted. Without the URL the channel does not exist: no person is offered a text, nothing changes.
 */
public final class SmsGateway {

    static final String ENV_URL = "HUMIFORTIS_SMS_GATEWAY_URL";
    static final String ENV_TOKEN = "HUMIFORTIS_SMS_GATEWAY_TOKEN";
    static final String ENV_ATTRIBUTE = "HUMIFORTIS_SMS_PHONE_ATTRIBUTE";
    static final String DEFAULT_ATTRIBUTE = "phoneNumber";

    /** E.164: a plus and 8 to 15 digits. A number in any other form is not texted. */
    private static final Pattern E164 = Pattern.compile("^\\+[1-9][0-9]{7,14}$");
    private static final Gson GSON = new Gson();
    private static final HttpClient CLIENT = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();

    /** The delivery failed: the person is not texted, and the router chooses another factor or refuses. */
    public static class SmsException extends RuntimeException {
        public SmsException(String message) {
            super(message);
        }
    }

    private SmsGateway() {}

    /** The gateway URL, or null when the channel is not configured or the URL is not allowed. */
    static String url(Map<String, String> env) {
        String url = env.get(ENV_URL);
        if (url == null || url.isBlank()) return null;
        String lower = url.trim().toLowerCase(Locale.ROOT);
        boolean https = lower.startsWith("https://");
        boolean http = lower.startsWith("http://") && "true".equalsIgnoreCase(env.get("HUMIFORTIS_ALLOW_INSECURE_HTTP"));
        return https || http ? url.trim() : null;
    }

    /** The number of the person in E.164, or null when there is none (or it is not one). */
    static String phoneOf(UserModel user, Map<String, String> env) {
        if (user == null) return null;
        String attribute = env.getOrDefault(ENV_ATTRIBUTE, DEFAULT_ATTRIBUTE);
        String raw = user.getFirstAttribute(attribute == null || attribute.isBlank() ? DEFAULT_ATTRIBUTE : attribute.trim());
        if (raw == null) return null;
        String number = raw.replaceAll("[\\s().-]", "");
        return E164.matcher(number).matches() ? number : null;
    }

    /** Whether this person can be texted: a gateway is configured and she has a usable number. */
    public static boolean canText(UserModel user) {
        Map<String, String> env = System.getenv();
        return url(env) != null && phoneOf(user, env) != null;
    }

    /** The number as shown to the person and logged: the country code and the last two digits only. */
    public static String mask(String phone) {
        if (phone == null || phone.length() < 6) return "***";
        return phone.substring(0, 2) + "*".repeat(phone.length() - 4) + phone.substring(phone.length() - 2);
    }

    /** The masked number of this person, or {@code ***}. */
    public static String maskedPhoneOf(UserModel user) {
        return mask(phoneOf(user, System.getenv()));
    }

    /** Sends the code to the person; throws {@link SmsException} when it cannot be delivered. */
    public static void send(UserModel user, String message) {
        send(user, message, System.getenv());
    }

    static void send(UserModel user, String message, Map<String, String> env) {
        String url = url(env);
        String to = phoneOf(user, env);
        if (url == null) throw new SmsException("SMS gateway not configured");
        if (to == null) throw new SmsException("no usable phone number");
        try {
            Map<String, String> body = new LinkedHashMap<>();
            body.put("to", to);
            body.put("message", message);
            HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(3))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(body)));
            String token = env.get(ENV_TOKEN);
            if (token != null && !token.isBlank()) request.header("Authorization", "Bearer " + token.trim());
            HttpResponse<Void> response = CLIENT.send(request.build(), HttpResponse.BodyHandlers.discarding());
            if (response.statusCode() / 100 != 2) throw new SmsException("gateway answered HTTP " + response.statusCode());
        } catch (SmsException e) {
            throw e;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SmsException("interrupted");
        } catch (Exception e) {
            throw new SmsException("gateway unreachable: " + e.getClass().getSimpleName());
        }
    }
}

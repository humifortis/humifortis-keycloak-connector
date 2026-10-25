package tech.humifortis.keycloak.mapper;

import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.keycloak.events.Event;
import org.keycloak.events.EventType;

import tech.humifortis.keycloak.model.HumifortisEvent;

/**
 * The events of the token endpoints and of the device authorization grant that are evidence for Humifortis
 * (docs/sso-and-external-idp-e2e.spec.md, P11, P12, P14): which Keycloak events are forwarded, under which name, and which
 * of them are not worth sending.
 *
 * <ul>
 *   <li>A refresh, a token exchange and an introspection are sent as events of the person the token belongs to
 *       ({@code auth_token_refresh}, {@code auth_token_exchange}, {@code auth_token_introspect} and their failures); the
 *       rules of the core weigh them.</li>
 *   <li>The token events of a <em>service account's</em> own Keycloak user are not sent: the service account is the client,
 *       reported by its client logins, and its user must never become a person.</li>
 *   <li>A resource server introspects the token of every call it receives. One introspection per person and application per
 *       minute is sent: the first, which is all the evidence there is in the rest.</li>
 *   <li>A token that is bound to a key (DPoP) and presented without the proof of that key is {@code auth_token_binding_failed},
 *       whatever endpoint refused it: it is what the thief of a bound token does.</li>
 *   <li>A wrong user code on the verification page of the device grant is a fact about the application that is attacked,
 *       not about a person (nobody has signed in yet): a feedback event of the integration.</li>
 * </ul>
 */
public final class TokenEvents {

    public static final String BINDING_FAILED = "auth_token_binding_failed";
    public static final String DEVICE_TOKEN_ISSUED = "auth_device_token_issued";
    public static final String TOKEN_EXCHANGE_FAILED = "auth_token_exchange_failed";
    /** The feedback event of a wrong user code on a device verification page (core: audit and operational alert). */
    public static final String DEVICE_USER_CODE_FAILED = "device_user_code_failed";

    /** One introspection per (realm, person or client, application) in this window is sent. */
    static final long INTROSPECTION_WINDOW_MS = 60_000L;
    private static final int SAMPLER_MAX_KEYS = 20_000;
    private static final ConcurrentHashMap<String, Long> LAST_INTROSPECTION = new ConcurrentHashMap<>();

    /** The Keycloak events this class adds to the ones the listener already monitors. */
    public static final Set<EventType> MONITORED = Set.of(
            EventType.REFRESH_TOKEN,
            EventType.TOKEN_EXCHANGE,
            EventType.TOKEN_EXCHANGE_ERROR,
            EventType.INTROSPECT_TOKEN,
            EventType.INTROSPECT_TOKEN_ERROR,
            // a resource server refusing a token: only when the refusal is a binding failure
            EventType.USER_INFO_REQUEST_ERROR,
            EventType.OAUTH2_DEVICE_CODE_TO_TOKEN,
            EventType.OAUTH2_DEVICE_VERIFY_USER_CODE_ERROR);

    private static final Set<EventType> ERRORS_THAT_CAN_BE_A_BINDING_FAILURE = Set.of(
            EventType.CODE_TO_TOKEN_ERROR, EventType.REFRESH_TOKEN_ERROR, EventType.TOKEN_EXCHANGE_ERROR,
            EventType.INTROSPECT_TOKEN_ERROR, EventType.USER_INFO_REQUEST_ERROR);

    private TokenEvents() {}

    /**
     * What Keycloak says about the refusal: its error, and its reason (a user-info refusal is the error invalid_token with the
     * reason "DPoP proof is missing").
     */
    public static String refusal(Event event) {
        String reason = event.getDetails() == null ? null : event.getDetails().get("reason");
        String error = event.getError();
        if (reason == null) return error;
        return error == null ? reason : error + " " + reason;
    }

    /** Whether Keycloak's error is the refusal of a DPoP proof (the proof is missing, expired, replayed or of another key). */
    public static boolean isBindingFailure(String error) {
        return error != null && error.toLowerCase(Locale.ROOT).contains("dpop");
    }

    /**
     * The name Humifortis gives the event when it is not the default one, or null. A service account's own client login keeps
     * its name: it is judged as a client authentication, not as a person's token.
     */
    public static String eventTypeOf(EventType type, String error, boolean serviceAccount) {
        if (type == null || serviceAccount) return null;
        if (ERRORS_THAT_CAN_BE_A_BINDING_FAILURE.contains(type) && isBindingFailure(error)) return BINDING_FAILED;
        return switch (type) {
            case OAUTH2_DEVICE_CODE_TO_TOKEN -> DEVICE_TOKEN_ISSUED;
            case TOKEN_EXCHANGE_ERROR -> TOKEN_EXCHANGE_FAILED;
            default -> null;
        };
    }

    /**
     * Whether the event is sent. Called for the events of {@link #MONITORED} only.
     *
     * @param serviceAccountUser the event is the token event of a service account's own Keycloak user
     * @param nowMillis          the time, for the sampling of introspections
     */
    public static boolean accepts(Event event, boolean serviceAccountUser, long nowMillis) {
        EventType type = event.getType();
        if (type == EventType.OAUTH2_DEVICE_VERIFY_USER_CODE_ERROR) return true; // no user: reported against the application
        if (serviceAccountUser) return false;
        if (type == EventType.USER_INFO_REQUEST_ERROR) return isBindingFailure(refusal(event));
        if (type == EventType.INTROSPECT_TOKEN || type == EventType.INTROSPECT_TOKEN_ERROR) {
            // a binding failure is never sampled away
            return isBindingFailure(refusal(event)) || firstIntrospectionInWindow(event, nowMillis);
        }
        return true;
    }

    static boolean firstIntrospectionInWindow(Event event, long nowMillis) {
        String key = event.getRealmId() + "|" + event.getUserId() + "|" + event.getClientId() + "|" + event.getType();
        if (LAST_INTROSPECTION.size() > SAMPLER_MAX_KEYS) {
            LAST_INTROSPECTION.entrySet().removeIf(e -> nowMillis - e.getValue() >= INTROSPECTION_WINDOW_MS);
            if (LAST_INTROSPECTION.size() > SAMPLER_MAX_KEYS) LAST_INTROSPECTION.clear();
        }
        boolean[] first = {false};
        LAST_INTROSPECTION.compute(key, (k, last) -> {
            if (last == null || nowMillis - last >= INTROSPECTION_WINDOW_MS) {
                first[0] = true;
                return nowMillis;
            }
            return last;
        });
        return first[0];
    }

    /** Test hook of the sampler's state. */
    static void resetSampler() {
        LAST_INTROSPECTION.clear();
    }

    /** Whether Keycloak's event is a wrong user code on a device verification page. */
    public static boolean isDeviceUserCodeFailure(EventType type) {
        return type == EventType.OAUTH2_DEVICE_VERIFY_USER_CODE_ERROR;
    }

    /**
     * The feedback event of a wrong user code: about the integration and the application, never about a person. Keycloak's
     * event has no user (nobody has signed in yet).
     */
    public static HumifortisEvent deviceUserCodeFailure(Event event) {
        HumifortisEvent e = new HumifortisEvent();
        String realmId = event.getRealmId() != null ? event.getRealmId() : "unknown";
        e.setEntityId(ProviderFailure.INTEGRATION_ENTITY_ID);
        e.setEntityType(ProviderFailure.INTEGRATION_ENTITY_TYPE);
        e.setTimestamp(Instant.ofEpochMilli(event.getTime()).toString());
        e.setEventType(DEVICE_USER_CODE_FAILED);
        e.setSource("keycloak");
        if (event.getId() != null) e.setEventId(event.getId());
        Map<String, String> details = event.getDetails();
        String flow = details != null ? details.get("code_id") : null;
        e.setFlowId(flow != null && !flow.isBlank() ? flow : event.getId());
        e.addMetadata("realm", realmId);
        if (event.getClientId() != null) e.addMetadata("client_id", event.getClientId());
        String ip = event.getIpAddress() != null ? event.getIpAddress() : details != null ? details.get("ip") : null;
        if (ip != null) e.addMetadata("ip", ip);
        if (event.getError() != null) e.addMetadata("failure_code", event.getError());
        return e;
    }
}

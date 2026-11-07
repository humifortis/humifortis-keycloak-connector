package tech.humifortis.keycloak.client;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jboss.logging.Logger;

/**
 * The access token of the connector: OAuth2 client credentials, the API key being the client secret. One cached token per
 * endpoint, refreshed before it ends, fetched once however many threads ask. The fetch goes through the transport, so it has
 * its retries, jittered backoff and circuit breaker like every call. When no token can be had — the endpoint is unreachable, or
 * an older Humifortis does not know the token endpoint — {@link #bearer()} answers null and the caller uses the API key: the
 * authentication never makes a login fail that the key would have served.
 */
public final class TokenSource {
    private static final Logger logger = Logger.getLogger(TokenSource.class);
    private static final Map<String, TokenSource> SHARED = new ConcurrentHashMap<>();
    private static final Pattern TOKEN = Pattern.compile("\"access_token\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern EXPIRES = Pattern.compile("\"expires_in\"\\s*:\\s*(\\d+)");

    /** A token is replaced this long before it ends. */
    static final long REFRESH_BEFORE_MS = 60_000;
    /** After a transient failure, the next attempt waits this long (the key serves meanwhile). */
    static final long RETRY_AFTER_TRANSIENT_MS = 5_000;
    /** After the endpoint refused or does not know the request, the next attempt waits this long. */
    static final long RETRY_AFTER_REFUSED_MS = 300_000;

    private final Supplier<HumifortisTransport.Result> fetch;
    private final LongSupplier clock;

    private String token;
    /** The token replaced by the last {@link #renew}: a thread refused with it gets the new one, not a second renewal. */
    private String previous;
    private long expiresAtMs;
    private long notBeforeMs;

    TokenSource(Supplier<HumifortisTransport.Result> fetch, LongSupplier clock) {
        this.fetch = fetch;
        this.clock = clock;
    }

    /** The token source of this endpoint, shared process-wide. */
    public static TokenSource shared(SaasConfig config) {
        String key = config.getApiUrl() + "|" + config.getClientId() + "|" + config.getMtlsCert();
        return SHARED.computeIfAbsent(key, k -> new TokenSource(() -> request(config), System::currentTimeMillis));
    }

    private static HumifortisTransport.Result request(SaasConfig config) {
        String form = "grant_type=client_credentials"
                + "&client_id=" + URLEncoder.encode(config.getClientId(), StandardCharsets.UTF_8)
                + "&client_secret=" + URLEncoder.encode(config.getClientSecret(), StandardCharsets.UTF_8);
        HttpRequest.Builder b = HttpRequest.newBuilder()
                .uri(URI.create(config.getApiUrl() + "/oauth2/token"))
                .header("Accept", "application/json")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("X-Connector-Type", "keycloak")
                .POST(HttpRequest.BodyPublishers.ofString(form));
        return HumifortisTransport.shared(config).send(b, RetryPolicy.token(config), null);
    }

    /** A valid access token, or null when the caller should use the API key. */
    public synchronized String bearer() {
        long now = clock.getAsLong();
        if (token != null && now < expiresAtMs - REFRESH_BEFORE_MS) return token;
        if (now < notBeforeMs) return stillValid(now);

        HumifortisTransport.Result r = fetch.get();
        now = clock.getAsLong();
        if (r.ok()) {
            Matcher t = TOKEN.matcher(r.body() == null ? "" : r.body());
            if (t.find()) {
                Matcher e = EXPIRES.matcher(r.body());
                long seconds = e.find() ? Long.parseLong(e.group(1)) : 300;
                token = t.group(1);
                expiresAtMs = now + seconds * 1000;
                notBeforeMs = 0;
                return token;
            }
        }
        // a 4xx is a refusal (wrong client, or a Humifortis without the endpoint): do not ask again at every call
        boolean refused = r.failure() == HumifortisTransport.Failure.HTTP_4XX && r.status() != 429;
        notBeforeMs = now + (refused ? RETRY_AFTER_REFUSED_MS : RETRY_AFTER_TRANSIENT_MS);
        if (refused) logger.warnf("[Humifortis] the token endpoint answered %d: authenticating with the API key", r.status());
        return stillValid(now);
    }

    /**
     * The token to use after the API refused {@code refused} (401) before it ended: its signing key was retired, or the server no
     * longer accepts it. The refused token is dropped and a new one is fetched at once, once for all the threads refused together
     * (a caller that comes after the renewal gets the new token). Null when no token can be had: the caller keeps the API's answer.
     */
    public synchronized String renew(String refused) {
        if (refused == null) return null;
        if (refused.equals(token)) {
            previous = token;
            token = null;
            expiresAtMs = 0;
            notBeforeMs = 0;
        } else if (!refused.equals(previous)) {
            return null; // not a token of this source
        }
        return bearer();
    }

    /** {@link #renew} on the shared source that issued {@code refused}; null when none did. */
    static String renewShared(String refused) {
        for (TokenSource s : SHARED.values()) {
            String renewed = s.renew(refused);
            if (renewed != null) return renewed;
        }
        return null;
    }

    /** The cached token while it has not ended, even past its refresh time: better than falling back when a refresh failed. */
    private String stillValid(long now) {
        return token != null && now < expiresAtMs ? token : null;
    }
}

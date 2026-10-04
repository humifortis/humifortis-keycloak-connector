package tech.humifortis.keycloak.client;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.LongSupplier;
import java.util.function.LongUnaryOperator;

import org.jboss.logging.Logger;

/**
 * Every call to the Humifortis API goes through here: one HTTP client and one circuit breaker
 * per API endpoint (shared by all realms and threads), retries with jittered exponential
 * backoff inside the call's budget, and the same Idempotency-Key on every attempt of a call.
 */
public final class HumifortisTransport {
    private static final Logger logger = Logger.getLogger(HumifortisTransport.class);
    static final String CONNECTOR_VERSION = "1.1.0";

    private static final Map<String, HumifortisTransport> SHARED = new ConcurrentHashMap<>();

    /** Why a call did not get an answer. */
    public enum Failure {
        NONE, CIRCUIT_OPEN, TIMEOUT, CONNECT, HTTP_5XX, HTTP_4XX, INTERRUPTED, ERROR;

        /** The fallback_reason reported for a login decided without Humifortis. */
        public String reason() {
            return switch (this) {
                case CIRCUIT_OPEN -> "circuit_open";
                case TIMEOUT -> "timeout";
                case CONNECT -> "unreachable";
                case HTTP_5XX -> "http_5xx";
                case HTTP_4XX -> "http_4xx";
                case INTERRUPTED -> "interrupted";
                case ERROR -> "error";
                case NONE -> "none";
            };
        }
    }

    /** The outcome of a call: the final status and body, or why there was none. */
    public record Result(int status, String body, Failure failure, int attempts) {
        public boolean ok() { return failure == Failure.NONE && status >= 200 && status < 300; }
    }

    /** One HTTP exchange — the real client, or a stub in tests. */
    public interface Sender {
        Response send(HttpRequest request) throws IOException, InterruptedException;
    }

    public record Response(int status, String body, String retryAfter) {}

    public interface Sleeper {
        void sleep(long millis) throws InterruptedException;
    }

    private final Sender sender;
    private final CircuitBreaker breaker;
    private final LongSupplier clock;
    private final Sleeper sleeper;
    private final LongUnaryOperator random;

    public HumifortisTransport(Sender sender, CircuitBreaker breaker, LongSupplier clock, Sleeper sleeper, LongUnaryOperator random) {
        this.sender = sender;
        this.breaker = breaker;
        this.clock = clock;
        this.sleeper = sleeper;
        this.random = random;
    }

    /** The transport of this endpoint, shared process-wide. */
    public static HumifortisTransport shared(SaasConfig config) {
        String key = config.getApiUrl() + "|" + config.isInsecureSsl() + "|" + config.getInsecureSslCertSha256();
        return SHARED.computeIfAbsent(key, k -> {
            HttpClient client = HttpClientFactory.create(config.getTimeoutMs(), config.isInsecureSsl(), config.getInsecureSslCertSha256());
            Sender sender = request -> {
                HttpResponse<String> r = client.send(request, HttpResponse.BodyHandlers.ofString());
                return new Response(r.statusCode(), r.body(), r.headers().firstValue("Retry-After").orElse(null));
            };
            return new HumifortisTransport(sender, CircuitBreaker.standard(config.getApiUrl()),
                    System::currentTimeMillis, Thread::sleep, bound -> ThreadLocalRandom.current().nextLong(bound));
        });
    }

    public CircuitBreaker breaker() { return breaker; }

    /** A JSON POST to {@code apiUrl + path} with the connector's standard headers. */
    public static HttpRequest.Builder jsonPost(SaasConfig config, String path, String tenantId, String json) {
        HttpRequest.Builder b = HttpRequest.newBuilder()
                .uri(URI.create(config.getApiUrl() + path))
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .header("X-API-Key", config.getApiKey())
                .header("X-Connector-Type", "keycloak")
                .header("X-Connector-Version", CONNECTOR_VERSION)
                .POST(HttpRequest.BodyPublishers.ofString(json));
        if (tenantId != null && !tenantId.isBlank()) b.header("X-Tenant-ID", tenantId);
        return b;
    }

    /**
     * Sends {@code request} under {@code policy}. The builder is completed per attempt with the
     * attempt's timeout and the call's Idempotency-Key. Never throws.
     */
    public Result send(HttpRequest.Builder request, RetryPolicy policy, String idempotencyKey) {
        if (!breaker.allowRequest()) {
            return new Result(0, null, Failure.CIRCUIT_OPEN, 0);
        }
        long deadline = clock.getAsLong() + policy.totalBudgetMs();
        if (idempotencyKey != null) request.setHeader("Idempotency-Key", idempotencyKey);

        Failure last = Failure.ERROR;
        int lastStatus = 0;
        String lastBody = null;
        int attempts = 0;
        for (int attempt = 0; attempt < policy.maxAttempts(); attempt++) {
            long remaining = deadline - clock.getAsLong();
            if (remaining < RetryPolicy.MIN_ATTEMPT_MS) break;
            attempts++;
            long retryAfterMs = 0;
            try {
                Response r = sender.send(request.timeout(Duration.ofMillis(Math.min(policy.attemptTimeoutMs(), remaining))).build());
                lastStatus = r.status();
                lastBody = r.body();
                if (r.status() >= 200 && r.status() < 300) {
                    breaker.onSuccess();
                    return new Result(r.status(), r.body(), Failure.NONE, attempts);
                }
                if (!RetryPolicy.isRetryableStatus(r.status())) {
                    if (r.status() >= 500) {
                        breaker.onFailure();
                        return new Result(r.status(), r.body(), Failure.HTTP_5XX, attempts);
                    }
                    breaker.onSuccess(); // the API answered: a bad request is not an outage
                    return new Result(r.status(), r.body(), Failure.HTTP_4XX, attempts);
                }
                last = r.status() == 429 ? Failure.HTTP_4XX : Failure.HTTP_5XX;
                retryAfterMs = parseRetryAfterMs(r.retryAfter());
                if (retryAfterMs > deadline - clock.getAsLong()) break; // the server asks to wait longer than we can
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return new Result(0, null, Failure.INTERRUPTED, attempts);
            } catch (HttpTimeoutException e) {
                last = Failure.TIMEOUT;
            } catch (IOException e) {
                last = Failure.CONNECT;
            } catch (RuntimeException e) {
                logger.debugf("[Humifortis] request failed: %s", e.getMessage());
                last = Failure.ERROR;
                break; // a malformed request will not get better
            }
            if (attempt + 1 >= policy.maxAttempts()) break;
            long wait = Math.max(retryAfterMs, policy.backoffMs(attempt, random));
            long room = deadline - clock.getAsLong() - RetryPolicy.MIN_ATTEMPT_MS;
            if (room <= 0) break;
            try {
                sleeper.sleep(Math.min(wait, room));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return new Result(0, null, Failure.INTERRUPTED, attempts);
            }
        }
        breaker.onFailure();
        return new Result(lastStatus, lastBody, last, attempts);
    }

    /** Retry-After in delta-seconds (HTTP-date is not used by the API). */
    static long parseRetryAfterMs(String value) {
        if (value == null || value.isBlank()) return 0;
        try {
            long seconds = Long.parseLong(value.trim());
            return seconds > 0 ? seconds * 1000 : 0;
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}

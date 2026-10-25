package tech.humifortis.keycloak.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpTimeoutException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;

class HumifortisTransportTest {

    /** A fake clock that advances only when the transport sleeps or an attempt "takes time". */
    static final class FakeTime {
        final AtomicLong now = new AtomicLong(1_000_000);
        final List<Long> sleeps = new ArrayList<>();
        long millis() { return now.get(); }
        void sleep(long ms) { sleeps.add(ms); now.addAndGet(ms); }
    }

    /** Scripted answers: an Integer is an HTTP status, an Exception is thrown. */
    static final class Script implements HumifortisTransport.Sender {
        final Deque<Object> steps = new ArrayDeque<>();
        final List<HttpRequest> requests = new ArrayList<>();
        final FakeTime time;
        final long attemptCostMs;
        Script(FakeTime time, long attemptCostMs, Object... steps) {
            this.time = time;
            this.attemptCostMs = attemptCostMs;
            this.steps.addAll(List.of(steps));
        }
        @Override
        public HumifortisTransport.Response send(HttpRequest request) throws IOException {
            requests.add(request);
            // an attempt never outlives its timeout (the HTTP client aborts it)
            time.now.addAndGet(Math.min(attemptCostMs, request.timeout().map(d -> d.toMillis()).orElse(attemptCostMs)));
            Object next = steps.isEmpty() ? 200 : steps.pollFirst();
            if (next instanceof IOException e) throw e;
            if (next instanceof String retryAfter) return new HumifortisTransport.Response(429, "", retryAfter);
            return new HumifortisTransport.Response((Integer) next, "{\"ok\":true}", null);
        }
    }

    static HumifortisTransport transport(FakeTime time, Script script, CircuitBreaker breaker) {
        return new HumifortisTransport(script, breaker, time::millis, time::sleep, bound -> bound / 2);
    }

    static CircuitBreaker breaker(FakeTime time) {
        return new CircuitBreaker("test", 5, 10_000, 120_000, time::millis);
    }

    static HttpRequest.Builder request() {
        return HttpRequest.newBuilder().uri(URI.create("https://api.example/evaluate")).POST(HttpRequest.BodyPublishers.ofString("{}"));
    }

    static final RetryPolicy EVALUATE = new RetryPolicy(3, 50, 400, 1500, 800);

    @Test
    void backoffIsFullJitterAndBounded() {
        Random seeded = new Random(42);
        for (int retry = 0; retry < 8; retry++) {
            long cap = Math.min(400, 50L << retry);
            for (int i = 0; i < 10_000; i++) {
                long d = EVALUATE.backoffMs(retry, bound -> (long) (seeded.nextDouble() * bound));
                assertTrue(d >= 0 && d <= cap, "retry " + retry + " delay " + d + " outside [0," + cap + "]");
            }
        }
    }

    @Test
    void retriesThenSucceeds_withOneIdempotencyKeyForEveryAttempt() {
        FakeTime time = new FakeTime();
        Script script = new Script(time, 10, 503, new ConnectException("refused"), 200);
        HumifortisTransport.Result r = transport(time, script, breaker(time)).send(request(), EVALUATE, "key-1");
        assertTrue(r.ok());
        assertEquals(3, r.attempts());
        Set<String> keys = new HashSet<>();
        script.requests.forEach(req -> keys.add(req.headers().firstValue("Idempotency-Key").orElse("none")));
        assertEquals(Set.of("key-1"), keys, "every attempt of one call carries the same key");
    }

    @Test
    void neverExceedsTheBudget_evenWhenEveryAttemptTimesOut() {
        FakeTime time = new FakeTime();
        Script script = new Script(time, 700, new HttpTimeoutException("t"), new HttpTimeoutException("t"), new HttpTimeoutException("t"));
        long start = time.millis();
        HumifortisTransport.Result r = transport(time, script, breaker(time)).send(request(), EVALUATE, "k");
        assertFalse(r.ok());
        assertEquals(HumifortisTransport.Failure.TIMEOUT, r.failure());
        assertTrue(time.millis() - start <= 1500, "elapsed " + (time.millis() - start));
        assertTrue(r.attempts() <= 3);
        // the per-attempt timeout never exceeds what is left of the budget
        for (HttpRequest req : script.requests) {
            assertTrue(req.timeout().orElseThrow().toMillis() <= 800);
        }
    }

    @Test
    void doesNotRetryAClientError() {
        for (int status : new int[]{400, 401, 403, 422}) {
            FakeTime time = new FakeTime();
            Script script = new Script(time, 5, status);
            HumifortisTransport.Result r = transport(time, script, breaker(time)).send(request(), EVALUATE, "k");
            assertEquals(1, r.attempts(), "HTTP " + status);
            assertEquals(HumifortisTransport.Failure.HTTP_4XX, r.failure());
        }
    }

    @Test
    void doesNotRetryAnInternalError() {
        FakeTime time = new FakeTime();
        Script script = new Script(time, 5, 500, 200);
        HumifortisTransport.Result r = transport(time, script, breaker(time)).send(request(), EVALUATE, "k");
        assertEquals(1, r.attempts());
        assertEquals(HumifortisTransport.Failure.HTTP_5XX, r.failure());
    }

    @Test
    void honoursRetryAfterWithinTheBudget() {
        FakeTime time = new FakeTime();
        RetryPolicy events = new RetryPolicy(4, 250, 4000, 15_000, 2000);
        Script script = new Script(time, 5, "2", 200);
        HumifortisTransport.Result r = transport(time, script, breaker(time)).send(request(), events, "k");
        assertTrue(r.ok());
        assertEquals(2000L, time.sleeps.get(0), "waited what the server asked");
    }

    @Test
    void stopsWhenRetryAfterExceedsTheBudget() {
        FakeTime time = new FakeTime();
        Script script = new Script(time, 5, "30", 200);
        HumifortisTransport.Result r = transport(time, script, breaker(time)).send(request(), EVALUATE, "k");
        assertFalse(r.ok());
        assertEquals(1, r.attempts());
        assertTrue(time.sleeps.isEmpty());
    }

    @Test
    void anOpenCircuitRefusesWithoutCalling() {
        FakeTime time = new FakeTime();
        CircuitBreaker b = new CircuitBreaker("t", 1, 10_000, 120_000, time::millis);
        b.onFailure();
        Script script = new Script(time, 5, 200);
        HumifortisTransport.Result r = transport(time, script, b).send(request(), EVALUATE, "k");
        assertEquals(HumifortisTransport.Failure.CIRCUIT_OPEN, r.failure());
        assertTrue(script.requests.isEmpty());
    }

    // ── circuit breaker ───────────────────────────────────────────────────────

    @Test
    void breakerOpensAfterThresholdAndAFourXxDoesNotCount() {
        FakeTime time = new FakeTime();
        CircuitBreaker b = breaker(time);
        for (int i = 0; i < 4; i++) b.onFailure();
        b.onSuccess(); // a 4xx is reported as success: the API answered
        for (int i = 0; i < 4; i++) b.onFailure();
        assertEquals(CircuitBreaker.State.CLOSED, b.state());
        b.onFailure();
        assertEquals(CircuitBreaker.State.OPEN, b.state());
        assertFalse(b.allowRequest());
    }

    @Test
    void openDurationDoublesOnFailedProbesAndIsCapped() {
        FakeTime time = new FakeTime();
        CircuitBreaker b = new CircuitBreaker("t", 1, 10_000, 120_000, time::millis);
        b.onFailure();
        long[] expected = {20_000, 40_000, 80_000, 120_000, 120_000};
        long open = 10_000;
        for (long next : expected) {
            time.now.addAndGet(open);
            assertTrue(b.allowRequest(), "probe after " + open);
            b.onFailure();
            assertEquals(next, b.millisUntilProbe());
            open = next;
        }
        time.now.addAndGet(open);
        assertTrue(b.allowRequest());
        b.onSuccess();
        assertEquals(CircuitBreaker.State.CLOSED, b.state());
    }

    @Test
    void halfOpenLetsExactlyOneProbeThrough() throws Exception {
        FakeTime time = new FakeTime();
        CircuitBreaker b = new CircuitBreaker("t", 1, 10_000, 120_000, time::millis);
        b.onFailure();
        time.now.addAndGet(10_000);
        ExecutorService pool = Executors.newFixedThreadPool(16);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger allowed = new AtomicInteger();
        for (int i = 0; i < 50; i++) {
            pool.submit(() -> {
                go.await();
                if (b.allowRequest()) allowed.incrementAndGet();
                return null;
            });
        }
        go.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        assertEquals(1, allowed.get());
    }

    @Test
    void aLostProbeDoesNotKeepTheBreakerHalfOpenForever() {
        FakeTime time = new FakeTime();
        CircuitBreaker b = new CircuitBreaker("t", 1, 10_000, 120_000, time::millis);
        b.onFailure();
        time.now.addAndGet(10_000);
        assertTrue(b.allowRequest());
        assertFalse(b.allowRequest());
        time.now.addAndGet(CircuitBreaker.PROBE_TIMEOUT_MS);
        assertTrue(b.allowRequest(), "a new probe once the first never reported back");
    }

    @Test
    void retryAfterParsing() {
        assertEquals(3000, HumifortisTransport.parseRetryAfterMs("3"));
        assertEquals(0, HumifortisTransport.parseRetryAfterMs("Wed, 21 Oct 2015 07:28:00 GMT"));
        assertEquals(0, HumifortisTransport.parseRetryAfterMs(null));
    }

    @Test
    void jsonPostCarriesTheConnectorHeaders() {
        SaasConfig c = new SaasConfig(Map.of("HUMIFORTIS_API_KEY", "k", "HUMIFORTIS_API_URL", "https://api.example/"));
        HttpRequest r = HumifortisTransport.jsonPost(c, "/events", "t1", "{}").build();
        assertEquals("https://api.example/events", r.uri().toString());
        assertEquals("k", r.headers().firstValue("X-API-Key").orElseThrow());
        assertEquals("t1", r.headers().firstValue("X-Tenant-ID").orElseThrow());
    }
}

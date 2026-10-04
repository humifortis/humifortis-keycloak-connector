package tech.humifortis.keycloak.client;

import java.io.IOException;
import java.net.ConnectException;
import java.net.http.HttpTimeoutException;
import java.util.function.LongUnaryOperator;

/**
 * How many times, how long and how far apart a call is retried.
 *
 * <p>Exponential backoff with FULL jitter: the n-th wait is uniform in
 * {@code [0, min(maxDelay, baseDelay * 2^n)]} — retries of many Keycloak nodes after one blip
 * spread out instead of hitting the API together. A policy never waits past its budget: a
 * login is never held longer than {@link #totalBudgetMs()}.</p>
 *
 * <p>Retried: connection errors, timeouts, HTTP 429 (honouring Retry-After when it fits the
 * budget), 502, 503, 504. Never retried: other 4xx (a bad key or payload will not get better)
 * and 500 (a server error the same request would hit again).</p>
 */
public record RetryPolicy(int maxAttempts, long baseDelayMs, long maxDelayMs, long totalBudgetMs, long attemptTimeoutMs) {

    /** Below this, an attempt has no realistic chance to complete — not worth starting. */
    static final long MIN_ATTEMPT_MS = 25;

    public RetryPolicy {
        if (maxAttempts < 1) throw new IllegalArgumentException("maxAttempts must be >= 1");
    }

    /** A login waiting for its decision: a short, bounded budget. */
    public static RetryPolicy evaluate(SaasConfig config) {
        return new RetryPolicy(3, 50, 400, config.getEvaluateBudgetMs(), config.getTimeoutMs());
    }

    /** One delivery round of a queued event (the queue retries undelivered events later). */
    public static RetryPolicy events(SaasConfig config) {
        return new RetryPolicy(4, 250, 4_000, 15_000, Math.max(config.getTimeoutMs(), 2_000));
    }

    /** Full-jitter backoff before retry number {@code retry} (0 = first retry). */
    long backoffMs(int retry, LongUnaryOperator random) {
        long cap = baseDelayMs << Math.min(retry, 20);
        if (cap <= 0 || cap > maxDelayMs) cap = maxDelayMs;
        long r = random.applyAsLong(cap + 1);
        return Math.max(0, Math.min(cap, r));
    }

    static boolean isRetryableStatus(int status) {
        return status == 429 || status == 502 || status == 503 || status == 504;
    }

    static boolean isRetryableError(Throwable e) {
        return e instanceof HttpTimeoutException || e instanceof ConnectException
                || (e instanceof IOException && !(e.getCause() instanceof InterruptedException));
    }
}

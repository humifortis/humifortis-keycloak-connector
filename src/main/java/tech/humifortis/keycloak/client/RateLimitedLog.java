package tech.humifortis.keycloak.client;

import java.util.concurrent.atomic.AtomicLong;

import org.jboss.logging.Logger;

/** A log line that repeats at most once per period — an outage must not flood Keycloak's log. */
public final class RateLimitedLog {
    private final long periodMs;
    private final AtomicLong last = new AtomicLong(Long.MIN_VALUE / 2);

    public RateLimitedLog(long periodMs) {
        this.periodMs = periodMs;
    }

    /** True when the caller may log now (and claims the slot). */
    public boolean tryAcquire() {
        long now = System.currentTimeMillis();
        long prev = last.get();
        return now - prev >= periodMs && last.compareAndSet(prev, now);
    }

    public void warn(Logger logger, String message) {
        if (tryAcquire()) logger.warn(message);
    }

    public void error(Logger logger, String message) {
        if (tryAcquire()) logger.error(message);
    }
}

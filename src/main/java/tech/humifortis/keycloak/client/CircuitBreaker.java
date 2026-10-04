package tech.humifortis.keycloak.client;

import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;

import org.jboss.logging.Logger;

/**
 * Stops calling an API that keeps failing, so logins do not each wait out a timeout.
 *
 * <ul>
 *   <li>CLOSED — calls go through; {@code threshold} consecutive failed calls (after their
 *       retries) open it.</li>
 *   <li>OPEN — calls are refused until the open period ends.</li>
 *   <li>HALF_OPEN — exactly ONE probe call goes through: success closes the breaker, failure
 *       re-opens it for twice as long (up to {@code maxOpenMs}).</li>
 * </ul>
 * A 4xx is not a failure: the API answered. Thread-safe (one compare-and-set per transition).
 */
public final class CircuitBreaker {
    private static final Logger logger = Logger.getLogger(CircuitBreaker.class);

    public enum State { CLOSED, OPEN, HALF_OPEN }

    /** A probe that never reports back (lost thread) does not keep the breaker half-open forever. */
    static final long PROBE_TIMEOUT_MS = 30_000;

    /** openUntil: end of the open period (OPEN) or start of the probe (HALF_OPEN). */
    private record Snapshot(State state, int failures, long openUntil, long openMs) {}

    private final String name;
    private final int threshold;
    private final long baseOpenMs;
    private final long maxOpenMs;
    private final LongSupplier clock;
    private final AtomicReference<Snapshot> ref;

    public CircuitBreaker(String name, int threshold, long baseOpenMs, long maxOpenMs, LongSupplier clock) {
        this.name = name;
        this.threshold = threshold;
        this.baseOpenMs = baseOpenMs;
        this.maxOpenMs = maxOpenMs;
        this.clock = clock;
        this.ref = new AtomicReference<>(new Snapshot(State.CLOSED, 0, 0, baseOpenMs));
    }

    public static CircuitBreaker standard(String name) {
        return new CircuitBreaker(name, 5, 10_000, 120_000, System::currentTimeMillis);
    }

    /** True when a call may be made now. In HALF_OPEN only the single probe caller gets true. */
    public boolean allowRequest() {
        while (true) {
            Snapshot s = ref.get();
            switch (s.state()) {
                case CLOSED:
                    return true;
                case HALF_OPEN:
                    // the probe is in flight — unless it never reported back (then probe again)
                    if (clock.getAsLong() < s.openUntil() + PROBE_TIMEOUT_MS) return false;
                    if (ref.compareAndSet(s, new Snapshot(State.HALF_OPEN, s.failures(), clock.getAsLong(), s.openMs()))) {
                        return true;
                    }
                    break;
                case OPEN:
                    if (clock.getAsLong() < s.openUntil()) return false;
                    if (ref.compareAndSet(s, new Snapshot(State.HALF_OPEN, s.failures(), clock.getAsLong(), s.openMs()))) {
                        logger.infof("[Humifortis] circuit %s HALF_OPEN — probing the API", name);
                        return true;
                    }
                    break; // lost the race: re-read
                default:
                    return true;
            }
        }
    }

    public void onSuccess() {
        Snapshot prev = ref.getAndSet(new Snapshot(State.CLOSED, 0, 0, baseOpenMs));
        if (prev.state() != State.CLOSED) {
            logger.infof("[Humifortis] circuit %s CLOSED — the API answers again", name);
        }
    }

    public void onFailure() {
        while (true) {
            Snapshot s = ref.get();
            Snapshot next;
            if (s.state() == State.HALF_OPEN) {
                long openMs = Math.min(maxOpenMs, s.openMs() * 2);
                next = new Snapshot(State.OPEN, s.failures() + 1, clock.getAsLong() + openMs, openMs);
            } else if (s.state() == State.OPEN) {
                return; // a call that started before it opened
            } else if (s.failures() + 1 >= threshold) {
                next = new Snapshot(State.OPEN, s.failures() + 1, clock.getAsLong() + baseOpenMs, baseOpenMs);
            } else {
                next = new Snapshot(State.CLOSED, s.failures() + 1, 0, s.openMs());
            }
            if (ref.compareAndSet(s, next)) {
                if (next.state() == State.OPEN) {
                    logger.warnf("[Humifortis] circuit %s OPEN for %d ms — the API failed %d time(s) in a row",
                            name, next.openMs(), next.failures());
                }
                return;
            }
        }
    }

    public State state() { return ref.get().state(); }

    /** Milliseconds until an OPEN breaker lets a probe through (0 when not open). */
    public long millisUntilProbe() {
        Snapshot s = ref.get();
        return s.state() == State.OPEN ? Math.max(0, s.openUntil() - clock.getAsLong()) : 0;
    }
}

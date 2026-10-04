package tech.humifortis.keycloak.client;

import java.util.ArrayDeque;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

import org.jboss.logging.Logger;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

import tech.humifortis.keycloak.model.HumifortisEvent;

/**
 * Delivers events to {@code POST /events} without ever blocking a login, and without losing
 * them when the API blinks: events wait in a bounded in-memory queue and one background worker
 * delivers them in order, retrying while the API is unreachable.
 *
 * <ul>
 *   <li>Each event keeps its {@code event_id} across retries — the API ingests it once.</li>
 *   <li>A full queue drops its oldest non-authentication event first (admin events) — the
 *       login evidence detection needs is kept longest. Drops are counted and logged.</li>
 *   <li>An event older than {@link #MAX_AGE_MS} is dropped: evidence that late is history.</li>
 *   <li>A 4xx answer is final (the payload will not get better) — logged, not retried.</li>
 * </ul>
 */
public final class EventQueue {
    private static final Logger logger = Logger.getLogger(EventQueue.class);

    static final long MAX_AGE_MS = 15 * 60_000L;
    private static final long PAUSE_ON_FAILURE_MS = 2_000;

    private static final Map<String, EventQueue> SHARED = new ConcurrentHashMap<>();

    record Item(HumifortisEvent event, String json, long enqueuedAt) {}

    private final ArrayDeque<Item> items = new ArrayDeque<>();
    private final int capacity;
    private final SaasConfig config;
    private final HumifortisTransport transport;
    private final LongSupplier clock;
    private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicLong delivered = new AtomicLong();
    private final RateLimitedLog dropLog = new RateLimitedLog(60_000);
    private final RateLimitedLog rejectLog = new RateLimitedLog(60_000);
    private volatile Thread worker;

    EventQueue(SaasConfig config, HumifortisTransport transport, LongSupplier clock) {
        this.config = config;
        this.capacity = config.getEventQueueSize();
        this.transport = transport;
        this.clock = clock;
    }

    /** The queue of this endpoint, shared process-wide; its worker starts on first use. */
    public static EventQueue shared(SaasConfig config) {
        EventQueue q = SHARED.computeIfAbsent(config.getApiUrl(),
                k -> new EventQueue(config, HumifortisTransport.shared(config), System::currentTimeMillis));
        q.startWorker();
        return q;
    }

    /** Queues an event for delivery. Returns immediately. */
    public void submit(HumifortisEvent event) {
        if (event.getEventId() == null || event.getEventId().isBlank()) {
            event.setEventId(UUID.randomUUID().toString());
        }
        JsonObject payload = new JsonObject();
        payload.add("event", gson.toJsonTree(event));
        Item item = new Item(event, payload.toString(), clock.getAsLong());
        synchronized (items) {
            if (items.size() >= capacity) dropOne();
            items.addLast(item);
            items.notifyAll();
        }
    }

    private void dropOne() {
        Iterator<Item> it = items.iterator();
        Item victim = null;
        while (it.hasNext()) {
            Item i = it.next();
            if (!isAuthEvent(i.event())) { victim = i; break; }
        }
        if (victim != null) items.remove(victim); else items.pollFirst();
        long n = dropped.incrementAndGet();
        dropLog.warn(logger, "[Humifortis] event queue full (" + capacity + ") — dropped " + n + " event(s) so far; the API is unreachable or too slow");
    }

    static boolean isAuthEvent(HumifortisEvent e) {
        String t = e.getEventType();
        return t != null && (t.startsWith("auth_") || t.startsWith("mfa_"));
    }

    public int size() {
        synchronized (items) { return items.size(); }
    }

    public long droppedCount() { return dropped.get(); }

    public long deliveredCount() { return delivered.get(); }

    /**
     * Delivers the head of the queue once. Returns the pause (ms) the worker should take before
     * the next round: 0 after a delivery, more while the API is unreachable, -1 when empty.
     */
    long deliverNext() {
        Item item;
        synchronized (items) {
            item = items.peekFirst();
        }
        if (item == null) return -1;
        if (clock.getAsLong() - item.enqueuedAt() > MAX_AGE_MS) {
            remove(item);
            long n = dropped.incrementAndGet();
            dropLog.warn(logger, "[Humifortis] event older than 15 min dropped (" + n + " so far) — the API has been unreachable");
            return 0;
        }
        if (!config.hasApiKey()) {
            remove(item);
            return 0;
        }
        String tenant = config.tenantIdOr(null);
        HumifortisTransport.Result r = transport.send(
                HumifortisTransport.jsonPost(config, "/events", tenant, item.json()),
                RetryPolicy.events(config), item.event().getEventId());
        if (r.ok()) {
            remove(item);
            delivered.incrementAndGet();
            return 0;
        }
        if (r.failure() == HumifortisTransport.Failure.HTTP_4XX && r.status() != 429) {
            remove(item);
            rejectLog.warn(logger, "[Humifortis] event rejected by the API: HTTP " + r.status() + " type=" + item.event().getEventType());
            return 0;
        }
        if (r.failure() == HumifortisTransport.Failure.INTERRUPTED) return -1;
        // unreachable: keep the event at the head and pause (until the breaker allows a probe)
        return Math.max(PAUSE_ON_FAILURE_MS, transport.breaker().millisUntilProbe());
    }

    private void remove(Item item) {
        synchronized (items) {
            items.remove(item);
        }
    }

    private void startWorker() {
        if (worker != null) return;
        synchronized (this) {
            if (worker != null) return;
            Thread t = new Thread(this::run, "humifortis-event-delivery");
            t.setDaemon(true);
            t.start();
            worker = t;
        }
    }

    private void run() {
        while (!Thread.currentThread().isInterrupted()) {
            try {
                long pause = deliverNext();
                if (pause < 0) {
                    synchronized (items) {
                        while (items.isEmpty()) items.wait();
                    }
                } else if (pause > 0) {
                    Thread.sleep(pause);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (RuntimeException e) {
                logger.warnf("[Humifortis] event delivery error: %s", e.getMessage());
            }
        }
    }
}

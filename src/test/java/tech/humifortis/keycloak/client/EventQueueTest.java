package tech.humifortis.keycloak.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.ConnectException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import tech.humifortis.keycloak.model.HumifortisEvent;

class EventQueueTest {

    static HumifortisEvent event(String type) {
        HumifortisEvent e = new HumifortisEvent();
        e.setEventType(type);
        e.setEntityId("user:keycloak:demo:1");
        return e;
    }

    static SaasConfig config(int capacity) {
        return new SaasConfig(Map.of("HUMIFORTIS_API_KEY", "k", "HUMIFORTIS_API_URL", "https://api.example",
                "HUMIFORTIS_EVENT_QUEUE_SIZE", String.valueOf(capacity)));
    }

    @Test
    void submitNeverBlocksAndAssignsAnEventId() {
        HumifortisTransportTest.FakeTime time = new HumifortisTransportTest.FakeTime();
        HumifortisTransportTest.Script script = new HumifortisTransportTest.Script(time, 1);
        EventQueue q = new EventQueue(config(10), HumifortisTransportTest.transport(time, script, HumifortisTransportTest.breaker(time)), time::millis);
        HumifortisEvent e = event("auth_login_failed");
        q.submit(e);
        assertNotNull(e.getEventId());
        assertEquals(1, q.size());
        assertTrue(script.requests.isEmpty(), "nothing is sent on the caller's thread");
    }

    @Test
    void dropsTheOldestNonAuthEventFirstWhenFull() {
        HumifortisTransportTest.FakeTime time = new HumifortisTransportTest.FakeTime();
        HumifortisTransportTest.Script script = new HumifortisTransportTest.Script(time, 1);
        EventQueue q = new EventQueue(config(3), HumifortisTransportTest.transport(time, script, HumifortisTransportTest.breaker(time)), time::millis);
        q.submit(event("auth_login_failed"));
        q.submit(event("admin_user_update"));
        q.submit(event("auth_login_failed"));
        q.submit(event("auth_login_success"));
        assertEquals(3, q.size());
        assertEquals(1, q.droppedCount());
        List<String> sent = new ArrayList<>();
        while (q.deliverNext() >= 0) {
            // drain
        }
        script.requests.forEach(r -> sent.add(r.uri().getPath()));
        assertEquals(3, sent.size(), "the three auth events were kept and delivered");
    }

    @Test
    void keepsTheEventWhileTheApiIsUnreachableAndDeliversItWithTheSameId() {
        HumifortisTransportTest.FakeTime time = new HumifortisTransportTest.FakeTime();
        HumifortisTransportTest.Script script = new HumifortisTransportTest.Script(time, 100,
                new ConnectException("down"), new ConnectException("down"), new ConnectException("down"), new ConnectException("down"),
                200);
        EventQueue q = new EventQueue(config(10), HumifortisTransportTest.transport(time, script, HumifortisTransportTest.breaker(time)), time::millis);
        HumifortisEvent e = event("auth_login_failed");
        q.submit(e);
        long pause = q.deliverNext();
        assertTrue(pause > 0, "unreachable: the worker pauses");
        assertEquals(1, q.size(), "the event is kept");
        assertEquals(0, q.deliverNext());
        assertEquals(0, q.size());
        assertEquals(1, q.deliveredCount());
        script.requests.forEach(r -> assertEquals(e.getEventId(), r.headers().firstValue("Idempotency-Key").orElseThrow()));
    }

    @Test
    void aRejectedEventIsNotRetried() {
        HumifortisTransportTest.FakeTime time = new HumifortisTransportTest.FakeTime();
        HumifortisTransportTest.Script script = new HumifortisTransportTest.Script(time, 1, 400);
        EventQueue q = new EventQueue(config(10), HumifortisTransportTest.transport(time, script, HumifortisTransportTest.breaker(time)), time::millis);
        q.submit(event("auth_login_failed"));
        assertEquals(0, q.deliverNext());
        assertEquals(0, q.size());
        assertEquals(1, script.requests.size());
    }

    @Test
    void anEventOlderThanFifteenMinutesIsDropped() {
        HumifortisTransportTest.FakeTime time = new HumifortisTransportTest.FakeTime();
        HumifortisTransportTest.Script script = new HumifortisTransportTest.Script(time, 1);
        EventQueue q = new EventQueue(config(10), HumifortisTransportTest.transport(time, script, HumifortisTransportTest.breaker(time)), time::millis);
        q.submit(event("auth_login_failed"));
        time.now.addAndGet(EventQueue.MAX_AGE_MS + 1);
        q.deliverNext();
        assertEquals(0, q.size());
        assertEquals(1, q.droppedCount());
        assertTrue(script.requests.isEmpty());
    }
}

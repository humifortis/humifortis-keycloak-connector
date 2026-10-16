package tech.humifortis.keycloak.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

class EdgeRttTest {

    @Test
    void readsWholeMilliseconds_andZeroIsAMeasurement() {
        assertEquals(42, EdgeRtt.parse("42"));
        assertEquals(42, EdgeRtt.parse(" 42 "));
        assertEquals(0, EdgeRtt.parse("0"));
    }

    @Test
    void anythingElseIsNotEvaluated() {
        assertNull(EdgeRtt.parse(null));
        assertNull(EdgeRtt.parse(""));
        assertNull(EdgeRtt.parse("-1"));
        assertNull(EdgeRtt.parse("12.5"));
        assertNull(EdgeRtt.parse("fast"));
        assertNull(EdgeRtt.parse("60001"));
        assertNull(EdgeRtt.fromHeaders(null));
    }

    @Test
    void theBrowserIsTheFallback_neverAnOverrideOfTheEdge() {
        EdgeRtt.Measure browser = EdgeRtt.resolve(null, "48");
        assertEquals(48, browser.ms());
        assertEquals(EdgeRtt.BROWSER, browser.source());
        assertNull(EdgeRtt.resolve(null, null));
        assertNull(EdgeRtt.resolve(null, "soon"));
    }
}

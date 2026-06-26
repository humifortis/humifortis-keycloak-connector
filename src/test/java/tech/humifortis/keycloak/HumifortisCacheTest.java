package tech.humifortis.keycloak;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for HumifortisCache — TTL, increment, eviction, capacity.
 */
class HumifortisCacheTest {

    private HumifortisCache cache;

    @BeforeEach
    void setUp() {
        cache = HumifortisCache.getInstance();
        cache.clear();
    }

    @Test
    void putAndGet_returnValue() {
        cache.put("test:key", 42L, 60_000L);
        assertEquals(42L, cache.get("test:key"));
    }

    @Test
    void get_returnsNullForAbsentKey() {
        assertNull(cache.get("nonexistent:key"));
    }

    @Test
    void get_returnsNullAfterTtlExpired() throws Exception {
        cache.put("test:short", 1L, 50L); // 50ms TTL
        Thread.sleep(80);
        assertNull(cache.get("test:short"), "Should be null after TTL expiry");
    }

    @Test
    void increment_startsAtOne() {
        long v = cache.increment("test:counter", 60_000L);
        assertEquals(1L, v);
    }

    @Test
    void increment_accumulates() {
        cache.increment("test:ctr", 60_000L);
        cache.increment("test:ctr", 60_000L);
        long v = cache.increment("test:ctr", 60_000L);
        assertEquals(3L, v);
    }

    @Test
    void increment_resetAfterExpiry() throws Exception {
        cache.increment("test:exp", 50L);
        Thread.sleep(80);
        long v = cache.increment("test:exp", 60_000L);
        assertEquals(1L, v, "Should reset to 1 after TTL expiry");
    }

    @Test
    void mark_andExists() {
        cache.mark("test:flag", 60_000L);
        assertTrue(cache.exists("test:flag"));
    }

    @Test
    void exists_returnsFalseAfterTtl() throws Exception {
        cache.mark("test:expflag", 50L);
        Thread.sleep(80);
        assertFalse(cache.exists("test:expflag"), "Flag should expire");
    }

    @Test
    void remove_clearsKey() {
        cache.put("test:rm", 99L, 60_000L);
        cache.remove("test:rm");
        assertNull(cache.get("test:rm"));
    }

    @Test
    void size_reflectsEntries() {
        cache.clear();
        assertEquals(0, cache.size());
        cache.put("a", 1L, 60_000L);
        cache.put("b", 2L, 60_000L);
        assertEquals(2, cache.size());
    }

    @Test
    void evictExpired_removesStaleEntries() throws Exception {
        cache.put("stale:1", 1L, 30L);
        cache.put("fresh:1", 1L, 60_000L);
        Thread.sleep(60);
        cache.evictExpired();
        assertEquals(1, cache.size(), "Only fresh entry should remain");
    }

    @Test
    void singleton_isSameInstance() {
        assertSame(HumifortisCache.getInstance(), HumifortisCache.getInstance(),
                "getInstance() must return the same singleton");
    }
}

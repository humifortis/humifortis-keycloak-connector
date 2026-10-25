package tech.humifortis.keycloak.caep;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.humifortis.keycloak.HumifortisCache;

import static org.junit.jupiter.api.Assertions.*;

class CaepReplayGuardTest {
    private HumifortisCache cache;
    private CaepReplayGuard guard;

    @BeforeEach
    void setUp() {
        cache = HumifortisCache.getInstance();
        cache.clear();
        guard = new CaepReplayGuard(cache);
    }

    @Test
    void marksAndDetectsReplay() {
        CaepConfig config = new CaepConfig(true, "iss", "aud", "jwks", 60, true, 600, true, true, true, true, false);
        assertFalse(guard.isReplay("realm-a", "jti-1", config));
        assertTrue(guard.isReplay("realm-a", "jti-1", config));
        assertFalse(guard.isReplay("realm-b", "jti-1", config));
    }
}

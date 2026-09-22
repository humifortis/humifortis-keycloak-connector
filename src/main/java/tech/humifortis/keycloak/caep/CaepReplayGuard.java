package tech.humifortis.keycloak.caep;

import tech.humifortis.keycloak.HumifortisCache;

public class CaepReplayGuard {
    private final HumifortisCache cache;

    public CaepReplayGuard(HumifortisCache cache) {
        this.cache = cache;
    }

    public boolean isReplay(String realmId, String jti, CaepConfig config) {
        if (!config.replayEnabled()) return false;
        String key = "caep:replay:" + realmId + ":" + jti;
        if (cache.exists(key)) return true;
        long ttlMs = Math.max(config.replayTtlSeconds(), 1) * 1000L;
        cache.mark(key, ttlMs);
        return false;
    }
}

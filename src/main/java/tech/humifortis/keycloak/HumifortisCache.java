package tech.humifortis.keycloak;

import org.jboss.logging.Logger;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * In-JVM TTL cache pour le rate limiting et l'anti-replay OTP.
 *
 * <p>Design :
 * <ul>
 *   <li>Singleton JVM partagé (static) — thread-safe via ConcurrentHashMap</li>
 *   <li>TTL par entrée — cleanup périodique toutes les 5 min</li>
 *   <li>Borne mémoire : MAX_ENTRIES = 100 000</li>
 *   <li>Zéro dépendance externe, zéro DB</li>
 *   <li>Fail-open : si exception → caller autorisé</li>
 * </ul>
 *
 * <p>Limites (documentées) :
 * <ul>
 *   <li>Per-node uniquement — pas distribué cross-cluster Keycloak</li>
 *   <li>Volatile au restart Keycloak</li>
 *   <li>Pour clusters actif-actif haute charge : migrer vers Infinispan ou
 *       externaliser vers POST /api/v1/ratelimit/check</li>
 * </ul>
 */
public final class HumifortisCache {

    private static final Logger logger = Logger.getLogger(HumifortisCache.class);

    /** Borne mémoire — empêche l'exhaustion par flood d'énumération. */
    static final int MAX_ENTRIES = 100_000;

    private static final HumifortisCache INSTANCE = new HumifortisCache();

    /** Entrée du cache : valeur longue + expiry timestamp. */
    record Entry(long value, long expiryMs) {
        boolean isExpired() { return System.currentTimeMillis() > expiryMs; }
    }

    private final ConcurrentHashMap<String, Entry> store = new ConcurrentHashMap<>();
    private final ScheduledExecutorService cleaner;

    private HumifortisCache() {
        cleaner = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "humifortis-cache-cleaner");
            t.setDaemon(true); // ne bloque pas le shutdown JVM
            return t;
        });
        cleaner.scheduleAtFixedRate(this::evictExpired, 5, 5, TimeUnit.MINUTES);

        // Shutdown hook — évite les thread leaks en hot-reload / restart container
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            cleaner.shutdown();
            try { cleaner.awaitTermination(5, TimeUnit.SECONDS); }
            catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
        }, "humifortis-cache-shutdown"));
    }

    public static HumifortisCache getInstance() { return INSTANCE; }

    /**
     * Lire une valeur. Retourne null si absente ou expirée.
     */
    public Long get(String key) {
        Entry e = store.get(key);
        if (e == null || e.isExpired()) {
            store.remove(key); // lazy cleanup
            return null;
        }
        return e.value();
    }

    /**
     * Écrire une valeur avec TTL.
     * Fail-open si MAX_ENTRIES atteint après eviction.
     */
    public void put(String key, long value, long ttlMs) {
        if (store.size() >= MAX_ENTRIES) {
            evictExpired();
            if (store.size() >= MAX_ENTRIES) {
                logger.warnf("[HumifortisCache] MAX_ENTRIES (%d) reached — " +
                             "skipping put for key prefix=%s (fail-open)",
                             MAX_ENTRIES, key.substring(0, Math.min(12, key.length())));
                return;
            }
        }
        store.put(key, new Entry(value, System.currentTimeMillis() + ttlMs));
    }

    /**
     * Incrémenter atomiquement un compteur avec TTL.
     * Si la clé n'existe pas ou est expirée, repart de 1.
     * Retourne la nouvelle valeur.
     */
    public long increment(String key, long ttlMs) {
        if (store.size() >= MAX_ENTRIES) evictExpired();

        AtomicLong result = new AtomicLong();
        long now = System.currentTimeMillis();
        store.compute(key, (k, existing) -> {
            if (existing == null || existing.isExpired()) {
                result.set(1);
                return new Entry(1, now + ttlMs);
            }
            long next = existing.value() + 1;
            result.set(next);
            return new Entry(next, existing.expiryMs()); // TTL inchangé sur increment
        });
        return result.get();
    }

    /**
     * Supprimer une clé.
     */
    public void remove(String key) { store.remove(key); }

    /**
     * Vérifier la présence d'une clé non expirée.
     */
    public boolean exists(String key) {
        Entry e = store.get(key);
        if (e == null || e.isExpired()) { store.remove(key); return false; }
        return true;
    }

    /**
     * Marquer une clé comme présente avec TTL (flag booléen).
     */
    public void mark(String key, long ttlMs) { put(key, 1L, ttlMs); }

    /** Taille courante du store (pour monitoring / tests). */
    public int size() { return store.size(); }

    /** Vider le cache (tests uniquement). */
    public void clear() { store.clear(); }

    /** Éviction des entrées expirées — appelée périodiquement et sous pression mémoire. */
    public void evictExpired() {
        int before = store.size();
        store.entrySet().removeIf(e -> e.getValue().isExpired());
        int evicted = before - store.size();
        if (evicted > 0) {
            logger.debugf("[HumifortisCache] Evicted %d expired entries (remaining=%d)",
                          evicted, store.size());
        }
    }
}


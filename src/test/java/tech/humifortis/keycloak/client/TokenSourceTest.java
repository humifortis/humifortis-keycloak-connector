package tech.humifortis.keycloak.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

import org.junit.jupiter.api.Test;

class TokenSourceTest {

    private static HumifortisTransport.Result ok(String token, int expiresIn) {
        return new HumifortisTransport.Result(200, "{\"access_token\":\"" + token + "\",\"token_type\":\"Bearer\",\"expires_in\":" + expiresIn + "}",
                HumifortisTransport.Failure.NONE, 1);
    }

    private static HumifortisTransport.Result status(int status) {
        return new HumifortisTransport.Result(status, "{}", status >= 500 ? HumifortisTransport.Failure.HTTP_5XX : HumifortisTransport.Failure.HTTP_4XX, 3);
    }

    private static HumifortisTransport.Result unreachable() {
        return new HumifortisTransport.Result(0, null, HumifortisTransport.Failure.CONNECT, 3);
    }

    @Test
    void aTokenIsFetchedOnceAndKeptUntilItIsAboutToEnd() {
        AtomicLong now = new AtomicLong(1_000_000);
        AtomicInteger fetches = new AtomicInteger();
        TokenSource source = new TokenSource(() -> { fetches.incrementAndGet(); return ok("t" + fetches.get(), 300); }, now::get);

        assertEquals("t1", source.bearer());
        now.addAndGet(200_000);
        assertEquals("t1", source.bearer());
        assertEquals(1, fetches.get());

        now.addAndGet(50_000); // 250 s of 300: inside the last minute
        assertEquals("t2", source.bearer(), "replaced before it ends");
        assertEquals(2, fetches.get());
    }

    @Test
    void concurrentCallersShareOneFetch() throws Exception {
        AtomicInteger fetches = new AtomicInteger();
        CountDownLatch inFetch = new CountDownLatch(1);
        TokenSource source = new TokenSource(() -> {
            fetches.incrementAndGet();
            inFetch.countDown();
            try { Thread.sleep(100); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            return ok("shared", 300);
        }, System::currentTimeMillis);

        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            java.util.List<java.util.concurrent.Future<String>> calls = new java.util.ArrayList<>();
            for (int i = 0; i < 8; i++) calls.add(pool.submit(source::bearer));
            inFetch.await(2, TimeUnit.SECONDS);
            for (var f : calls) assertEquals("shared", f.get(5, TimeUnit.SECONDS));
        } finally {
            pool.shutdownNow();
        }
        assertEquals(1, fetches.get());
    }

    @Test
    void whenTheEndpointCannotAnswerTheKeyServesAndTheNextAttemptWaits() {
        AtomicLong now = new AtomicLong(1_000_000);
        AtomicInteger fetches = new AtomicInteger();
        Supplier<HumifortisTransport.Result> script = () -> fetches.incrementAndGet() == 1 ? unreachable() : ok("late", 300);
        TokenSource source = new TokenSource(script, now::get);

        assertNull(source.bearer(), "no token: the caller uses the API key");
        assertNull(source.bearer());
        assertEquals(1, fetches.get(), "not asked again at every call");

        now.addAndGet(TokenSource.RETRY_AFTER_TRANSIENT_MS + 1);
        assertEquals("late", source.bearer(), "a transient failure is retried soon");
    }

    @Test
    void aRefusalOrAnOlderHumifortisIsNotAskedAgainForAWhile() {
        AtomicLong now = new AtomicLong(1_000_000);
        AtomicInteger fetches = new AtomicInteger();
        TokenSource source = new TokenSource(() -> { fetches.incrementAndGet(); return status(404); }, now::get);

        assertNull(source.bearer());
        now.addAndGet(TokenSource.RETRY_AFTER_TRANSIENT_MS + 1);
        assertNull(source.bearer());
        assertEquals(1, fetches.get());

        now.addAndGet(TokenSource.RETRY_AFTER_REFUSED_MS);
        assertNull(source.bearer());
        assertEquals(2, fetches.get());
    }

    @Test
    void aFailedRefreshKeepsTheTokenThatHasNotEnded() {
        AtomicLong now = new AtomicLong(1_000_000);
        AtomicInteger fetches = new AtomicInteger();
        TokenSource source = new TokenSource(() -> fetches.incrementAndGet() == 1 ? ok("first", 300) : unreachable(), now::get);

        assertEquals("first", source.bearer());
        now.addAndGet(250_000);
        assertEquals("first", source.bearer(), "the refresh failed, the token is still good");
        now.addAndGet(60_000);
        assertNull(source.bearer(), "ended: the key serves");
    }

    @Test
    void theApiKeyIsTheClientSecretAndItsPrefixTheClientIdUnlessSaidOtherwise() {
        String key = "hf_0123456789abcdef";
        SaasConfig c = new SaasConfig(Map.of("HUMIFORTIS_API_KEY", key));
        assertTrue(c.useOAuth2(), "OAuth2 is the default");
        assertEquals("hf_0123456", c.getClientId());
        assertEquals(key, c.getClientSecret());
        assertTrue(!c.useMtls());

        SaasConfig opt = new SaasConfig(Map.of("HUMIFORTIS_API_KEY", key, "HUMIFORTIS_AUTH", "api_key"));
        assertTrue(!opt.useOAuth2(), "one line to opt out");

        SaasConfig own = new SaasConfig(Map.of("HUMIFORTIS_CLIENT_ID", "cid", "HUMIFORTIS_CLIENT_SECRET", "hf_s"));
        assertEquals("cid", own.getClientId());
        assertTrue(own.useOAuth2());

        assertTrue(!new SaasConfig(Map.of()).useOAuth2(), "nothing to authenticate with");

        SaasConfig tls = new SaasConfig(Map.of("HUMIFORTIS_API_KEY", key, "HUMIFORTIS_MTLS_CERT", "/c.pem", "HUMIFORTIS_MTLS_KEY", "/k.pem"));
        assertTrue(tls.useMtls(), "present means used");
        assertTrue(!new SaasConfig(Map.of("HUMIFORTIS_MTLS_CERT", "/c.pem")).useMtls(), "a certificate without its key is off");
    }

    @Test
    void thePrivateKeyIsReadFromPkcs8Pem() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair pair = gen.generateKeyPair();
        String pem = "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(pair.getPrivate().getEncoded()) + "\n-----END PRIVATE KEY-----\n";
        assertEquals(pair.getPrivate(), PemKeys.privateKey(pem));
        try {
            PemKeys.privateKey("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----");
            throw new AssertionError("a PKCS#1 key must be refused with the way to convert it");
        } catch (IllegalStateException e) {
            assertTrue(e.getMessage().contains("pkcs8"));
        }
    }

    @Test
    void aRefusedTokenIsReplacedAtOnce_onceForEveryoneRefusedWithIt() {
        AtomicLong now = new AtomicLong(1_000_000);
        AtomicInteger fetches = new AtomicInteger();
        TokenSource source = new TokenSource(() -> { fetches.incrementAndGet(); return ok("t" + fetches.get(), 300); }, now::get);
        assertEquals("t1", source.bearer());

        assertEquals("t2", source.renew("t1"), "the refused token is dropped although it has not ended");
        assertEquals("t2", source.renew("t1"), "a thread refused with the same token gets the new one");
        assertEquals(2, fetches.get(), "one fetch for the renewal");
        assertEquals("t2", source.bearer());
        assertNull(source.renew("someone-else"), "a token this source never issued is not renewed");
        assertNull(source.renew(null));
    }
}

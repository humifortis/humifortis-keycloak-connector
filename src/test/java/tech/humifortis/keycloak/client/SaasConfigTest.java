package tech.humifortis.keycloak.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Test;

class SaasConfigTest {

    @Test
    void defaultsToSecureTlsWhenInsecureFlagIsMissing() {
        SaasConfig config = new SaasConfig(Map.of("HUMIFORTIS_API_KEY", "test-key"));

        assertFalse(config.isInsecureSsl());
    }

    @Test
    void enablesInsecureTlsOnlyWhenEnvironmentFlagIsTrue() {
        SaasConfig config = new SaasConfig(Map.of(
                "HUMIFORTIS_API_KEY", "test-key",
                "INSECURE_SSL", "true"
        ));

        assertTrue(config.isInsecureSsl());
    }

    @Test
    void zeroConfigDefaults() {
        SaasConfig c = new SaasConfig(Map.of());
        assertFalse(c.hasApiKey());
        assertEquals(SaasConfig.DEFAULT_API_URL, c.getApiUrl());
        assertEquals(800, c.getTimeoutMs());
        assertEquals(1500, c.getEvaluateBudgetMs());
        assertEquals(10_000, c.getEventQueueSize());
        assertNull(c.getFallbackOverride(), "the tenant policy decides");
        assertEquals("demo", c.tenantIdOr("demo"));
        assertTrue(c.isEndpointAllowed());
    }

    @Test
    void badNumbersFallBackToDefaults() {
        SaasConfig c = new SaasConfig(Map.of("HUMIFORTIS_TIMEOUT_MS", "abc", "HUMIFORTIS_EVALUATE_BUDGET_MS", "-5"));
        assertEquals(800, c.getTimeoutMs());
        assertEquals(1500, c.getEvaluateBudgetMs());
    }

    @Test
    void fallbackOverride() {
        assertEquals("step_up", new SaasConfig(Map.of("HUMIFORTIS_FALLBACK", "Step-Up")).getFallbackOverride());
        assertEquals("deny", new SaasConfig(Map.of("HUMIFORTIS_FALLBACK", "deny")).getFallbackOverride());
        assertNull(new SaasConfig(Map.of("HUMIFORTIS_FALLBACK", "maybe")).getFallbackOverride());
        // deprecated flag: false meant "fail closed", true was the old default
        assertEquals("deny", new SaasConfig(Map.of("HUMIFORTIS_FALLBACK_ALLOW", "false")).getFallbackOverride());
        assertNull(new SaasConfig(Map.of("HUMIFORTIS_FALLBACK_ALLOW", "true")).getFallbackOverride());
        assertEquals("allow", new SaasConfig(Map.of("HUMIFORTIS_FALLBACK", "allow", "HUMIFORTIS_FALLBACK_ALLOW", "false")).getFallbackOverride());
    }

    @Test
    void plainHttpOnlyWithTheExplicitOptIn() {
        assertFalse(new SaasConfig(Map.of("HUMIFORTIS_API_URL", "http://hf-proxy:80")).isEndpointAllowed());
        assertTrue(new SaasConfig(Map.of("HUMIFORTIS_API_URL", "http://hf-proxy:80", "HUMIFORTIS_ALLOW_INSECURE_HTTP", "true")).isEndpointAllowed());
        assertFalse(new SaasConfig(Map.of("HUMIFORTIS_API_URL", "ftp://x", "HUMIFORTIS_ALLOW_INSECURE_HTTP", "true")).isEndpointAllowed());
    }

    @Test
    void proxySettings() {
        ProxySettings unsafe = ProxySettings.resolve(k -> null, Map.of("KC_PROXY_HEADERS", "xforwarded"));
        assertTrue(unsafe.isUnsafe());
        ProxySettings safe = ProxySettings.resolve(k -> null, Map.of("KC_PROXY_HEADERS", "xforwarded", "KC_PROXY_TRUSTED_ADDRESSES", "10.0.0.5"));
        assertFalse(safe.isUnsafe());
        ProxySettings none = ProxySettings.resolve(k -> null, Map.of());
        assertEquals("none", none.headersMode());
        assertFalse(none.isUnsafe());
        ProxySettings fromKcConfig = ProxySettings.resolve(k -> k.equals("kc.proxy-headers") ? "forwarded" : null, Map.of());
        assertTrue(fromKcConfig.isUnsafe());
        Map<String, String> out = new java.util.HashMap<>();
        safe.writeTo(out::put);
        assertEquals(Map.of("ip_source", "keycloak_connection", "proxy_headers_mode", "xforwarded", "proxy_trusted_addresses_set", "true"), out);
    }
}

package tech.humifortis.keycloak.client;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
}

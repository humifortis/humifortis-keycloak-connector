package tech.humifortis.keycloak.auth;

import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import tech.humifortis.keycloak.model.Risk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;

class HumifortisRiskEvaluatorDetailedTest {

    @Test
    void evaluateDetailed_whenKnownUserIsNull_returnsFailOpenWithoutDecision() {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmModel realm = mock(RealmModel.class);

        HumifortisRiskEvaluator.EvaluationResult result =
                new HumifortisRiskEvaluator(session).evaluateDetailed(realm, null, "flow-1");

        assertEquals(Risk.Score.NONE, result.risk().getScore());
        assertEquals("Humifortis unavailable - fail open", result.risk().getReason().orElseThrow());
        assertNull(result.decision());
    }

    @Test
    void endpointPolicy_rejectsPlainHttpWithoutExplicitOverride() {
        assertEquals(false, HumifortisRiskEvaluator.isAllowedEndpoint("http://hf-proxy:80", null));
        assertEquals(false, HumifortisRiskEvaluator.isAllowedEndpoint("http://hf-proxy:80", "false"));
    }

    @Test
    void endpointPolicy_allowsHttpsAndExplicitTestHttpOverride() {
        assertEquals(true, HumifortisRiskEvaluator.isAllowedEndpoint("https://core.example", null));
        assertEquals(true, HumifortisRiskEvaluator.isAllowedEndpoint("http://hf-proxy:80", "true"));
        assertEquals(false, HumifortisRiskEvaluator.isAllowedEndpoint("ftp://core.example", "true"));
    }
}

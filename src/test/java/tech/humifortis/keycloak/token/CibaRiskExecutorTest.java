package tech.humifortis.keycloak.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.grants.ciba.clientpolicy.context.CIBAContext;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;

class CibaRiskExecutorTest {

    @Test
    void theRequestAndTheTokenAreDecidedAsTwoStages() {
        assertEquals("ciba_request", CibaRiskExecutor.stageOf(ClientPolicyEvent.BACKCHANNEL_AUTHENTICATION_REQUEST));
        assertEquals("ciba_token", CibaRiskExecutor.stageOf(ClientPolicyEvent.BACKCHANNEL_TOKEN_REQUEST));
    }

    @Test
    void everyOtherEventIsLeftAlone() {
        assertNull(CibaRiskExecutor.stageOf(ClientPolicyEvent.TOKEN_REFRESH));
        assertNull(CibaRiskExecutor.stageOf(ClientPolicyEvent.BACKCHANNEL_TOKEN_RESPONSE));
        assertNull(CibaRiskExecutor.stageOf(ClientPolicyEvent.DEVICE_TOKEN_REQUEST));
    }

    @Test
    void aRequestForNobodyIsKeycloaksToRefuse_noDecisionNoRefusal() throws Exception {
        CIBAContext ctx = mock(CIBAContext.class);
        when(ctx.getEvent()).thenReturn(ClientPolicyEvent.BACKCHANNEL_TOKEN_REQUEST);
        when(ctx.getParsedRequest()).thenReturn(null);
        new CibaRiskExecutor(mock(KeycloakSession.class)).executeOnEvent(ctx); // does not throw
    }

    @Test
    void anotherKindOfContextIsIgnored() throws Exception {
        ClientPolicyContext ctx = mock(ClientPolicyContext.class);
        when(ctx.getEvent()).thenReturn(ClientPolicyEvent.BACKCHANNEL_TOKEN_REQUEST);
        new CibaRiskExecutor(mock(KeycloakSession.class)).executeOnEvent(ctx);
    }
}

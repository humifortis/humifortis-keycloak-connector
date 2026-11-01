package tech.humifortis.keycloak.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;

/** MA-3: the decision about a person names the machine that acts for her. */
class ExchangeActingMachineTest {

    @Test
    void theDecisionCarriesTheMachineAndItsEntity() {
        RealmModel realm = mock(RealmModel.class);
        ClientModel client = mock(ClientModel.class);
        when(realm.getId()).thenReturn("realm-id");
        when(client.getClientId()).thenReturn("backend");
        Map<String, String> more = TokenExchangeRiskExecutor.actingMachine(realm, client);
        assertEquals("backend", more.get("actor_client_id"));
        assertEquals("service_account:keycloak:realm-id:backend", more.get("actor"));
    }
}

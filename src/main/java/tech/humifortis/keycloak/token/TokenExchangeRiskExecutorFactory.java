package tech.humifortis.keycloak.token;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProviderFactory;

/**
 * Registers the token-exchange risk stage as a client-policy executor. A realm enables it with a client profile holding
 * the executor and a client policy applying the profile (INSTALLATION.md, "Token exchange").
 */
public class TokenExchangeRiskExecutorFactory implements ClientPolicyExecutorProviderFactory {

    public static final String PROVIDER_ID = "humifortis-token-exchange-risk";

    @Override
    public ClientPolicyExecutorProvider create(KeycloakSession session) {
        return new TokenExchangeRiskExecutor(session);
    }

    @Override
    public void init(Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "Humifortis: evaluates the risk of a token exchange and refuses it when the decision is a deny or a step-up";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }
}

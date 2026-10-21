package tech.humifortis.keycloak.token;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProviderFactory;

/**
 * Registers the refresh-token risk stage as a client-policy executor. A realm enables it with a client profile holding
 * the executor and a client policy applying the profile (INSTALLATION.md, "Refresh tokens").
 */
public class TokenRefreshRiskExecutorFactory implements ClientPolicyExecutorProviderFactory {

    public static final String PROVIDER_ID = "humifortis-token-refresh-risk";

    @Override
    public ClientPolicyExecutorProvider create(KeycloakSession session) {
        return new TokenRefreshRiskExecutor(session);
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
        return "Humifortis: evaluates the risk of a refresh-token request and refuses it when the decision is a deny or a step-up";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }
}

package tech.humifortis.keycloak.serviceaccount;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProviderFactory;

/**
 * Registers the service-account risk stage as a client-policy executor. A realm enables it with a client profile
 * holding the executor and a client policy applying the profile (README, "Service accounts: risk stage").
 * Keycloak marks the client-policy executor SPI internal: the stage is tested on every supported Keycloak version.
 */
public class ServiceAccountRiskExecutorFactory implements ClientPolicyExecutorProviderFactory {

    public static final String PROVIDER_ID = "humifortis-service-account-risk";

    @Override
    public ClientPolicyExecutorProvider create(KeycloakSession session) {
        return new ServiceAccountRiskExecutor(session);
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
        return "Humifortis: evaluates the risk of a service-account token request before the token is issued, and refuses it when the decision is DENY.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }
}

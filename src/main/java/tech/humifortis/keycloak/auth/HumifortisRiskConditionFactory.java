package tech.humifortis.keycloak.auth;

import java.util.Collections;
import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class HumifortisRiskConditionFactory implements ConditionalAuthenticatorFactory {

    public static final String PROVIDER_ID = "humifortis-risk-condition";
    private static final HumifortisRiskCondition SINGLETON = new HumifortisRiskCondition();

    @Override
    public String getDisplayType() {
        return "Humifortis Risk Condition";
    }

    @Override
    public String getReferenceCategory() {
        return "condition";
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {
                AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Evaluates the Humifortis risk decision stored in the auth session. Returns true if step-up authentication is required.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    public ConditionalAuthenticator getSingleton() {
        return SINGLETON;
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
}


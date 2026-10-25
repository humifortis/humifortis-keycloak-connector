package tech.humifortis.keycloak.auth;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class HumifortisRiskAuthenticatorFactory implements AuthenticatorFactory {
    public static final String PROVIDER_ID = "humifortis-risk-authenticator";

    @Override
    public Authenticator create(KeycloakSession session) {
        return new HumifortisRiskAuthenticator();
    }

    @Override public void init(org.keycloak.Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
    @Override public String getId() { return PROVIDER_ID; }
    @Override public String getDisplayType() { return "Humifortis Risk Authenticator"; }
    @Override public String getReferenceCategory() { return null; }
    @Override public boolean isConfigurable() { return true; }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public org.keycloak.models.AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new org.keycloak.models.AuthenticationExecutionModel.Requirement[] {
            org.keycloak.models.AuthenticationExecutionModel.Requirement.REQUIRED,
            org.keycloak.models.AuthenticationExecutionModel.Requirement.DISABLED
        };
    }
    @Override public String getHelpText() { return "Evaluates risk using Humifortis external service"; }
    @Override public java.util.List<org.keycloak.provider.ProviderConfigProperty> getConfigProperties() {
        return org.keycloak.provider.ProviderConfigurationBuilder.create().property()
                .name(DecisionSource.CONFIG_KEY).label("Decision source").type(org.keycloak.provider.ProviderConfigProperty.LIST_TYPE)
                .options("inherit", "server", "local").defaultValue("inherit")
                .helpText("Who decides the login. server: the action returned by Humifortis is enforced. local: this flow decides with the Humifortis conditions (an explicit deny is still enforced). inherit: follow HUMIFORTIS_DECISION_SOURCE.")
                .add().build();
    }
}

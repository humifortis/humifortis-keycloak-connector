package tech.humifortis.keycloak.auth;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class HumifortisDirectGrantAuthenticatorFactory implements AuthenticatorFactory {
    public static final String PROVIDER_ID = "humifortis-direct-grant-risk";

    @Override public Authenticator create(KeycloakSession session) { return new HumifortisDirectGrantAuthenticator(); }
    @Override public void init(org.keycloak.Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
    @Override public String getId() { return PROVIDER_ID; }
    @Override public String getDisplayType() { return "Humifortis Direct Grant Risk"; }
    @Override public String getReferenceCategory() { return null; }
    @Override public boolean isConfigurable() { return false; }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public Requirement[] getRequirementChoices() { return new Requirement[] {Requirement.REQUIRED, Requirement.DISABLED}; }
    @Override public String getHelpText() { return "Evaluates the password grant with Humifortis and refuses the token on a deny or a step-up"; }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return List.of(); }
}

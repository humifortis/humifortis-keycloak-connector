package tech.humifortis.keycloak.auth;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/** Factory of {@link HumifortisDecisionReport}: "Humifortis decision report", the last step of a flow under the local decision source. */
public class HumifortisDecisionReportFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "humifortis-decision-report";

    private static final HumifortisDecisionReport SINGLETON = new HumifortisDecisionReport();

    @Override public Authenticator create(KeycloakSession session) { return SINGLETON; }
    @Override public void init(org.keycloak.Config.Scope config) {}
    @Override public void postInit(KeycloakSessionFactory factory) {}
    @Override public void close() {}
    @Override public String getId() { return PROVIDER_ID; }
    @Override public String getDisplayType() { return "Humifortis decision report"; }
    @Override public String getReferenceCategory() { return null; }
    @Override public boolean isConfigurable() { return true; }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {
                AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED
        };
    }
    @Override public String getHelpText() {
        return "Reports to Humifortis what this flow did with the decision of the login. Place it last in the flow, after the second-factor sub-flow. Only used with HUMIFORTIS_DECISION_SOURCE=local.";
    }
    @Override public List<ProviderConfigProperty> getConfigProperties() {
        return org.keycloak.provider.ProviderConfigurationBuilder.create().property()
                .name(HumifortisDecisionReport.CONFIG_OUTCOME).label("Report as").type(ProviderConfigProperty.LIST_TYPE)
                .options("auto", HumifortisDecisionReport.OUTCOME_DENY).defaultValue("auto")
                .helpText("auto: derive what the flow did (last step). deny: report the denial the flow is about to apply; put it just before Deny access.")
                .add().build();
    }
}

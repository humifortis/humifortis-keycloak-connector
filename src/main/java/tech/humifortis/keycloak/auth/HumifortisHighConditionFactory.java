package tech.humifortis.keycloak.auth;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

/**
 * Factory for {@link HumifortisHighCondition}.
 *
 * <p>SPI registration: add to
 * {@code META-INF/services/org.keycloak.authentication.AuthenticatorFactory}</p>
 *
 * <p>Keycloak admin UI display: "Condition - Humifortis high risk"</p>
 */
public class HumifortisHighConditionFactory implements ConditionalAuthenticatorFactory {

    public static final String PROVIDER_ID = "humifortis-high-condition";

    private static final HumifortisHighCondition SINGLETON = new HumifortisHighCondition();

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENTS = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override public String getId()          { return PROVIDER_ID; }
    @Override public String getDisplayType() { return "Condition - Humifortis high risk"; }
    @Override public String getReferenceCategory()  { return null; }
    @Override public boolean isConfigurable()       { return true; }
    @Override public boolean isUserSetupAllowed()   { return false; }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() { return REQUIREMENTS; }

    @Override
    public String getHelpText() {
        return "Matches when the decision of Humifortis for this login is a step-up (or a deny, when configured). " +
               "Place after Humifortis Risk Authenticator.";
    }

    @Override public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create().property()
                .name(HumifortisHighCondition.CONFIG_OUTCOME).label("Platform decision").type(ProviderConfigProperty.LIST_TYPE)
                .options(ContextConditions.OUTCOME_STEP_UP, ContextConditions.OUTCOME_DENY).defaultValue(ContextConditions.OUTCOME_STEP_UP)
                .helpText("The decision of Humifortis that matches: a step-up, or a deny.").add().build();
    }
    @Override public Authenticator create(KeycloakSession session)      { return SINGLETON; }
    @Override public HumifortisHighCondition getSingleton()             { return SINGLETON; }
    @Override public void init(Config.Scope config)                     {}
    @Override public void postInit(KeycloakSessionFactory factory)      {}
    @Override public void close()                                       {}
}
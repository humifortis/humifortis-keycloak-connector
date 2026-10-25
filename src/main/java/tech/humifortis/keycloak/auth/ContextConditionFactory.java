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
 * The factories of the three context conditions (docs/risk-as-data.spec.md, D4). Registered in
 * {@code META-INF/services/org.keycloak.authentication.AuthenticatorFactory}.
 */
public abstract class ContextConditionFactory implements ConditionalAuthenticatorFactory {

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENTS = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    private final String id;
    private final String displayType;
    private final String helpText;
    private final List<ProviderConfigProperty> properties;
    private final ContextCondition condition;

    ContextConditionFactory(String id, String displayType, String helpText, ContextCondition.Kind kind, List<ProviderConfigProperty> properties) {
        this.id = id;
        this.displayType = displayType;
        this.helpText = helpText;
        this.properties = properties;
        this.condition = new ContextCondition(kind);
    }

    @Override public String getId() { return id; }
    @Override public String getDisplayType() { return displayType; }
    @Override public String getHelpText() { return helpText; }
    @Override public String getReferenceCategory() { return null; }
    @Override public boolean isConfigurable() { return true; }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() { return REQUIREMENTS; }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return properties; }
    @Override public Authenticator create(KeycloakSession session) { return condition; }
    @Override public ContextCondition getSingleton() { return condition; }
    @Override public void init(Config.Scope config) {}
    @Override public void postInit(KeycloakSessionFactory factory) {}
    @Override public void close() {}

    /** Condition - Humifortis risk level at least X. */
    public static final class RiskLevel extends ContextConditionFactory {
        public static final String PROVIDER_ID = "humifortis-risk-level-condition";

        public RiskLevel() {
            super(PROVIDER_ID, "Condition - Humifortis risk level at least",
                    "Matches when the risk level Humifortis computed for this login is at least the level below. Place after Humifortis Risk Authenticator.",
                    ContextCondition.Kind.RISK_LEVEL,
                    ProviderConfigurationBuilder.create().property()
                            .name(ContextCondition.CONFIG_LEVEL).label("Risk level at least").type(ProviderConfigProperty.LIST_TYPE)
                            .options("LOW", "MEDIUM", "HIGH", "CRITICAL").defaultValue("HIGH")
                            .helpText("The lowest risk level that matches.").add().build());
        }
    }

    /** Condition - Humifortis rule fired. */
    public static final class RuleFired extends ContextConditionFactory {
        public static final String PROVIDER_ID = "humifortis-rule-fired-condition";

        public RuleFired() {
            super(PROVIDER_ID, "Condition - Humifortis rule fired",
                    "Matches when the named Humifortis detection rule fired for this login. Anything richer than one rule is written once as a rule in Humifortis. Place after Humifortis Risk Authenticator.",
                    ContextCondition.Kind.RULE_FIRED,
                    ProviderConfigurationBuilder.create().property()
                            .name(ContextCondition.CONFIG_RULE).label("Rule").type(ProviderConfigProperty.STRING_TYPE)
                            .helpText("The exact name of the rule, as shown in Humifortis.").add().build());
        }
    }

    /** Condition - Humifortis attribute equals. */
    public static final class Attribute extends ContextConditionFactory {
        public static final String PROVIDER_ID = "humifortis-attribute-condition";

        public Attribute() {
            super(PROVIDER_ID, "Condition - Humifortis attribute equals",
                    "Matches when a Humifortis attribute of this login equals the value. Only attributes of HUMIFORTIS_CONTEXT_ATTRIBUTES are available. Place after Humifortis Risk Authenticator.",
                    ContextCondition.Kind.ATTRIBUTE,
                    ProviderConfigurationBuilder.create()
                            .property().name(ContextCondition.CONFIG_ATTRIBUTE).label("Attribute").type(ProviderConfigProperty.STRING_TYPE)
                            .helpText("The catalogue name, for example network.is_tor.").add()
                            .property().name(ContextCondition.CONFIG_VALUE).label("Value").type(ProviderConfigProperty.STRING_TYPE)
                            .helpText("The exact value, for example true.").add().build());
        }
    }
}

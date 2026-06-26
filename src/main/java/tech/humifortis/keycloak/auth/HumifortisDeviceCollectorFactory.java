package tech.humifortis.keycloak.auth;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import java.util.Collections;
import java.util.List;
/**
 * Factory for {@link HumifortisDeviceCollectorAuthenticator}.
 * Registered via META-INF/services/org.keycloak.authentication.AuthenticatorFactory.
 *
 * In the Keycloak Admin UI this step appears as "Humifortis Device Collector"
 * and should be placed immediately after the Username/Password form.
 */
public class HumifortisDeviceCollectorFactory implements AuthenticatorFactory {
    public static final String PROVIDER_ID = "humifortis-device-collector";
    private static final HumifortisDeviceCollectorAuthenticator SINGLETON =
            new HumifortisDeviceCollectorAuthenticator();
    @Override
    public Authenticator create(KeycloakSession session) { return SINGLETON; }
    @Override public String  getId()                 { return PROVIDER_ID; }
    @Override public String  getDisplayType()        { return "Humifortis Device Collector"; }
    @Override public String  getReferenceCategory()  { return "device-fingerprint"; }
    @Override public boolean isConfigurable()        { return false; }
    @Override public boolean isUserSetupAllowed()    { return false; }
    @Override
    public String getHelpText() {
        return "Transparent step: collects FingerprintJS signals after password auth " +
               "and stores them as auth notes for downstream risk evaluation.";
    }
    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
        };
    }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return Collections.emptyList(); }
    @Override public void init(Config.Scope config)           {}
    @Override public void postInit(KeycloakSessionFactory f)  {}
    @Override public void close()                             {}
}

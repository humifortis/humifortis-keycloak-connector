package tech.humifortis.keycloak.auth;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.*;
import org.keycloak.provider.ProviderConfigProperty;
import java.util.List;

/** SPI factory for HumifortisStepUpRouter. */
public class HumifortisStepUpRouterFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "humifortis-step-up-router";
    private static final HumifortisStepUpRouter SINGLETON = new HumifortisStepUpRouter();

    @Override public Authenticator create(KeycloakSession session) { return SINGLETON; }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of(
            new ProviderConfigProperty("fallback.order", "MFA Fallback Order",
                "Comma-separated method priority: EMAIL_OTP,TOTP,WEBAUTHN",
                ProviderConfigProperty.STRING_TYPE, "EMAIL_OTP,TOTP,WEBAUTHN"),
            new ProviderConfigProperty("default.method", "Default MFA Method",
                "Fail-secure default when no action is set.",
                ProviderConfigProperty.LIST_TYPE, "EMAIL_OTP"),
            new ProviderConfigProperty("email_otp.expiry", "Email OTP Expiry (seconds)",
                "Recommended: 180.  Clamped to 60/120 for CRITICAL/HIGH risk.",
                ProviderConfigProperty.STRING_TYPE, "180"),
            new ProviderConfigProperty("allow.enrollment", "Allow TOTP enrollment during login",
                "SECURITY: set to false in production.",
                ProviderConfigProperty.BOOLEAN_TYPE, "false")
        );
    }

    @Override public String getId()                { return PROVIDER_ID; }
    @Override public String getDisplayType()       { return "Humifortis Step-Up Router"; }
    @Override public String getHelpText()          {
        return "Routes to EMAIL_OTP / TOTP / WebAuthn based on HUMIFORTIS_RISK_ACTION. "
             + "Place inside the MFA sub-flow triggered by HumifortisHighCondition.";
    }
    @Override public String getReferenceCategory() { return "humifortis"; }
    @Override public boolean isConfigurable()      { return true; }
    @Override public boolean isUserSetupAllowed()  { return false; }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
        };
    }
    @Override public void init(org.keycloak.Config.Scope config) {}
    @Override public void postInit(KeycloakSessionFactory factory) {}
    @Override public void close() {}
}

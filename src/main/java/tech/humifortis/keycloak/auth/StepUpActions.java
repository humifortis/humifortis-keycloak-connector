package tech.humifortis.keycloak.auth;

import java.util.Set;

/**
 * The step-up actions Humifortis can return. One list for the whole connector: the risk authenticator, the
 * conditional sub-flow and the decision report all read it, so an action the server returns can never be a
 * step-up in one place and an unknown action in another. It must equal humifortis-core's
 * {@code human_mfa_actions} (policy/engine.rego).
 */
public final class StepUpActions {

    public static final Set<String> ALL = Set.of("REQUIRE_MFA", "REQUIRE_WEBAUTHN", "REQUIRE_TOTP", "REQUIRE_EMAIL_OTP");

    private StepUpActions() {}

    public static boolean isStepUp(String action) {
        return action != null && ALL.contains(action);
    }
}

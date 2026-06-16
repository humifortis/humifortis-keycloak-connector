package tech.humifortis.keycloak.auth;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Humifortis Risk Condition — a ConditionalAuthenticator that determines
 * whether a conditional sub-flow (e.g., MFA step) should be executed.
 *
 * Usage in Keycloak Authentication Flow:
 *   Browser Flow
 *     └── Username/Password (REQUIRED)
 *     └── Humifortis RBA Evaluator (REQUIRED) — calls /evaluate, stores decision
 *     └── Conditional Sub-Flow (CONDITIONAL)
 *         ├── Humifortis Risk Condition (REQUIRED) — reads stored decision
 *         └── OTP Form (REQUIRED) — only executes if condition = true
 *
 * This condition reads the risk decision stored in auth session notes
 * by the HumifortisRBAAuthenticator and returns true if step-up auth
 * is required (REQUIRE_MFA or REQUIRE_WEBAUTHN).
 */
public class HumifortisRiskCondition implements ConditionalAuthenticator {

    private static final Logger logger = Logger.getLogger(HumifortisRiskCondition.class);

    static final String NOTE_ACTION = "HUMIFORTIS_RISK_ACTION";

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        String action = context.getAuthenticationSession().getAuthNote(NOTE_ACTION);

        if (action == null || action.isBlank()) {
            logger.debug("HumifortisRiskCondition: no action in session — condition = false (allow)");
            return false;
        }

        boolean requiresStepUp = switch (action) {
            case "REQUIRE_MFA", "REQUIRE_WEBAUTHN", "CHALLENGE_MFA" -> true;
            case "ALLOW" -> false;
            case "DENY", "BLOCK" -> {
                // DENY should have been handled by the authenticator already.
                // If we reach here, let the sub-flow proceed (defense in depth).
                logger.warnf("HumifortisRiskCondition: DENY/BLOCK reached condition — forcing step-up");
                yield true;
            }
            default -> {
                logger.warnf("HumifortisRiskCondition: unknown action '%s' — defaulting to step-up", action);
                yield true;
            }
        };

        logger.debugf("HumifortisRiskCondition: action=%s → requiresStepUp=%s", action, requiresStepUp);
        return requiresStepUp;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Not used for conditional authenticators
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No required actions
    }

    @Override
    public void close() {
        // Nothing to close
    }
}


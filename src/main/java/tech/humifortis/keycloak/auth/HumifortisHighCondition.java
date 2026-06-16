package tech.humifortis.keycloak.auth;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Conditional authenticator that triggers the MFA sub-flow when the risk action
 * stored by {@link HumifortisRiskAuthenticator} requires step-up authentication.
 *
 * <h3>Flow position</h3>
 * <pre>
 *   Browser Flow
 *     ├── Username / Password form       (Required)
 *     ├── Humifortis Risk Authenticator  (Required)  ← sets HUMIFORTIS_RISK_ACTION + LEVEL
 *     └── Force MFA (Conditional)
 *           ├── Condition — Humifortis high risk  (Required)  ← this class
 *           └── OTP / WebAuthn form               (Required)
 * </pre>
 *
 * <h3>Contract</h3>
 * {@code matchCondition} returns {@code true} when:
 * <ul>
 *   <li>action is REQUIRE_MFA, REQUIRE_WEBAUTHN, or REQUIRE_EMAIL_OTP — primary check</li>
 *   <li>or risk level is MEDIUM, HIGH, or CRITICAL — fallback for backward compat</li>
 * </ul>
 */
public class HumifortisHighCondition implements ConditionalAuthenticator {

    private static final Logger logger = Logger.getLogger(HumifortisHighCondition.class);

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        // Primary: server action (most accurate — set by HumifortisRiskAuthenticator)
        String action = context.getAuthenticationSession()
                               .getAuthNote(HumifortisRiskAuthenticator.NOTE_RISK_ACTION);

        if (action != null && !action.isBlank()) {
            boolean match = switch (action) {
                case "REQUIRE_MFA", "REQUIRE_WEBAUTHN", "REQUIRE_EMAIL_OTP" -> true;
                case "ALLOW"                                                 -> false;
                case "DENY", "LOCK_ACCOUNT"                                  -> false; // handled upstream
                default                                                      -> true;  // unknown → challenge
            };
            logger.infof("[HumifortisHighCondition] action=%s match=%s", action, match);
            return match;
        }

        // Fallback: risk level (backward compatibility with older flows)
        String level = context.getAuthenticationSession()
                              .getAuthNote(HumifortisRiskAuthenticator.NOTE_RISK_LEVEL);

        boolean match = "HIGH".equals(level) || "MEDIUM".equals(level) || "CRITICAL".equals(level);
        logger.infof("[HumifortisHighCondition] level=%s match=%s (fallback)", level, match);
        return match;
    }

    @Override public void authenticate(AuthenticationFlowContext context) { context.success(); }
    @Override public void action(AuthenticationFlowContext context)       { context.success(); }
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(KeycloakSession s, RealmModel r, UserModel u) { return true; }
    @Override public void setRequiredActions(KeycloakSession s, RealmModel r, UserModel u) {}
    @Override public void close() {}
}
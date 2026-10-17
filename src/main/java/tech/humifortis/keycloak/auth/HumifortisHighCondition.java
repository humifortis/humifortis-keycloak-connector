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
 *     ├── Username / Password form          (Required, priority=10)
 *     ├── Humifortis Device Collector       (Required, priority=15) ← collects device signals
 *     ├── Humifortis Risk Authenticator     (Required, priority=20) ← sets HUMIFORTIS_RISK_ACTION + LEVEL
 *     └── Force MFA (Conditional,          priority=30)
 *           ├── Condition — Humifortis high risk  (Required)  ← this class
 *           └── OTP / WebAuthn form               (Required)
 * </pre>
 *
 * <h3>Contract</h3>
 * {@code matchCondition} returns {@code true} when:
 * <ul>
 *   <li>action is one of {@link StepUpActions#ALL} — primary check</li>
 *   <li>or risk level is MEDIUM, HIGH, or CRITICAL — fallback for backward compat</li>
 * </ul>
 */
public class HumifortisHighCondition implements ConditionalAuthenticator {

    private static final Logger logger = Logger.getLogger(HumifortisHighCondition.class);

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        // The platform's decision is X (step-up by default, deny when configured): the action Humifortis returned,
        // written by HumifortisRiskAuthenticator. It never matches in dry_run / shadow under the local source, and with
        // no notes at all it asks for a step-up: friction, never a silent allow (docs/risk-as-data.spec.md, D4, D11).
        String configured = ContextCondition.configOf(context).get(CONFIG_OUTCOME);
        String outcome = ContextConditions.OUTCOME_DENY.equals(configured) ? ContextConditions.OUTCOME_DENY : ContextConditions.OUTCOME_STEP_UP;
        boolean match = ContextConditions.platformDecision(ContextCondition.notesOf(context.getAuthenticationSession()), outcome);
        logger.infof("[HumifortisHighCondition] outcome=%s match=%s", outcome, match);
        return match;
    }

    /** The configuration key naming the outcome of the platform's decision this condition tests. */
    static final String CONFIG_OUTCOME = "outcome";

    @Override public void authenticate(AuthenticationFlowContext context) { context.success(); }
    @Override public void action(AuthenticationFlowContext context)       { context.success(); }
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(KeycloakSession s, RealmModel r, UserModel u) { return true; }
    @Override public void setRequiredActions(KeycloakSession s, RealmModel r, UserModel u) {}
    @Override public void close() {}
}
package tech.humifortis.keycloak.auth;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.CommonClientSessionModel.ExecutionStatus;
import tech.humifortis.keycloak.client.EventQueue;
import tech.humifortis.keycloak.client.SaasConfig;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * The last step of a flow under the local decision source: it reports what the realm's own flow did with the decision
 * of this login (docs/risk-as-data.spec.md, D15). The report is {@code decision_enforced} with
 * {@code decision_source=local}: the action the platform decided as {@code requested_action}, and as
 * {@code enforced_action} what the flow applied, derived from what ran: a second factor that completed is a step-up,
 * the end of the flow with none is an allow. A denial ends in Keycloak's <em>Deny access</em> and never reaches this
 * step; the event listener already sees it as a login error.
 *
 * <p>Placed inside the deny sub-flow, just before <em>Deny access</em>, with {@code outcome = deny}, it reports the denial
 * the flow is about to apply: the deny step ends the flow and nothing after it can report.</p>
 *
 * <p>It does nothing when no report is pending (server source, a fallback, a missing context, a deny already reported)
 * and never blocks a login. Place it last in the flow, after the second-factor sub-flow.</p>
 */
public final class HumifortisDecisionReport implements Authenticator {

    private static final Logger logger = Logger.getLogger(HumifortisDecisionReport.class);

    /** The configuration key and value that make this step report a denial instead of deriving the outcome. */
    static final String CONFIG_OUTCOME = "outcome";
    static final String OUTCOME_DENY = "deny";

    /** The authenticators whose success is a second factor completed. */
    static final Set<String> SECOND_FACTORS = Set.of(
            "auth-otp-form", "webauthn-authenticator", "webauthn-authenticator-passwordless",
            "auth-recovery-authn-code-form", HumifortisStepUpRouterFactory.PROVIDER_ID);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        try {
            report(context);
        } catch (RuntimeException e) {
            // a report is best effort: it never blocks a login
            logger.debugf("[HumifortisDecisionReport] report failed: %s", e.getMessage());
        }
        context.success();
    }

    private void report(AuthenticationFlowContext context) {
        AuthenticationSessionModel session = context.getAuthenticationSession();
        ContextNotes.Notes notes = ContextCondition.notesOf(session);
        if (!ContextNotes.REPORT_PENDING.equals(notes.get(ContextNotes.REPORT))) return;
        notes.remove(ContextNotes.REPORT);   // one report per decision, even if the flow is run again

        SaasConfig config = SaasConfig.fromEnv();
        UserModel user = context.getUser();
        if (!config.hasApiKey() || user == null) return;

        String requested = notes.get(HumifortisRiskAuthenticator.NOTE_RISK_ACTION);
        boolean denying = OUTCOME_DENY.equals(ContextCondition.configOf(context).get(CONFIG_OUTCOME));
        boolean secondFactor = !denying && secondFactorCompleted(session, context.getRealm());
        String enforced = denying ? denyAction(requested) : enforcedAction(requested, secondFactor);

        RealmModel realm = context.getRealm();
        Map<String, String> extra = new LinkedHashMap<>();
        extra.put("decision_source", "local");
        extra.put("username", user.getUsername());
        extra.put("risk_level", notes.get(ContextNotes.LEVEL));
        extra.put("risk_score", notes.get(ContextNotes.SCORE));
        extra.put("decision_rule", notes.get(ContextNotes.REPORT_RULE));
        extra.put("policy_source", notes.get(ContextNotes.REPORT_SOURCE));
        extra.put("record_id", notes.get(ContextNotes.RECORD));
        extra.put("second_factor_completed", String.valueOf(secondFactor));
        // the flow is the customer's: what the person experienced is what the flow did, whatever the platform mode
        extra.put("outcome", DecisionReport.outcomeOf(enforced));
        var client = session.getClient();
        if (client != null) extra.put("client_id", client.getClientId());

        String flowId = null;
        try {
            flowId = session.getParentSession().getId();
        } catch (RuntimeException e) {
            logger.debugf("[HumifortisDecisionReport] no flow id: %s", e.getMessage());
        }
        String mode = notes.get(ContextNotes.REPORT_MODE);
        EventQueue.shared(config).submit(DecisionReport.build(DecisionReport.DECISION_ENFORCED,
                HumifortisRiskEvaluator.buildEntityId(realm, user), DecisionReport.USER, flowId, realm.getName(),
                requested, enforced, mode != null ? mode : "enforce", extra));
    }

    /** The action of a denial the flow applies: the platform's own deny action, else a plain deny. */
    static String denyAction(String platformAction) {
        return "LOCK_ACCOUNT".equals(platformAction) ? platformAction : "DENY";
    }

    /** What the flow applied: a completed second factor is a step-up (the platform's own if it asked for one), otherwise an allow. */
    static String enforcedAction(String platformAction, boolean secondFactorCompleted) {
        if (!secondFactorCompleted) return "ALLOW";
        return StepUpActions.isStepUp(platformAction) ? platformAction : "REQUIRE_MFA";
    }

    /** Whether an execution of this authentication session that is a second factor succeeded. */
    static boolean secondFactorCompleted(AuthenticationSessionModel session, RealmModel realm) {
        Map<String, ExecutionStatus> statuses = session.getExecutionStatus();
        if (statuses == null) return false;
        for (Map.Entry<String, ExecutionStatus> e : statuses.entrySet()) {
            if (e.getValue() != ExecutionStatus.SUCCESS) continue;
            AuthenticationExecutionModel execution = realm.getAuthenticationExecutionById(e.getKey());
            if (execution != null && execution.getAuthenticator() != null && SECOND_FACTORS.contains(execution.getAuthenticator())) {
                return true;
            }
        }
        return false;
    }

    @Override public void action(AuthenticationFlowContext context) {}
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(KeycloakSession s, RealmModel r, UserModel u) { return true; }
    @Override public void setRequiredActions(KeycloakSession s, RealmModel r, UserModel u) {}
    @Override public void close() {}
}

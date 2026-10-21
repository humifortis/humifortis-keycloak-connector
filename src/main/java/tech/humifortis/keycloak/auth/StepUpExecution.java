package tech.humifortis.keycloak.auth;

import java.util.LinkedHashMap;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import tech.humifortis.keycloak.client.EventQueue;
import tech.humifortis.keycloak.client.RateLimitedLog;
import tech.humifortis.keycloak.client.SaasConfig;
import tech.humifortis.keycloak.model.HumifortisEvent;

/**
 * A step-up that was decided and enforced but never ran. The risk authenticator lets the flow go on after a step-up
 * decision: the MFA sub-flow (Humifortis high condition + step-up router) is what challenges. A realm without that
 * sub-flow signs the person in with no second factor while the decision report says "step_up". When the login
 * completes that way, the connector sends a second report for the same flow saying what really happened
 * ({@code outcome=allow}, {@code divergence=step_up_not_executed}) and logs the misconfiguration.
 */
public final class StepUpExecution {

    private static final Logger logger = Logger.getLogger(StepUpExecution.class);
    private static final RateLimitedLog misconfigLog = new RateLimitedLog(60_000);

    public static final String DIVERGENCE = "divergence";
    public static final String NOT_EXECUTED = "step_up_not_executed";

    private StepUpExecution() {}

    /**
     * True when this authentication session enforced a step-up decision of the server and no second factor ran.
     * Not in dry_run / shadow (nothing was to be enforced) and not under the local decision source (the realm's own
     * flow decides and reports what it did).
     */
    static boolean skipped(AuthenticationSessionModel as, RealmModel realm) {
        if (as == null) return false;
        if (!StepUpActions.isStepUp(as.getAuthNote(HumifortisRiskAuthenticator.NOTE_RISK_ACTION))) return false;
        if (as.getAuthNote("humifortis_mode") != null) return false;
        if (as.getAuthNote(ContextNotes.REPORT_MODE) != null) return false;
        String method = as.getAuthNote(HumifortisStepUpRouter.NOTE_MFA_METHOD);
        if (method != null && !method.isBlank()) return false;
        return !HumifortisDecisionReport.secondFactorCompleted(as, realm);
    }

    /** Reports a skipped step-up of a completed login (best effort, never throws). */
    public static void reportIfSkipped(AuthenticationSessionModel as, RealmModel realm, UserModel user) {
        try {
            if (user == null || !skipped(as, realm)) return;
            String requested = as.getAuthNote(HumifortisRiskAuthenticator.NOTE_RISK_ACTION);
            misconfigLog.error(logger, "[Humifortis] step-up " + requested + " decided but no second factor ran: the browser"
                    + " flow has no MFA sub-flow (Humifortis high condition + Humifortis step-up router) after the risk"
                    + " authenticator — the person was signed in without a step-up (realm=" + realm.getName() + ")");
            SaasConfig config = SaasConfig.fromEnv();
            if (!config.hasApiKey()) return;
            Map<String, String> extra = new LinkedHashMap<>();
            extra.put("username", user.getUsername());
            extra.put("risk_level", as.getAuthNote(HumifortisRiskAuthenticator.NOTE_RISK_LEVEL));
            if (as.getClient() != null) extra.put("client_id", as.getClient().getClientId());
            extra.put(DIVERGENCE, NOT_EXECUTED);
            String flowId = as.getParentSession() != null ? as.getParentSession().getId() : null;
            HumifortisEvent report = DecisionReport.build(DecisionReport.DECISION_ENFORCED,
                    HumifortisRiskEvaluator.buildEntityId(realm, user), DecisionReport.USER, flowId, realm.getName(),
                    requested, "ALLOW", "enforce", extra);
            EventQueue.shared(config).submit(report);
        } catch (RuntimeException e) {
            logger.debugf("[Humifortis] step-up execution check failed: %s", e.getMessage());
        }
    }
}

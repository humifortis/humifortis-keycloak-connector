package tech.humifortis.keycloak.token;

import java.util.LinkedHashMap;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import tech.humifortis.keycloak.auth.DecisionReport;
import tech.humifortis.keycloak.auth.HumifortisRiskAuthenticator;
import tech.humifortis.keycloak.auth.HumifortisRiskEvaluator;
import tech.humifortis.keycloak.client.EventQueue;
import tech.humifortis.keycloak.client.SaasConfig;
import tech.humifortis.keycloak.serviceaccount.ServiceAccountRiskExecutor;

/**
 * What the token stages (refresh, token exchange) share: ask Humifortis for the decision about the person a token request
 * is for, report it, and say whether the request must be refused. A token endpoint has no page, so a second factor cannot
 * be asked: a deny and a step-up both refuse (the client sends the person through the browser flow again).
 *
 * <p>Fail-open: no answer lets the request go on, unless the client says {@code humifortis.fallback=deny}; a client with
 * {@code humifortis.enforcement=off} is never evaluated; nothing is refused in {@code dry_run} and {@code shadow}.</p>
 */
public final class TokenRiskStage {

    private static final Logger LOG = Logger.getLogger(TokenRiskStage.class);

    /** The error description of a refusal: the listener recognises the error event it produces and does not count it. */
    static final String DENY_DESCRIPTION = "humifortis_risk";

    private TokenRiskStage() {}

    /** What the stage does with the answer. */
    record Verdict(String requested, String applied, String mode, boolean refuse) {}

    /**
     * Evaluates the request; null when the stage does not apply (not configured, client exempt, no known person).
     * Reports the decision. Never throws: a fault of the stage never refuses a request.
     */
    static Verdict evaluate(KeycloakSession session, String stage, UserModel user, String flowId) {
        try {
            RealmModel realm = session.getContext().getRealm();
            ClientModel client = session.getContext().getClient();
            if (realm == null || client == null || user == null) return null;
            if ("off".equalsIgnoreCase(attr(client, ServiceAccountRiskExecutor.ATTR_ENFORCEMENT))) return null;
            SaasConfig config = SaasConfig.fromEnv();
            if (!config.hasApiKey()) return null; // not configured: nothing changes

            HumifortisRiskEvaluator.EvaluateResponse d = new HumifortisRiskEvaluator(session).decisionFor(realm, user, flowId);
            Verdict v = decide(d, attr(client, ServiceAccountRiskExecutor.ATTR_FALLBACK));

            Map<String, String> extra = new LinkedHashMap<>();
            extra.put("username", user.getUsername());
            extra.put("client_id", client.getClientId());
            extra.put("decision_stage", stage);
            if (d != null) {
                extra.put("risk_level", d.risk_level);
                extra.put("risk_score", String.valueOf(d.risk_score));
                extra.put("decision_rule", d.playbook_rule);
                extra.put("policy_source", d.policy_source);
            } else {
                extra.put("fallback_outcome", v.refuse() ? "deny" : "allow");
            }
            try {
                EventQueue.shared(config).submit(DecisionReport.build(
                        d != null ? DecisionReport.DECISION_ENFORCED : DecisionReport.FALLBACK_APPLIED,
                        HumifortisRiskEvaluator.buildEntityId(realm, user), DecisionReport.USER, flowId, realm.getName(),
                        v.requested(), v.applied(), v.mode(), extra));
            } catch (RuntimeException e) {
                LOG.debugf("[Humifortis] %s decision report failed: %s", stage, e.getMessage());
            }
            if (v.refuse()) LOG.infof("[Humifortis] %s of %s refused (%s)", stage, user.getUsername(), v.applied());
            return v;
        } catch (RuntimeException e) {
            LOG.warnf("[Humifortis] %s stage failed, the request continues: %s", stage, e.getMessage());
            return null;
        }
    }

    /** Pure: refuse on a deny or a step-up that is enforced; no answer follows the client's fallback. */
    static Verdict decide(HumifortisRiskEvaluator.EvaluateResponse d, String clientFallback) {
        if (d == null) {
            boolean deny = "deny".equalsIgnoreCase(clientFallback);
            String action = deny ? "DENY" : "ALLOW";
            return new Verdict(action, action, "enforce", deny);
        }
        String requested = d.action != null && !d.action.isBlank() ? d.action : "ALLOW";
        String applied = HumifortisRiskAuthenticator.appliedAction(d, requested);
        String mode = HumifortisRiskAuthenticator.resolveMode(d);
        return new Verdict(requested, applied, mode, DecisionReport.refusesToken(applied, mode));
    }

    /** The error event Keycloak emits when a token stage refuses: already reported by the decision, never a credential failure. */
    public static boolean isRefusal(Map<String, String> details) {
        return details != null && DENY_DESCRIPTION.equals(details.get("client_policy_error_detail"));
    }

    private static String attr(ClientModel client, String name) {
        String v = client.getAttribute(name);
        return v != null ? v.trim() : null;
    }
}

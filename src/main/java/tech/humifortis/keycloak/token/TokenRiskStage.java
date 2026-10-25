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
        return evaluate(session, stage, user, flowId, null);
    }

    /** As above; {@code more} is added to the decision report (a machine acting for the person names itself, MA-3). */
    static Verdict evaluate(KeycloakSession session, String stage, UserModel user, String flowId, Map<String, String> more) {
        return evaluate(session, stage, user, flowId, null, null, more);
    }

    /** The key under which the stage tells the listener that it evaluated this request (core then has one evaluation, not two). */
    public static final String SESSION_ATTR_EVALUATED = "hf.token.evaluated";

    /**
     * As above, for a touch that is its own kind of event ({@code eventType}, for example a refresh) with facts of its own
     * ({@code context}); both null judge it as the exchange is judged. The epoch the artefact was issued in is read from the
     * session it belongs to and the epoch of this decision is noted on it when the touch is let through.
     */
    static Verdict evaluate(KeycloakSession session, String stage, UserModel user, String flowId, String eventType,
                            tech.humifortis.keycloak.auth.StageContext context) {
        return evaluate(session, stage, user, flowId, eventType, context, null);
    }

    private static Verdict evaluate(KeycloakSession session, String stage, UserModel user, String flowId, String eventType,
                                    tech.humifortis.keycloak.auth.StageContext context, Map<String, String> more) {
        try {
            RealmModel realm = session.getContext().getRealm();
            ClientModel client = session.getContext().getClient();
            if (realm == null || client == null || user == null) return null;
            if ("off".equalsIgnoreCase(attr(client, ServiceAccountRiskExecutor.ATTR_ENFORCEMENT))) return null;
            SaasConfig config = SaasConfig.fromEnv();
            if (!config.hasApiKey()) return null; // not configured: nothing changes

            org.keycloak.models.UserSessionModel userSession = userSessionOf(session, realm, flowId);
            Long issuedIn = RiskEpoch.of(userSession);
            if (issuedIn != null) {
                java.util.Map<String, String> extra = new LinkedHashMap<>(context != null && context.extra() != null ? context.extra() : Map.of());
                extra.put(RiskEpoch.METADATA_KEY, String.valueOf(issuedIn));
                context = new tech.humifortis.keycloak.auth.StageContext(extra, context == null || context.personNetwork(),
                        context != null ? context.currentSessionId() : null);
            }
            session.setAttribute(SESSION_ATTR_EVALUATED, Boolean.TRUE);
            HumifortisRiskEvaluator evaluator = new HumifortisRiskEvaluator(session);
            HumifortisRiskEvaluator.EvaluateResponse d = eventType == null
                    ? evaluator.decisionFor(realm, user, flowId)
                    : evaluator.decisionFor(realm, user, flowId, eventType, context);
            Verdict v = decide(d, attr(client, ServiceAccountRiskExecutor.ATTR_FALLBACK));

            Map<String, String> extra = new LinkedHashMap<>();
            extra.put("username", user.getUsername());
            extra.put("client_id", client.getClientId());
            extra.put("decision_stage", stage);
            if (more != null) extra.putAll(more);
            if (d != null) {
                extra.put("risk_level", d.risk_level);
                extra.put("risk_score", String.valueOf(d.risk_score));
                extra.put("decision_rule", d.playbook_rule);
                extra.put("policy_source", d.policy_source);
                if (issuedIn != null) extra.put(RiskEpoch.METADATA_KEY, String.valueOf(issuedIn));
                if (!v.refuse()) RiskEpoch.record(userSession, d.risk_epoch);
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

    /** The user session a token belongs to (the id is the session id the token carries), or null. */
    private static org.keycloak.models.UserSessionModel userSessionOf(KeycloakSession session, RealmModel realm, String sessionId) {
        if (sessionId == null || sessionId.isBlank()) return null;
        try {
            org.keycloak.models.UserSessionModel us = session.sessions().getUserSession(realm, sessionId);
            return us != null ? us : session.sessions().getOfflineUserSession(realm, sessionId);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String attr(ClientModel client, String name) {
        String v = client.getAttribute(name);
        return v != null ? v.trim() : null;
    }
}

package tech.humifortis.keycloak.auth;

import java.util.LinkedHashMap;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import tech.humifortis.keycloak.client.EventQueue;
import tech.humifortis.keycloak.client.SaasConfig;
import tech.humifortis.keycloak.model.HumifortisEvent;

/**
 * The risk step of the realm's <em>Direct grant</em> flow (the OAuth password grant: a client sends the username and
 * password itself). Placed after the password step it asks Humifortis for the decision of the sign-in and refuses the
 * token when the decision is a deny or a step-up: no page exists in this flow, so a second factor cannot be asked and a
 * token must not be issued without it. The refusal is a {@code 401} with {@code error_description=humifortis_risk}.
 *
 * <p>Like every connector stage it never breaks a sign-in on a fault: with no answer from Humifortis the tenant's fallback
 * policy decides (allow unless it says deny), and in {@code dry_run} / {@code shadow} nothing is refused.</p>
 */
public class HumifortisDirectGrantAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(HumifortisDirectGrantAuthenticator.class);

    public static final String DECISION_STAGE = "direct_grant";
    public static final String DENY_DESCRIPTION = "humifortis_risk";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        try {
            decide(context);
        } catch (RuntimeException e) {
            // a fault of this stage never refuses a sign-in (the fallback of "no decision" is to let the grant go on)
            logger.warnf("[HumifortisDirectGrant] stage failed, grant continues: %s", e.getMessage());
            context.success();
        }
    }

    private void decide(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        RealmModel realm = context.getRealm();
        if (user == null) {
            context.success();
            return;
        }
        String flowId = context.getAuthenticationSession().getParentSession() != null
                ? context.getAuthenticationSession().getParentSession().getId() : null;
        HumifortisRiskEvaluator.EvaluationResult result =
                new HumifortisRiskEvaluator(context.getSession()).evaluateDetailed(realm, user, flowId, false);
        HumifortisRiskEvaluator.EvaluateResponse d = result.decision();

        String requested;
        String applied;
        String mode;
        if (d != null) {
            requested = d.action != null && !d.action.isBlank() ? d.action : "ALLOW";
            applied = HumifortisRiskAuthenticator.appliedAction(d, requested);
            mode = HumifortisRiskAuthenticator.resolveMode(d);
        } else {
            // no answer: the tenant's fallback policy; no second factor can be asked here, so a step-up is unavailable
            SaasConfig config = SaasConfig.fromEnv();
            FallbackPolicy.Decision fb = FallbackPolicy.resolve(config.getFallbackOverride(),
                    config.tenantIdOr(realm.getName()), false, false);
            requested = fb.outcome() == FallbackPolicy.Outcome.DENY ? "DENY" : "ALLOW";
            applied = requested;
            String cached = FallbackPolicy.cachedMode(config.tenantIdOr(realm.getName()));
            mode = cached != null ? cached : "enforce";
        }

        boolean refuse = refuses(applied, mode);
        report(context, user, flowId, d, requested, applied, mode);
        if (refuse) {
            context.failure(AuthenticationFlowError.ACCESS_DENIED, refusal());
        } else {
            context.success();
        }
    }

    /** True when the grant must be refused: a deny or a step-up that is enforced (not in dry_run / shadow). */
    static boolean refuses(String appliedAction, String mode) {
        return DecisionReport.refusesToken(appliedAction, mode);
    }

    /** The token endpoint's answer to a refused grant. */
    static Response refusal() {
        return Response.status(Response.Status.UNAUTHORIZED)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .entity(Map.of("error", "access_denied", "error_description", DENY_DESCRIPTION))
                .build();
    }

    private void report(AuthenticationFlowContext context, UserModel user, String flowId,
                        HumifortisRiskEvaluator.EvaluateResponse d, String requested, String applied, String mode) {
        try {
            SaasConfig config = SaasConfig.fromEnv();
            if (!config.hasApiKey()) return;
            RealmModel realm = context.getRealm();
            Map<String, String> extra = new LinkedHashMap<>();
            extra.put("username", user.getUsername());
            extra.put("decision_stage", DECISION_STAGE);
            extra.put("grant_type", "password");
            if (context.getAuthenticationSession().getClient() != null) {
                extra.put("client_id", context.getAuthenticationSession().getClient().getClientId());
            }
            String type = DecisionReport.DECISION_ENFORCED;
            if (d != null) {
                extra.put("risk_level", d.risk_level);
                extra.put("risk_score", String.valueOf(d.risk_score));
                extra.put("decision_rule", d.playbook_rule);
                extra.put("policy_source", d.policy_source);
            } else {
                type = DecisionReport.FALLBACK_APPLIED;
                extra.put("fallback_outcome", "ALLOW".equals(applied) ? "allow" : "deny");
            }
            HumifortisEvent event = DecisionReport.build(type, HumifortisRiskEvaluator.buildEntityId(realm, user),
                    DecisionReport.USER, flowId, realm.getName(), requested, applied, mode, extra);
            EventQueue.shared(config).submit(event);
        } catch (RuntimeException e) {
            logger.debugf("[HumifortisDirectGrant] decision report failed: %s", e.getMessage());
        }
    }

    @Override public void action(AuthenticationFlowContext context) { }
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(KeycloakSession s, RealmModel r, UserModel u) { return true; }
    @Override public void setRequiredActions(KeycloakSession s, RealmModel r, UserModel u) { }
    @Override public void close() { }
}

package tech.humifortis.keycloak.auth;

import java.util.LinkedHashMap;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.managers.AuthenticationManager;

import jakarta.ws.rs.core.Response;
import tech.humifortis.keycloak.client.SaasConfig;
import tech.humifortis.keycloak.client.EventQueue;
import tech.humifortis.keycloak.model.HumifortisEvent;

/**
 * Evaluates a sign-in that skipped the password flow: the single-sign-on cookie of an existing session used for another
 * application. Keycloak runs the {@code evaluateTriggers} of every enabled required action on each completed
 * authentication, so one toggle in <em>Authentication → Required actions</em> covers it, with no flow to edit.
 *
 * <p>A decision other than an allow ends the reused session and shows an error page: the next sign-in runs the full
 * browser flow, where the risk step and the MFA sub-flow decide and challenge. In {@code dry_run} / {@code shadow} the
 * decision is reported and nothing is refused. A fault of this stage, or no answer from Humifortis with a tenant policy
 * that allows, never stops a sign-in.</p>
 */
public class HumifortisSessionCheck implements RequiredActionProvider {

    private static final Logger logger = Logger.getLogger(HumifortisSessionCheck.class);

    public static final String PROVIDER_ID = "humifortis-session-check";
    public static final String DECISION_STAGE = "session_reuse";
    public static final String NOTE_SESSION_CHECKED = "HUMIFORTIS_SESSION_CHECKED";
    public static final String ERROR_MESSAGE = "humifortisSessionRefused";

    /** Keycloak's mark of an authentication session that came from the identity cookie. */
    static final String NOTE_SSO_AUTH = "SSO_AUTH";

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        try {
            var authSession = context.getAuthenticationSession();
            // the password flow decided, or this reuse was already evaluated in this authentication session
            if (authSession.getAuthNote(HumifortisRiskAuthenticator.NOTE_RISK_ACTION) != null) return;
            if (authSession.getAuthNote(NOTE_SESSION_CHECKED) != null) return;
            if (!"true".equals(authSession.getAuthNote(NOTE_SSO_AUTH))) return;
            authSession.setAuthNote(NOTE_SESSION_CHECKED, "true");

            UserModel user = context.getUser();
            RealmModel realm = context.getRealm();
            if (user == null) return;
            String flowId = authSession.getParentSession() != null ? authSession.getParentSession().getId() : null;
            HumifortisRiskEvaluator.EvaluateResponse d = evaluate(context.getSession(), realm, user, flowId);

            String requested;
            String applied;
            String mode;
            if (d != null) {
                requested = d.action != null && !d.action.isBlank() ? d.action : "ALLOW";
                applied = HumifortisRiskAuthenticator.appliedAction(d, requested);
                mode = HumifortisRiskAuthenticator.resolveMode(d);
            } else {
                SaasConfig config = SaasConfig.fromEnv();
                String tenant = config.tenantIdOr(realm.getName());
                FallbackPolicy.Decision fb = FallbackPolicy.resolve(config.getFallbackOverride(), tenant, false, false);
                requested = fb.outcome() == FallbackPolicy.Outcome.DENY ? "DENY" : "ALLOW";
                applied = requested;
                String cached = FallbackPolicy.cachedMode(tenant);
                mode = cached != null ? cached : "enforce";
            }
            report(context, user, flowId, d, requested, applied, mode);
            if (DecisionReport.refusesToken(applied, mode)) {
                authSession.setAuthNote(HumifortisRiskAuthenticator.NOTE_RISK_ACTION, applied);
                authSession.addRequiredAction(PROVIDER_ID);
            }
        } catch (RuntimeException e) {
            // a fault of this stage never stops a sign-in
            logger.warnf("[HumifortisSessionCheck] stage failed, sign-in continues: %s", e.getMessage());
        }
    }

    /** The decision for the reused session; null when Humifortis did not answer. Overridable for tests. */
    HumifortisRiskEvaluator.EvaluateResponse evaluate(KeycloakSession session, RealmModel realm, UserModel user, String flowId) {
        return new HumifortisRiskEvaluator(session)
                .evaluateDetailed(realm, user, flowId, false, HumifortisRiskEvaluator.EVENT_SESSION_REUSED).decision();
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        try {
            endReusedSession(context.getSession(), context.getRealm());
        } catch (RuntimeException e) {
            logger.warnf("[HumifortisSessionCheck] reused session not ended: %s", e.getMessage());
        }
        Response page = context.getSession().getProvider(LoginFormsProvider.class)
                .setAuthenticationSession(context.getAuthenticationSession())
                .setError(ERROR_MESSAGE)
                .createErrorPage(Response.Status.FORBIDDEN);
        context.challenge(page);
    }

    /** Ends the single-sign-on session the cookie points to: the person signs in again, in full. */
    void endReusedSession(KeycloakSession session, RealmModel realm) {
        AuthenticationManager.AuthResult auth = AuthenticationManager.authenticateIdentityCookie(session, realm, true);
        if (auth == null) return;
        UserSessionModel us = auth.getSession();
        if (us != null) session.sessions().removeUserSession(realm, us);
    }

    private void report(RequiredActionContext context, UserModel user, String flowId,
                        HumifortisRiskEvaluator.EvaluateResponse d, String requested, String applied, String mode) {
        try {
            SaasConfig config = SaasConfig.fromEnv();
            if (!config.hasApiKey()) return;
            RealmModel realm = context.getRealm();
            Map<String, String> extra = new LinkedHashMap<>();
            extra.put("username", user.getUsername());
            extra.put("decision_stage", DECISION_STAGE);
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
            logger.debugf("[HumifortisSessionCheck] decision report failed: %s", e.getMessage());
        }
    }

    @Override public void processAction(RequiredActionContext context) { context.failure(); }
    @Override public void close() { }
}

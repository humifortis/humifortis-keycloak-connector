package tech.humifortis.keycloak.serviceaccount;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.idm.ClientPolicyExecutorConfigurationRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.context.ServiceAccountTokenRequestContext;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider;

import tech.humifortis.keycloak.auth.DecisionReport;
import tech.humifortis.keycloak.auth.HumifortisRiskEvaluator;
import tech.humifortis.keycloak.client.EventQueue;
import tech.humifortis.keycloak.client.ProxySettings;
import tech.humifortis.keycloak.client.SaasConfig;
import tech.humifortis.keycloak.user.UserContextExtractor;

/**
 * The risk stage of a service-account token request (docs/service-account-risk-and-enforcement.spec.md).
 *
 * <p>Runs on the client-policy event {@code SERVICE_ACCOUNT_TOKEN_REQUEST}, before the token exists: it collects the
 * context, asks Humifortis for the decision ({@code POST /evaluate}, the same call as the browser flow), refuses the
 * request when the decision is DENY in {@code enforce} mode — and disables the client first when the decision is
 * DISABLE_CLIENT and the client allows it ({@link ClientContainment}) — and reports what it did ({@code decision_enforced}
 * or {@code decision_fallback_applied}). It is attached to a realm by a client profile and a client policy (README,
 * "Service accounts: risk stage"); without them nothing changes.
 *
 * <p>Fail-open: when Humifortis does not answer within the budget the token is issued, unless the client says
 * {@code humifortis.fallback=deny}. A client with {@code humifortis.enforcement=off} is never evaluated.
 */
public class ServiceAccountRiskExecutor implements ClientPolicyExecutorProvider<ClientPolicyExecutorConfigurationRepresentation> {

    private static final Logger LOG = Logger.getLogger(ServiceAccountRiskExecutor.class);

    /** Client attribute: {@code off} exempts the client (never evaluated, never refused). */
    public static final String ATTR_ENFORCEMENT = "humifortis.enforcement";
    /** Client attribute: {@code deny} refuses the token when Humifortis does not answer (default: allow). */
    public static final String ATTR_FALLBACK = "humifortis.fallback";

    /** The OAuth error description of a refusal; the listener recognises the CLIENT_LOGIN_ERROR it produces. */
    public static final String DENY_DESCRIPTION = "humifortis_risk";
    /** KeycloakSession attribute set when this request was evaluated: the listener tags its CLIENT_LOGIN. */
    public static final String SESSION_ATTR_EVALUATED = "humifortis.sa.evaluated";
    /** The CLIENT_LOGIN detail telling core the request was already decided (no second decision). */
    public static final String DETAIL_DECISION_STAGE = "decision_stage";
    public static final String DECISION_STAGE_TOKEN_REQUEST = "token_request";

    /** What this stage can carry out for a request (sent as {@code executors} of /evaluate). */
    static final List<String> EXECUTORS = List.of("DENY");
    /** ... and for a client that lets Humifortis disable it. */
    static final List<String> EXECUTORS_WITH_DISABLE = List.of("DENY", "DISABLE_CLIENT");

    private final KeycloakSession session;
    private final Evaluate evaluate;
    private final Report report;

    /** The /evaluate call (replaced in tests). */
    interface Evaluate {
        HumifortisRiskEvaluator.ServiceAccountResult call(RealmModel realm, ClientModel client, String flowId,
                                                           Map<String, Object> metadata, List<String> executors);
    }

    /** The decision report (replaced in tests). */
    interface Report {
        void send(String type, String entityId, String flowId, RealmModel realm, String requested, String enforced,
                  String mode, Map<String, String> extra);
    }

    public ServiceAccountRiskExecutor(KeycloakSession session) {
        this(session,
                (realm, client, flowId, md, executors) -> new HumifortisRiskEvaluator(session)
                        .evaluateServiceAccount(realm, client, flowId, md, executors),
                (type, entityId, flowId, realm, requested, enforced, mode, extra) -> {
                    SaasConfig config = SaasConfig.fromEnv();
                    EventQueue.shared(config).submit(DecisionReport.build(type, entityId, DecisionReport.SERVICE_ACCOUNT,
                            flowId, realm.getName(), requested, enforced, mode, extra));
                });
    }

    ServiceAccountRiskExecutor(KeycloakSession session, Evaluate evaluate, Report report) {
        this.session = session;
        this.evaluate = evaluate;
        this.report = report;
    }

    @Override
    public String getProviderId() {
        return ServiceAccountRiskExecutorFactory.PROVIDER_ID;
    }

    @Override
    public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {
        // the policy also calls executors on client administration events: only token requests matter
        if (context.getEvent() != ClientPolicyEvent.SERVICE_ACCOUNT_TOKEN_REQUEST
                || !(context instanceof ServiceAccountTokenRequestContext sa)) {
            return;
        }
        RealmModel realm = session.getContext().getRealm();
        ClientModel client = session.getContext().getClient();
        if (realm == null || client == null || !client.isServiceAccountsEnabled()) return;
        if ("off".equalsIgnoreCase(attr(client, ATTR_ENFORCEMENT))) return; // exempt (break-glass, own automation)
        if (!SaasConfig.fromEnv().hasApiKey()) return;                      // not configured: nothing changes

        AuthenticatedClientSessionModel clientSession = sa.getClientSession();
        UserSessionModel userSession = clientSession != null ? clientSession.getUserSession() : null;
        // the CLIENT_LOGIN of this request carries the same session id: both events are one flow (counted once)
        String flowId = userSession != null ? userSession.getId() : null;
        String requestedScope = sa.getParams() != null ? sa.getParams().getFirst("scope") : null;

        Map<String, Object> metadata = collect(realm, client, requestedScope);
        boolean allowDisable = ClientContainment.allowsDisable(client);
        HumifortisRiskEvaluator.ServiceAccountResult result = evaluate.call(realm, client, flowId, metadata,
                allowDisable ? EXECUTORS_WITH_DISABLE : EXECUTORS);
        session.setAttribute(SESSION_ATTR_EVALUATED, Boolean.TRUE);

        Decision d = decide(result, attr(client, ATTR_FALLBACK), allowDisable);
        String entityId = entityId(realm, client);
        Map<String, String> extra = new LinkedHashMap<>();
        extra.put("client_id", client.getClientId());
        Object ip = metadata.get("ip");
        if (ip != null) extra.put("ip", ip.toString());
        if (result.decision() != null) {
            var r = result.decision();
            extra.put("decision_rule", r.playbook_rule);
            extra.put("risk_level", r.risk_level);
            extra.put("risk_score", String.valueOf(r.risk_score));
            extra.put("advisory", String.valueOf(r.advisory));
            if (r.actions != null && !r.actions.isEmpty()) extra.put("all_actions", String.join(",", r.actions));
        } else {
            extra.put("fallback_reason", result.fallbackReason());
            extra.put("fallback_outcome", d.refuse ? "deny" : "allow");
        }
        if (d.disable) {
            // contained before the report, so the report says what was really done
            try {
                ClientContainment.Result done = ClientContainment.disable(client, "rule:" + result.decision().playbook_rule);
                if (done == ClientContainment.Result.DISABLED) {
                    extra.put("disabled", "true");
                    LOG.warnf("[Humifortis] client %s disabled by decision %s", client.getClientId(), result.decision().playbook_rule);
                }
            } catch (RuntimeException e) {
                extra.put("disable_error", e.getMessage() == null ? "error" : e.getMessage());
                LOG.warnf("[Humifortis] client %s could not be disabled: %s", client.getClientId(), e.getMessage());
            }
        }
        try {
            report.send(d.reportType, entityId, flowId, realm, d.requested, d.enforced, d.mode, extra);
        } catch (RuntimeException e) {
            LOG.debugf("[Humifortis] service-account decision report failed: %s", e.getMessage());
        }

        if (d.refuse) {
            LOG.infof("[Humifortis] token request of client %s refused (%s)", client.getClientId(),
                    result.decision() != null ? result.decision().playbook_rule : "fallback " + result.fallbackReason());
            throw new ClientPolicyException("access_denied", DENY_DESCRIPTION);
        }
    }

    /** What the stage does with the answer (pure; unit-tested): refuse the request, and disable the client first. */
    record Decision(String reportType, String requested, String enforced, String mode, boolean refuse, boolean disable) {}

    /** The CLIENT_LOGIN_ERROR Keycloak emits when this stage refuses a request (error access_denied, reason ours). */
    public static boolean isRiskStageRefusal(boolean clientLoginError, String error, Map<String, String> details) {
        return clientLoginError && "access_denied".equals(error) && details != null && DENY_DESCRIPTION.equals(details.get("reason"));
    }

    static Decision decide(HumifortisRiskEvaluator.ServiceAccountResult result, String clientFallback, boolean allowDisable) {
        var r = result.decision();
        if (r == null) {
            // without a decision nothing is contained: the fallback refuses at most
            boolean deny = "deny".equalsIgnoreCase(clientFallback);
            String action = deny ? "DENY" : "ALLOW";
            return new Decision(DecisionReport.FALLBACK_APPLIED, action, action, "enforce", deny, false);
        }
        String mode = r.mode != null && !r.mode.isBlank() ? r.mode.toLowerCase(Locale.ROOT) : "enforce";
        String enforced = r.enforced_action != null && !r.enforced_action.isBlank() ? r.enforced_action : "ALLOW";
        String requested = r.action != null && !r.action.isBlank() ? r.action : enforced;
        boolean applied = DecisionReport.applied(mode);
        // DISABLE_CLIENT is carried out for a client that allows it: decided alone (HIGH) or with DENY (CRITICAL);
        // an advisory decision comes back with enforced_action ALLOW
        boolean decidedDisable = "DISABLE_CLIENT".equals(enforced)
                || ("DENY".equals(enforced) && r.actions != null && r.actions.contains("DISABLE_CLIENT"));
        boolean disable = applied && allowDisable && decidedDisable;
        boolean refuse = applied && ("DENY".equals(enforced) || disable);
        return new Decision(DecisionReport.DECISION_ENFORCED, requested, enforced, mode, refuse, disable);
    }

    /** The context of the request, built from the same sources as the CLIENT_LOGIN enrichment. */
    Map<String, Object> collect(RealmModel realm, ClientModel client, String requestedScope) {
        Map<String, Object> md = new HashMap<>();
        String ip = null;
        try {
            var conn = session.getContext().getConnection();
            ip = conn != null ? conn.getRemoteAddr() : null;
        } catch (RuntimeException ignored) {
            // no connection: the address is not evaluated
        }
        if (ip != null && !ip.isBlank()) md.put("ip", ip);
        try {
            ProxySettings.current().writeTo(md::put);
            var headers = session.getContext().getRequestHeaders();
            String ua = headers != null ? headers.getHeaderString("User-Agent") : null;
            if (ua != null && !ua.isBlank()) md.put("user_agent", ua);
        } catch (RuntimeException ignored) {
            // headers unavailable: not evaluated
        }
        md.put("realm", realm.getName());
        md.put("client_id", client.getClientId());
        md.put("grant_type", "client_credentials");
        String authMethod = client.getClientAuthenticatorType();
        if (authMethod != null && !authMethod.isBlank()) md.put("client_auth_method", authMethod);
        md.put("identity_provider", "local");
        md.putAll(ServiceAccountContext.resolve(client.getAttributes(), ip, grantedScopes(client, requestedScope), Instant.now()));
        try {
            UserModel saUser = session.users().getServiceAccount(client);
            if (saUser != null) {
                new UserContextExtractor().extract(session, realm, saUser).writeTo(md::put);
                md.put("username", saUser.getUsername());
            }
        } catch (RuntimeException e) {
            LOG.debugf("[Humifortis] service-account identity context failed: %s", e.getMessage());
        }
        return md;
    }

    /**
     * The scopes the token will carry, as the CLIENT_LOGIN reports them: the client's default scopes, plus the optional
     * ones the request asks for (the {@code scope} parameter alone omits the defaults Keycloak adds later).
     */
    static String grantedScopes(ClientModel client, String requestedScope) {
        Set<String> out = new TreeSet<>();
        try {
            // only the scopes Keycloak puts in the token's scope claim (roles, web-origins, acr, basic are not)
            client.getClientScopes(true).forEach((name, scope) -> {
                if (scope == null || scope.isIncludeInTokenScope()) out.add(name);
            });
            if (requestedScope != null && !requestedScope.isBlank()) {
                Map<String, ClientScopeModel> optional = client.getClientScopes(false);
                for (String s : requestedScope.trim().split("\\s+")) {
                    ClientScopeModel scope = optional.get(s);
                    if (optional.containsKey(s) && (scope == null || scope.isIncludeInTokenScope())) out.add(s);
                }
            }
        } catch (RuntimeException ignored) {
            // scopes unavailable: only what was asked
            if (requestedScope != null) out.addAll(List.of(requestedScope.trim().split("\\s+")));
        }
        return out.isEmpty() ? null : String.join(" ", new ArrayList<>(out));
    }

    static String entityId(RealmModel realm, ClientModel client) {
        return String.format("service_account:keycloak:%s:%s", realm.getId(), client.getClientId());
    }

    private static String attr(ClientModel client, String name) {
        String v = client.getAttribute(name);
        return v != null ? v.trim() : null;
    }
}

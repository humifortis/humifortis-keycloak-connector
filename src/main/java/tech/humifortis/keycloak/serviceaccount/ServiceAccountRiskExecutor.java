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
import tech.humifortis.keycloak.client.EdgeRtt;
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
    /** The reason core reports for a decided DISABLE_CLIENT that this stage could carry out but the client did not allow. */
    static final Map<String, String> DECLINED_NOT_OPTED_IN = Map.of("DISABLE_CLIENT", "client_not_opted_in");

    private final KeycloakSession session;
    private final Evaluate evaluate;
    private final Report report;

    /** The /evaluate call (replaced in tests). */
    interface Evaluate {
        HumifortisRiskEvaluator.ServiceAccountResult call(RealmModel realm, ClientModel client, String flowId,
                                                           Map<String, Object> metadata, List<String> executors,
                                                           Map<String, String> declined);
    }

    /** The decision report (replaced in tests). */
    interface Report {
        void send(String type, String recordId, String entityId, String flowId, RealmModel realm, String requested,
                  String enforced, String mode, Map<String, String> extra);
    }

    public ServiceAccountRiskExecutor(KeycloakSession session) {
        this(session,
                (realm, client, flowId, md, executors, declined) -> new HumifortisRiskEvaluator(session)
                        .evaluateServiceAccount(realm, client, flowId, md, executors, declined),
                (type, recordId, entityId, flowId, realm, requested, enforced, mode, extra) -> {
                    SaasConfig config = SaasConfig.fromEnv();
                    EventQueue.shared(config).submit(DecisionReport.build(type, recordId, entityId, entityId.substring(0, entityId.indexOf(':')),
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
        // how the client proved its identity (P11): the method, and the subject of its certificate or token
        metadata.putAll(ClientAuthentication.resolve(client.getClientAuthenticatorType(),
                sa.getParams() != null ? sa.getParams().getFirst("client_assertion") : null, ClientAuthentication.certificateSubject(session)));
        // the tool server the token is for (RFC 8707 resource indicator): an agent asks for a token per tool (P17, AG-2)
        String resource = sa.getParams() != null ? sa.getParams().getFirst("resource") : null;
        if (resource != null && !resource.isBlank()) metadata.put("token.audience", resource.length() > 255 ? resource.substring(0, 255) : resource);
        decideAndEnforce(realm, client, flowId, metadata, null);
    }

    /** The decision stage of an exchange of the token of a service account (MA-2, MA-4). */
    public static final String DECISION_STAGE_TOKEN_EXCHANGE = "token_exchange";

    /**
     * A service account's token is exchanged (RFC 8693): decided as the machine it is, with the audience judged like a scope
     * (MA-2). {@code actor} is the client that presents the exchange when it is not the machine itself (a machine acting for
     * another machine, MA-4); it is on the decision report. Throws the refusal like the token request does.
     *
     * @param client the service account's client whose token is exchanged
     */
    public void executeExchange(ClientModel client, String flowId, String requestedScope, String audience, String actor) throws ClientPolicyException {
        runTokenStage(client, flowId, requestedScope, audience, actor, DECISION_STAGE_TOKEN_EXCHANGE, "urn:ietf:params:oauth:grant-type:token-exchange");
    }

    /** The decision stage of a refresh of the token of a service account (MA-6): a client configured to receive a refresh token. */
    public static final String DECISION_STAGE_TOKEN_REFRESH = "token_refresh";

    /** A service account refreshes a token it holds (MA-6): decided as the machine it is, like its token request. */
    public void executeRefresh(ClientModel client, String flowId) throws ClientPolicyException {
        runTokenStage(client, flowId, null, null, null, DECISION_STAGE_TOKEN_REFRESH, "refresh_token");
    }

    private void runTokenStage(ClientModel client, String flowId, String requestedScope, String audience, String actor, String stage, String grantType) throws ClientPolicyException {
        RealmModel realm = session.getContext().getRealm();
        if (realm == null || client == null || !client.isServiceAccountsEnabled()) return;
        if ("off".equalsIgnoreCase(attr(client, ATTR_ENFORCEMENT))) return;
        if (!SaasConfig.fromEnv().hasApiKey()) return;
        Map<String, Object> metadata = collect(realm, client, requestedScope);
        // the exchange is judged on its own scope and audience, not on the scopes the client is granted by default
        metadata.remove(ServiceAccountContext.KEY_REQUESTED_SCOPES);
        metadata.remove(ServiceAccountContext.KEY_HISTORICAL_SCOPES);
        metadata.putAll(ServiceAccountContext.resolveExchange(client.getAttributes(), (String) metadata.get("ip"), requestedScope, audience, Instant.now()));
        metadata.put("grant_type", grantType);
        Map<String, String> more = new LinkedHashMap<>();
        more.put(DETAIL_DECISION_STAGE, stage);
        if (audience != null && !audience.isBlank()) more.put("exchange_audience", audience.trim());
        if (actor != null && !actor.isBlank()) more.put("actor_client_id", actor);
        decideAndEnforce(realm, client, flowId, metadata, more);
    }

    private void decideAndEnforce(RealmModel realm, ClientModel client, String flowId, Map<String, Object> metadata,
                                  Map<String, String> more) throws ClientPolicyException {
        boolean allowDisable = ClientContainment.allowsDisable(client);
        HumifortisRiskEvaluator.ServiceAccountResult result = evaluate.call(realm, client, flowId, metadata,
                allowDisable ? EXECUTORS_WITH_DISABLE : EXECUTORS,
                allowDisable ? Map.of() : DECLINED_NOT_OPTED_IN);
        session.setAttribute(SESSION_ATTR_EVALUATED, Boolean.TRUE);

        Decision d = decide(result, attr(client, ATTR_FALLBACK), allowDisable);
        String entityId = entityId(realm, client);
        Map<String, String> extra = new LinkedHashMap<>();
        extra.put("client_id", client.getClientId());
        if (more != null) extra.putAll(more);
        Object ip = metadata.get("ip");
        if (ip != null) extra.put("ip", ip.toString());
        if (result.decision() != null) {
            var r = result.decision();
            extra.put("decision_rule", r.playbook_rule);
            extra.put("risk_level", r.risk_level);
            extra.put("risk_score", String.valueOf(r.risk_score));
            extra.put("advisory", String.valueOf(r.advisory));
            if (r.actions != null && !r.actions.isEmpty()) extra.put("all_actions", String.join(",", r.actions));
            String notEnforced = notEnforced(r, d.mode, d.enforced);
            if (!notEnforced.isEmpty()) extra.put("not_enforced", notEnforced);
        } else {
            extra.put("fallback_reason", result.fallbackReason());
            extra.put("fallback_outcome", d.refuse ? "deny" : "allow");
        }
        if (d.disable) {
            // contained before the report, so the report says what was really done
            try {
                ClientContainment.Result done = ClientContainment.disableCommitted(session, client, "rule:" + result.decision().playbook_rule);
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
            report.send(d.reportType, result.decision() != null ? result.decision().record_id : null, entityId, flowId, realm,
                    d.requested, d.enforced, d.mode, extra);
        } catch (RuntimeException e) {
            LOG.debugf("[Humifortis] service-account decision report failed: %s", e.getMessage());
        }

        if (d.refuse) {
            LOG.infof("[Humifortis] token request of client %s refused (%s)", client.getClientId(),
                    result.decision() != null ? result.decision().playbook_rule : "fallback " + result.fallbackReason());
            throw new ClientPolicyException("access_denied", DENY_DESCRIPTION);
        }
    }

    /**
     * The decided actions nothing carried out for this request, "ACTION:reason" comma-separated: core's list copied
     * verbatim (it knows the entity type's executors and the caller's declarations), plus the enforced action itself
     * when the mode lets the request through (shadow, dry run). The stage derives nothing else.
     */
    static String notEnforced(HumifortisRiskEvaluator.EvaluateResponse r, String mode, String enforced) {
        java.util.LinkedHashSet<String> out = new java.util.LinkedHashSet<>();
        if (r != null && r.not_enforced != null) {
            for (HumifortisRiskEvaluator.NotEnforcedItem n : r.not_enforced) {
                if (n != null && n.action != null && n.reason != null) out.add(n.action + ":" + n.reason);
            }
        }
        if (!DecisionReport.applied(mode) && enforced != null && !enforced.isBlank() && !"ALLOW".equals(enforced)) {
            out.add(enforced + ":mode_" + mode);
        }
        return String.join(",", out);
    }

    /** What the stage does with the answer (pure; unit-tested): refuse the request, and disable the client first. */
    record Decision(String reportType, String requested, String enforced, String mode, boolean refuse, boolean disable) {}

    /** The CLIENT_LOGIN_ERROR Keycloak emits when this stage refuses a request (error access_denied, reason ours). */
    public static boolean isRiskStageRefusal(boolean clientLoginError, String error, Map<String, String> details) {
        // Keycloak puts the text of a client-policy refusal in client_policy_error_detail (reason is then client_policy_error)
        return clientLoginError && "access_denied".equals(error) && details != null
                && (DENY_DESCRIPTION.equals(details.get("client_policy_error_detail")) || DENY_DESCRIPTION.equals(details.get("reason")));
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
            Integer rtt = EdgeRtt.fromHeaders(headers);
            if (rtt != null) {
                md.put(EdgeRtt.METADATA_KEY, rtt);
                md.put(EdgeRtt.SOURCE_KEY, EdgeRtt.EDGE);
            }
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
            String rotated = ServiceAccountContext.secretRotationAgeDays(client.getAttributes(),
                    saUser != null ? saUser.getCreatedTimestamp() : null, Instant.now());
            if (rotated != null) md.put(ServiceAccountContext.KEY_SECRET_ROTATION_AGE_DAYS, rotated);
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

    public static String entityId(RealmModel realm, ClientModel client) {
        // a service account, or an agent when the client declares it (P17): the type is the prefix of the id
        return ClientEntityType.entityId(ClientEntityType.of(client.getAttribute(ClientEntityType.ATTR)), realm.getId(), client.getClientId());
    }

    private static String attr(ClientModel client, String name) {
        String v = client.getAttribute(name);
        return v != null ? v.trim() : null;
    }
}

package tech.humifortis.keycloak.auth;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import tech.humifortis.keycloak.HumifortisError;
import tech.humifortis.keycloak.client.EventQueue;
import tech.humifortis.keycloak.client.SaasConfig;
import tech.humifortis.keycloak.model.Risk;
import tech.humifortis.keycloak.user.UserContextExtractor;
import tech.humifortis.keycloak.user.UserContextSnapshot;

import java.util.List;
import java.util.Locale;

/**
 * Risk-based authenticator — thin enforcement layer driven by the Humifortis Core server.
 *
 * <h3>Flow</h3>
 * <ol>
 *   <li>Calls {@link HumifortisRiskEvaluator#evaluate} → POST /api/v1/evaluate with raw context.</li>
 *   <li>Reads the server's PLAYBOOK DECISION from the evaluator result.</li>
 *   <li>Stores risk level + action in auth session notes for downstream conditions.</li>
 *   <li>Reports what the flow did with the decision ({@code decision_enforced} / {@code decision_fallback_applied}).</li>
 *   <li>Executes the server's enforcement action — NO local policy logic.</li>
 * </ol>
 *
 * <h3>Supported Actions (from server playbook)</h3>
 * <ul>
 *   <li>{@code ALLOW}             → success()</li>
 *   <li>{@code REQUIRE_MFA}       → success() + auth note triggers HumifortisHighCondition sub-flow</li>
 *   <li>{@code REQUIRE_WEBAUTHN}  → same as REQUIRE_MFA</li>
 *   <li>{@code DENY}              → failure(ACCESS_DENIED) with error page</li>
 *   <li>{@code LOCK_ACCOUNT}      → disables user + revokes all sessions + failure</li>
 * </ul>
 *
 * <h3>Side-effect actions</h3>
 * <ul>
 *   <li>{@code REVOKE_OTHER_SESSIONS} — revokes all other sessions</li>
 *   <li>{@code NOTIFY_USER}           — sends security alert email via Keycloak SMTP</li>
 *   <li>{@code NOTIFY_SOC}            — logged; server handles delivery</li>
 * </ul>
 *
 * <h3>Enforcement modes (HUMIFORTIS_MODE env var)</h3>
 * <ul>
 *   <li>{@code enforce} (default) — action is applied</li>
 *   <li>{@code dry_run}           — logs what would have happened, always ALLOW</li>
 *   <li>{@code shadow}            — same as dry_run but side-effects still execute</li>
 * </ul>
 */
public class HumifortisRiskAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(HumifortisRiskAuthenticator.class);

    // Auth session note keys — shared with HumifortisHighCondition and HumifortisEventListener
    public static final String NOTE_RISK_ACTION  = "HUMIFORTIS_RISK_ACTION";
    public static final String NOTE_RISK_LEVEL   = "HUMIFORTIS_RISK_LEVEL";

    /**
     * Verified-Unblock challenge id (dual-source: authNote + event detail), stamped
     * when the server downgrades a DENY to a step-up MFA because an admin opened a
     * verification window. HumifortisEventListener echoes it in mfa_challenge_succeeded so
     * humifortis-core can bind the step-up to this challenge and clear the block.
     */
    public static final String NOTE_CHALLENGE_ID = "HUMIFORTIS_CHALLENGE_ID";

    // Enforcement mode — read once at class load
    private static final String ENFORCEMENT_MODE_ENV =
            System.getenv("HUMIFORTIS_MODE") != null
                    ? System.getenv("HUMIFORTIS_MODE").toLowerCase(Locale.ROOT) : null;

    static {
        logger.infof(
                "[HumifortisRiskAuthenticator] Loaded — enforcement mode: %s",
                ENFORCEMENT_MODE_ENV != null ? ENFORCEMENT_MODE_ENV : "<from API response>");
    }

    // =========================================================================
    // AUTHENTICATE — main entry point
    // =========================================================================

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.debugf("[HumifortisRiskAuthenticator] realm=%s user=%s",
                context.getRealm().getName(),
                context.getUser() != null ? context.getUser().getUsername() : "null");

        // Step 1 — evaluate risk
        // Extract the Keycloak root auth session id (= code_id in OIDC browser flows).
        // This is used as flow_id so auth_credential_verified is grouped with the
        // decision report (decision_enforced) that shares the same session.
        String flowId = null;
        try {
            flowId = context.getAuthenticationSession().getParentSession().getId();
        } catch (Exception e) {
            logger.debugf("[HumifortisRiskAuthenticator] Could not extract flowId: %s", e.getMessage());
        }
        HumifortisRiskEvaluator evaluator = new HumifortisRiskEvaluator(context.getSession());
        HumifortisRiskEvaluator.EvaluationResult evaluation =
                evaluator.evaluateDetailed(context.getRealm(), context.getUser(), flowId);
        Risk risk = evaluation.risk();

        // Step 2 — read explicit server decision from evaluator result
        HumifortisRiskEvaluator.EvaluateResponse serverDecision = evaluation.decision();

        String serverAction  = "ALLOW";
        String riskLevel     = "MINIMAL";
        String playbookRule  = "";
        List<String> actions = List.of();
        Fallback fallback    = null;

        if (serverDecision != null) {
            serverAction = nvl(serverDecision.action,       "ALLOW");
            riskLevel    = nvl(serverDecision.risk_level,   "MINIMAL");
            playbookRule = nvl(serverDecision.playbook_rule, "");
            actions      = serverDecision.actions != null ? serverDecision.actions : List.of();
        } else {
            // No answer from Humifortis: the fallback policy decides (never a silent allow)
            riskLevel    = deriveLevel(risk);
            fallback     = applyFallback(context, evaluation.fallbackReason());
            serverAction = fallback.action();
        }

        logger.debugf("[HumifortisRiskAuthenticator] action=%s level=%s rule=%s",
                serverAction, riskLevel, playbookRule);

        // Step 3 — store in auth session for downstream conditions
        context.getAuthenticationSession().setAuthNote(NOTE_RISK_LEVEL,  riskLevel);
        context.getAuthenticationSession().setAuthNote(NOTE_RISK_ACTION, serverAction);

        // Step 3b — Verified-Unblock: if the server opened a verification window it
        // returns a challenge_id alongside a REQUIRE_MFA* step-up. Stamp it dual-source
        // (authNote survives the MFA sub-flow; event detail survives the LOGIN event)
        // so HumifortisEventListener can echo it in mfa_challenge_succeeded for challenge binding.
        if (serverDecision != null && notBlank(serverDecision.verification_challenge_id)) {
            context.getAuthenticationSession().setAuthNote(NOTE_CHALLENGE_ID, serverDecision.verification_challenge_id);
            context.getEvent().detail(NOTE_CHALLENGE_ID, serverDecision.verification_challenge_id);
            logger.infof("[HumifortisRiskAuthenticator] Verified-Unblock challenge active: id=%s level=%s → step-up %s",
                    serverDecision.verification_challenge_id,
                    nvl(serverDecision.verification_required_level, "AAL2"),
                    serverAction);
        }

        // Step 4 — the mode, then the report of what the flow does with the decision (sent after enforcement
        // is decided, never before: in dry_run / shadow the person is let in and the report says so)
        String mode = serverDecision != null ? resolveMode(serverDecision) : resolveFallbackMode(context);
        reportDecision(context, flowId, serverDecision, fallback, serverAction, mode, riskLevel, playbookRule);

        // Step 5 — enforce (or simulate in dry_run / shadow mode)
        if ("dry_run".equals(mode) || "shadow".equals(mode)) {
            logger.infof("[HumifortisRiskAuthenticator] %s mode: would=%s, actual=ALLOW (user=%s rule=%s)",
                    mode, serverAction,
                    context.getUser() != null ? context.getUser().getUsername() : "?",
                    playbookRule);
            context.getAuthenticationSession().setAuthNote("humifortis_mode",         mode);
            context.getAuthenticationSession().setAuthNote("humifortis_would_action", serverAction);
            if ("shadow".equals(mode)) executeSideActions(context, serverAction, actions, serverDecision);
            context.success();
            return;
        }

        executeAction(context, serverAction, actions, risk, serverDecision);
    }

    // =========================================================================
    // ACTION EXECUTION
    // =========================================================================

    private void executeAction(AuthenticationFlowContext context,
                               String action,
                               List<String> actions,
                               Risk risk,
                               HumifortisRiskEvaluator.EvaluateResponse serverDecision) {
        if (StepUpActions.isStepUp(action)) {
            // success() here — HumifortisHighCondition in the sub-flow triggers the step-up, run by
            // HumifortisStepUpRouter; HumifortisEventListener reports the step-up the router actually ran.
            logger.infof("[HumifortisRiskAuthenticator] %s → delegating to MFA sub-flow", action);
            executeSideActions(context, action, actions, serverDecision);
            context.success();
            return;
        }
        switch (action) {
            case "ALLOW" -> {
                logger.debugf("[HumifortisRiskAuthenticator] ALLOW");
                executeSideActions(context, "ALLOW", actions, serverDecision);
                context.success();
            }

            case "DENY" -> {
                logger.warnf("[HumifortisRiskAuthenticator] DENY — %s", risk.getReason().orElse(""));
                executeSideActions(context, "DENY", actions, serverDecision);
                // a fallback denial says "unavailable", never "suspicious": nothing was evaluated
                HumifortisError err = serverDecision == null ? HumifortisError.SERVICE_TIMEOUT : HumifortisError.ACCESS_DENIED_RISK;
                context.failure(AuthenticationFlowError.ACCESS_DENIED,
                        context.form()
                                .setAttribute("hfErrorCode",       err.code)
                                .setAttribute("hfErrorMessageKey",  err.messageKey())
                                .setAttribute("hfErrorDetailKey",   err.messageDetailKey())
                                .setAttribute("hfTimestamp",        java.time.Instant.now().toString())
                                .createForm("humifortis-error.ftl"));
            }

            case "LOCK_ACCOUNT" -> {
                logger.warnf("[HumifortisRiskAuthenticator] LOCK_ACCOUNT");
                disableUser(context);
                revokeAllSessions(context);
                context.failure(AuthenticationFlowError.ACCESS_DENIED,
                        context.form()
                                .setAttribute("hfErrorCode",       HumifortisError.ACCOUNT_LOCKED.code)
                                .setAttribute("hfErrorMessageKey",  HumifortisError.ACCOUNT_LOCKED.messageKey())
                                .setAttribute("hfErrorDetailKey",   HumifortisError.ACCOUNT_LOCKED.messageDetailKey())
                                .setAttribute("hfTimestamp",        java.time.Instant.now().toString())
                                .createForm("humifortis-error.ftl"));
            }

            default -> {
                // NOTIFY_USER / NOTIFY_SOC may appear as primary when rule has only side-effect
                // actions — treat as ALLOW and still fire side effects.
                logger.warnf("[HumifortisRiskAuthenticator] Unknown primary action '%s' → ALLOW (side-effects still run)", action);
                executeSideActions(context, "ALLOW", actions, serverDecision);
                context.success();
            }
        }
    }

    // =========================================================================
    // SIDE ACTIONS
    // =========================================================================

    /**
     * Executes playbook side-effect actions.
     *
     * <p><strong>REVOKE_OTHER_SESSIONS timing strategy</strong>:
     * <ul>
     *   <li>For {@code DENY} / {@code LOCK_ACCOUNT}: revoke <em>immediately</em> — the flow is
     *       about to fail, no new session will be created, so direct revocation is safe and correct.</li>
     *   <li>For {@code ALLOW} / {@code REQUIRE_MFA*}: defer via
     *       {@link org.keycloak.sessions.AuthenticationSessionModel#setUserSessionNote} so that
     *       {@code HumifortisEventListener} can safely exclude the <em>newly-created</em> session
     *       (whose ID is only known after {@code LOGIN} fires) when revoking all others.</li>
     * </ul>
     *
     * @param primaryAction the main enforcement decision driving this call
     */
    private void executeSideActions(AuthenticationFlowContext context,
                                    String primaryAction,
                                    List<String> actions,
                                    HumifortisRiskEvaluator.EvaluateResponse serverDecision) {
        if (actions == null || actions.isEmpty()) return;
        boolean isBlocking = "DENY".equals(primaryAction) || "LOCK_ACCOUNT".equals(primaryAction);
        for (String a : actions) {
            switch (a) {
                case "REVOKE_OTHER_SESSIONS" -> {
                    if (isBlocking) {
                        // Flow is about to fail — safe to revoke directly
                        revokeOtherSessions(context);
                    } else {
                        // Flow is about to succeed — defer to EventListener (post-LOGIN)
                        // so we can properly identify and exclude the brand-new session.
                        try {
                            context.getAuthenticationSession()
                                   .setUserSessionNote("HUMIFORTIS_REVOKE_SESSIONS", "true");
                            logger.infof("[HumifortisRiskAuthenticator] REVOKE_OTHER_SESSIONS deferred " +
                                    "to EventListener for user=%s",
                                    context.getUser() != null ? context.getUser().getUsername() : "?");
                        } catch (Exception e) {
                            logger.warnf("[HumifortisRiskAuthenticator] defer failed, direct fallback: %s",
                                    e.getMessage());
                            revokeOtherSessions(context);
                        }
                    }
                }
                case "NOTIFY_SOC"  -> logger.infof("[HumifortisRiskAuthenticator] NOTIFY_SOC (server handles delivery)");
                case "NOTIFY_USER" -> sendSecurityEmail(context, "security_alert", serverDecision);
                // Primary action names may appear in the list — skip silently
            }
        }
    }

    // =========================================================================
    // EMAIL NOTIFICATION — user-facing security alert (Google/Apple style)
    // =========================================================================

    /**
     * Sends a security alert email via Keycloak's built-in SMTP provider.
     * Content is i18n-aware via theme message bundles.
     *
     * <p>Placeholders in message templates:
     * {0}=device, {1}=location, {2}=timestamp, {3}=IP, {4}=displayName</p>
     *
     * <p>Location and device type come from the server's /evaluate response —
     * the server resolves GeoIP and UA parsing, not this connector.</p>
     */
    private void sendSecurityEmail(AuthenticationFlowContext context,
                                   String templateKey,
                                   HumifortisRiskEvaluator.EvaluateResponse serverDecision) {
        try {
            UserModel user = context.getUser();
            if (user == null || user.getEmail() == null || user.getEmail().isBlank()) return;
            if (!user.isEmailVerified()) {
                logger.debugf("[HumifortisRiskAuthenticator] NOTIFY_USER skipped: email not verified (%s)",
                        user.getUsername());
                return;
            }

            var smtpConfig = context.getRealm().getSmtpConfig();
            if (smtpConfig == null || smtpConfig.isEmpty()) return;

            // {0} Device — derived from raw User-Agent header (no library)
            String ua = getUserAgent(context);
            String device = parseDeviceSummary(ua);

            // {1} Location — resolved by the server (GeoIP), read from response
            String location = resolveLocation(serverDecision);

            // {2} Timestamp
            String timestamp = java.time.Instant.now()
                    .atZone(java.time.ZoneOffset.UTC)
                    .format(java.time.format.DateTimeFormatter.ofPattern(
                            "MMMM d, yyyy 'at' h:mm a 'UTC'", java.util.Locale.ENGLISH));

            // {3} IP
            String ip = getRemoteAddr(context);

            // {4} Display name
            String displayName = (user.getFirstName() != null && !user.getFirstName().isBlank())
                    ? user.getFirstName() : user.getUsername();

            String prefix    = "humifortis.email." + templateKey;
            String subject   = fmt(msg(context, prefix + ".subject",
                    "Security alert: new sign-in to your account"),
                    device, location, timestamp, ip, displayName);
            String textBody  = fmt(msg(context, prefix + ".body.text",
                    "A new sign-in was detected. Device: {0}, Location: {1}."),
                    device, location, timestamp, ip, displayName);
            String htmlBody  = msg(context, prefix + ".body.html", null);
            if (htmlBody != null) htmlBody = fmt(htmlBody, device, location, timestamp, ip, displayName);

            context.getSession()
                    .getProvider(org.keycloak.email.EmailSenderProvider.class)
                    .send(smtpConfig, user, subject, textBody, htmlBody);

            logger.infof("[HumifortisRiskAuthenticator] NOTIFY_USER: email sent to %s", user.getEmail());

        } catch (Exception e) {
            logger.warnf("[HumifortisRiskAuthenticator] NOTIFY_USER failed (non-blocking): %s",
                    e.getMessage());
        }
    }

    /**
     * Returns a human-readable summary of the browser and OS from a raw User-Agent string.
     * Pure string inspection — no library dependency.
     * Examples: "Chrome on Windows", "Safari on iPhone", "Firefox on macOS"
     */
    static String parseDeviceSummary(String ua) {
        if (ua == null || ua.isBlank()) return "Unknown device";

        String browser;
        if      (ua.contains("Edg"))                                  browser = "Edge";
        else if (ua.contains("OPR") || ua.contains("Opera"))         browser = "Opera";
        else if (ua.contains("Chrome"))                               browser = "Chrome";
        else if (ua.contains("Firefox"))                              browser = "Firefox";
        else if (ua.contains("Safari") && !ua.contains("Chrome"))    browser = "Safari";
        else                                                          browser = "Unknown browser";

        String os;
        if      (ua.contains("iPhone"))                               os = "iPhone";
        else if (ua.contains("iPad"))                                 os = "iPad";
        else if (ua.contains("Android"))                              os = "Android";
        else if (ua.contains("Windows"))                              os = "Windows";
        else if (ua.contains("Macintosh") || ua.contains("Mac OS"))  os = "macOS";
        else if (ua.contains("Linux"))                                os = "Linux";
        else                                                          os = "Unknown OS";

        return browser + " on " + os;
    }

    /**
     * Extracts geo-location from the server's /evaluate response.
     * The server performs GeoIP lookup — the connector only forwards the raw IP.
     */
    private static String resolveLocation(HumifortisRiskEvaluator.EvaluateResponse d) {
        if (d == null) return "Unknown location";
        String city    = d.geo_city;
        String country = d.geo_country;
        if (notBlank(city) && notBlank(country)) return city + ", " + country;
        if (notBlank(country)) return country;
        if (notBlank(city))    return city;
        return "Unknown location";
    }

    private String getUserAgent(AuthenticationFlowContext context) {
        try {
            var headers = context.getSession().getContext().getRequestHeaders();
            return headers != null ? headers.getHeaderString("User-Agent") : null;
        } catch (Exception e) { return null; }
    }

    private String getRemoteAddr(AuthenticationFlowContext context) {
        try {
            var conn = context.getSession().getContext().getConnection();
            return conn != null ? conn.getRemoteAddr() : "unknown";
        } catch (Exception e) { return "unknown"; }
    }

    /** Loads a message from the Keycloak theme bundle; falls back to defaultValue. */
    private String msg(AuthenticationFlowContext context, String key, String defaultValue) {
        try {
            var theme  = context.getSession().theme().getTheme(org.keycloak.theme.Theme.Type.LOGIN);
            String loc = context.getRealm().getDefaultLocale();
            var messages = theme.getMessages(java.util.Locale.forLanguageTag(loc != null ? loc : "en"));
            String v = messages != null ? (String) messages.get(key) : null;
            return v != null ? v : nvl(defaultValue, key);
        } catch (Exception e) { return nvl(defaultValue, key); }
    }

    /** Replaces {0}…{4} positional placeholders. */
    private static String fmt(String tpl, String... args) {
        if (tpl == null) return null;
        String r = tpl;
        for (int i = 0; i < args.length; i++)
            r = r.replace("{" + i + "}", args[i] != null ? args[i] : "—");
        return r.replace("\\n", "\n");
    }

    // =========================================================================
    // SESSION HELPERS
    // =========================================================================

    private void revokeOtherSessions(AuthenticationFlowContext context) {
        try {
            var realm = context.getRealm();
            var user  = context.getUser();
            if (user == null) return;
            // NOTE: At this point in the auth flow, no user session exists yet (it is created only
            // after context.success() completes the entire flow). The root auth session ID is NOT
            // a user session ID. We intentionally revoke ALL existing user sessions so that on next
            // successful login only the newly-created session is active.
            long count = context.getSession().sessions().getUserSessionsStream(realm, user)
                    .peek(s -> {
                        context.getSession().sessions().removeUserSession(realm, s);
                        logger.debugf("[HumifortisRiskAuthenticator] Revoked pre-existing session %s for user %s",
                                s.getId(), user.getUsername());
                    })
                    .count();
            if (count > 0) {
                logger.infof("[HumifortisRiskAuthenticator] REVOKE_OTHER_SESSIONS: revoked %d session(s) for user %s",
                        count, user.getUsername());
            }
        } catch (Exception e) {
            logger.warnf("[HumifortisRiskAuthenticator] revokeOtherSessions failed: %s", e.getMessage());
        }
    }

    private void revokeAllSessions(AuthenticationFlowContext context) {
        try {
            var realm = context.getRealm();
            var user  = context.getUser();
            if (user == null) return;
            context.getSession().sessions().getUserSessionsStream(realm, user)
                    .forEach(s -> context.getSession().sessions().removeUserSession(realm, s));
        } catch (Exception e) {
            logger.warnf("[HumifortisRiskAuthenticator] revokeAllSessions failed: %s", e.getMessage());
        }
    }

    private void disableUser(AuthenticationFlowContext context) {
        try {
            UserModel user = context.getUser();
            if (user != null) {
                user.setEnabled(false);
                logger.infof("[HumifortisRiskAuthenticator] User %s disabled", user.getUsername());
            }
        } catch (Exception e) {
            logger.warnf("[HumifortisRiskAuthenticator] disableUser failed: %s", e.getMessage());
        }
    }

    // =========================================================================
    // FALLBACK (server unreachable)
    // =========================================================================

    /** Auth note: why this login was decided without Humifortis (neutral text in the UI). */
    public static final String NOTE_FALLBACK_REASON = "hf.fallback.reason";

    /** The fallback policy's action for a login Humifortis could not answer, and what its report carries. */
    record Fallback(String action, java.util.Map<String, String> report) {}

    /** Decides a login Humifortis could not answer with the fallback policy (reported by {@link #reportDecision}). */
    private Fallback applyFallback(AuthenticationFlowContext context, String reason) {
        UserModel user = context.getUser();
        RealmModel realm = context.getRealm();
        SaasConfig config = SaasConfig.fromEnv();
        String tenantId = config.tenantIdOr(realm.getName());
        UserContextSnapshot snapshot = null;
        try {
            if (user != null) snapshot = new UserContextExtractor().extract(context.getSession(), realm, user);
        } catch (RuntimeException e) {
            logger.debugf("[HumifortisRiskAuthenticator] user context for fallback failed: %s", e.getMessage());
        }
        boolean privileged = snapshot != null && snapshot.privileged();
        boolean emailOtp = user != null && user.isEmailVerified() && user.getEmail() != null && !user.getEmail().isBlank();
        boolean canStepUp = (snapshot != null && snapshot.mfaEnrolled()) || emailOtp;
        FallbackPolicy.Decision d = FallbackPolicy.resolve(config.getFallbackOverride(), tenantId, privileged, canStepUp);

        String action = fallbackAction(d.outcome(), snapshot != null ? snapshot.mfaMethods() : List.of());
        String why = reason != null ? reason : "error";
        context.getAuthenticationSession().setAuthNote(NOTE_FALLBACK_REASON, why);
        logger.infof("[Humifortis] fallback applied: outcome=%s source=%s reason=%s privileged=%s user=%s",
                d.outcome().wire(), d.source(), why, privileged, user != null ? user.getUsername() : "?");

        java.util.Map<String, String> report = new java.util.LinkedHashMap<>();
        report.put("fallback_reason", why);
        report.put("fallback_outcome", d.outcome().wire());
        report.put("fallback_policy_source", d.source());
        if (d.stepUpUnavailable()) report.put("fallback_step_up_unavailable", "true");
        report.put("is_privileged", String.valueOf(privileged));
        return new Fallback(action, report);
    }

    /**
     * Reports what the flow does with the decision of this login: {@code decision_enforced} (Humifortis answered)
     * or {@code decision_fallback_applied} (the fallback policy decided). Queued, best-effort, never blocks the login.
     */
    private void reportDecision(AuthenticationFlowContext context, String flowId,
                                HumifortisRiskEvaluator.EvaluateResponse d, Fallback fallback,
                                String action, String mode, String riskLevel, String decisionRule) {
        try {
            SaasConfig config = SaasConfig.fromEnv();
            UserModel user = context.getUser();
            if (!config.hasApiKey() || user == null) return;
            RealmModel realm = context.getRealm();
            java.util.Map<String, String> extra = new java.util.LinkedHashMap<>();
            extra.put("username", user.getUsername());
            extra.put("risk_level", riskLevel);
            String ip = getRemoteAddr(context);
            if (!"unknown".equals(ip)) extra.put("ip", ip);
            var client = context.getAuthenticationSession().getClient();
            if (client != null) extra.put("client_id", client.getClientId());
            String enforced = action;
            String type;
            if (d != null) {
                type = DecisionReport.DECISION_ENFORCED;
                if (notBlank(d.enforced_action)) enforced = d.enforced_action;
                extra.put("decision_rule", decisionRule);
                extra.put("risk_score", String.valueOf(d.risk_score));
                extra.put("policy_source", d.policy_source);
                extra.put("access_policy", d.access_policy);
                extra.put("fallback_reason", d.fallback_reason);
                if (d.derived_signals != null && !d.derived_signals.isEmpty()) extra.put("derived_signals", String.join(",", d.derived_signals));
                if (d.actions != null && !d.actions.isEmpty()) extra.put("all_actions", String.join(",", d.actions));
                extra.put("device_is_new", String.valueOf(d.device_is_new));
                extra.put("device_is_trusted", String.valueOf(d.device_is_trusted));
                extra.put("challenge_id", d.verification_challenge_id);
            } else {
                type = DecisionReport.FALLBACK_APPLIED;
                if (fallback != null) extra.putAll(fallback.report());
            }
            EventQueue.shared(config).submit(DecisionReport.build(type, HumifortisRiskEvaluator.buildEntityId(realm, user), DecisionReport.USER,
                    flowId, realm.getName(), action, enforced, mode, extra));
        } catch (RuntimeException e) {
            logger.debugf("[HumifortisRiskAuthenticator] decision report failed: %s", e.getMessage());
        }
    }

    /** The flow action of a fallback outcome: a step-up prefers the user's passkey. */
    static String fallbackAction(FallbackPolicy.Outcome outcome, List<String> mfaMethods) {
        return switch (outcome) {
            case ALLOW -> "ALLOW";
            case DENY -> "DENY";
            case STEP_UP -> mfaMethods.contains("WEBAUTHN") || mfaMethods.contains("WEBAUTHN_PASSWORDLESS")
                    ? "REQUIRE_WEBAUTHN" : "REQUIRE_MFA";
        };
    }

    /** The tenant's mode as last seen (a tenant in shadow/dry_run is never blocked by a fallback). */
    private static String resolveFallbackMode(AuthenticationFlowContext context) {
        if (ENFORCEMENT_MODE_ENV != null) return ENFORCEMENT_MODE_ENV;
        String cached = FallbackPolicy.cachedMode(SaasConfig.fromEnv().tenantIdOr(context.getRealm().getName()));
        return cached != null ? cached : "enforce";
    }

    private static String deriveLevel(Risk risk) {
        if (risk.getScore() == null) return "MINIMAL";
        return switch (risk.getScore()) {
            case NONE, INVALID, NEGATIVE_HIGH, NEGATIVE_LOW -> "MINIMAL";
            case VERY_SMALL, SMALL                          -> "LOW";
            case MEDIUM                                     -> "MEDIUM";
            case HIGH, VERY_HIGH                            -> "HIGH";
            case EXTREME                                    -> "CRITICAL";
        };
    }

    private static String resolveMode(HumifortisRiskEvaluator.EvaluateResponse d) {
        if (ENFORCEMENT_MODE_ENV != null) return ENFORCEMENT_MODE_ENV;
        if (d != null && notBlank(d.mode)) return d.mode.toLowerCase(Locale.ROOT);
        return "enforce";
    }

    // =========================================================================
    // UTILITIES
    // =========================================================================

    private static String nvl(String value, String fallback) {
        return (value != null && !value.isBlank()) ? value : fallback;
    }

    private static boolean notBlank(String s) { return s != null && !s.isBlank(); }

    @Override public void action(AuthenticationFlowContext context) {}
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(KeycloakSession s, RealmModel r, UserModel u) { return true; }
    @Override public void setRequiredActions(KeycloakSession s, RealmModel r, UserModel u) {}
    @Override public void close() {}
}

package tech.humifortis.keycloak.listener;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;

import tech.humifortis.keycloak.client.EdgeRtt;
import tech.humifortis.keycloak.client.ProxySettings;
import tech.humifortis.keycloak.client.SaasClient;
import tech.humifortis.keycloak.client.SaasConfig;
import tech.humifortis.keycloak.mapper.EventMapper;
import tech.humifortis.keycloak.model.HumifortisEvent;
import tech.humifortis.keycloak.serviceaccount.ServiceAccountContext;
import tech.humifortis.keycloak.auth.DeviceSignals;
import tech.humifortis.keycloak.auth.HumifortisDeviceCollectorAuthenticator;
import tech.humifortis.keycloak.user.UserContextExtractor;
import tech.humifortis.keycloak.user.UserContextSnapshot;

/**
 * Humifortis Event Listener — LEAN connector.
 *
 * Design principle: extract ONLY what requires Keycloak session access.
 * Heavy computation (GeoIP, UA parsing, device_id) is done server-side
 * in humifortis-core's Enricher.
 *
 * This connector extracts:
 *   - Raw IP address (from HTTP connection)
 *   - Raw User-Agent (from HTTP headers)
 *   - Session ID
 *   - User roles, MFA status, account age (from Keycloak UserModel)
 *   - Active session count
 *   - Identity provider
 *
 * NOT done here (moved to server):
 *   - GeoIP lookup (moved to humifortis-core — raw IP is forwarded as-is)
 *   - User-Agent parsing (moved to humifortis-core)
 *   - device_id computation (handled by HumifortisDeviceCollectorAuthenticator + FingerprintJS)
 */
public class HumifortisEventListener implements EventListenerProvider {

    private static final Logger logger =
            Logger.getLogger(HumifortisEventListener.class);

    /**
     * Verified-Unblock challenge id — stamped by HumifortisRiskAuthenticator (dual-source:
     * event detail + auth session note). Echoed into mfa_challenge_succeeded so humifortis-core
     * can bind the MFA to the admin-initiated challenge and clear the block.
     */
    private static final String DETAIL_CHALLENGE_ID = "HUMIFORTIS_CHALLENGE_ID";

    /**
     * Session note stamped after the first auth_login_success is emitted for a given user session.
     * Prevents duplicate auth_login_success events when Keycloak fires EventType.LOGIN multiple times
     * within the same SSO session (account-console client + account client = 2 LOGIN events, 1 session).
     */
    private static final String NOTE_LOGIN_EMITTED = "HUMIFORTIS_LOGIN_EMITTED";

    private static final Set<EventType> MONITORED_EVENTS = Set.of(
            EventType.LOGIN,
            EventType.LOGIN_ERROR,
            // a client authenticating with its own credentials: a service account (client_credentials)
            EventType.CLIENT_LOGIN,
            EventType.CLIENT_LOGIN_ERROR,
            EventType.LOGOUT,
            EventType.REGISTER,
            EventType.UPDATE_PASSWORD,
            EventType.UPDATE_EMAIL,
            EventType.RESET_PASSWORD,
            EventType.RESET_PASSWORD_ERROR,
            EventType.CODE_TO_TOKEN_ERROR,
            EventType.REFRESH_TOKEN_ERROR,
            EventType.REMOVE_TOTP,
            EventType.UPDATE_TOTP,
            // a sign-in through an external identity provider that failed on the provider's side (about the integration)
            EventType.IDENTITY_PROVIDER_LOGIN_ERROR,
            // a WebAuthn credential registered (only that type: passwords and app codes have their own events)
            EventType.UPDATE_CREDENTIAL,
            EventType.IMPERSONATE,
            EventType.GRANT_CONSENT,
            EventType.REVOKE_GRANT,
            EventType.DELETE_ACCOUNT
    );

    private final SaasClient     saasClient;
    private final EventMapper    eventMapper;
    private final UserContextExtractor userContextExtractor;
    private final KeycloakSession session;
    /** Set to true when SaasClient/SaasConfig init failed — all onEvent() calls are no-ops. */
    private final boolean        disabled;

    public HumifortisEventListener(KeycloakSession session) {
        this.session = session;
        SaasClient  client  = null;
        EventMapper mapper  = null;
        boolean     isDisabled = false;
        try {
            SaasConfig config = SaasConfig.fromEnv();
            client  = new SaasClient(config);
            mapper  = new EventMapper();
            logger.info("[HumifortisEventListener] Initialized (lean mode — server-side enrichment)");
        } catch (Exception e) {
            logger.errorf("[HumifortisEventListener] Init failed — listener disabled for this request: %s",
                    e.getMessage());
            isDisabled = true;
        }
        this.saasClient  = client;
        this.eventMapper = mapper;
        this.userContextExtractor = new UserContextExtractor();
        this.disabled    = isDisabled;
    }

    // ── Entry points ──────────────────────────────────────────────────────────

    @Override
    public void onEvent(Event event) {
        if (disabled) return;  // init failed — skip silently

        logger.debugf("[HumifortisEventListener] Received event: type=%s error=%s realm=%s user=%s",
                event.getType(), event.getError(), event.getRealmId(), event.getUserId());

        // Path 0: deferred session revocation — safe post-LOGIN timing (session is now fully established)
        if (event.getType() == EventType.LOGIN && event.getSessionId() != null) {
            handleDeferredSessionRevocation(event);
        }

        // Path 0b: deduplicate auth_login_success.
        // Keycloak fires EventType.LOGIN once per client in the same SSO session
        // (e.g., account-console + account = 2 LOGIN events, same sessionId).
        // We stamp a note on the UserSession after the first one; subsequent LOGINs are silent SSO grants.
        if (event.getType() == EventType.LOGIN && event.getSessionId() != null) {
            try {
                RealmModel realm = session.getContext().getRealm();
                if (realm == null) realm = session.realms().getRealm(event.getRealmId());
                if (realm != null) {
                    var userSession = session.sessions().getUserSession(realm, event.getSessionId());
                    if (userSession != null) {
                        if ("true".equals(userSession.getNote(NOTE_LOGIN_EMITTED))) {
                            logger.debugf("[HumifortisEventListener] Skipping duplicate auth_login_success " +
                                    "(session=%s) — SSO silent grant", event.getSessionId());
                            return;
                        }
                        userSession.setNote(NOTE_LOGIN_EMITTED, "true");
                    }
                }
            } catch (Exception e) {
                logger.debugf("[HumifortisEventListener] Login dedup check failed (non-blocking): %s",
                        e.getMessage());
            }
        }

        // The refusal of a token request by the service-account risk stage: already reported by decision_enforced,
        // and never a wrong secret (it must not count as credential guessing)
        if (tech.humifortis.keycloak.serviceaccount.ServiceAccountRiskExecutor.isRiskStageRefusal(
                event.getType() == EventType.CLIENT_LOGIN_ERROR, event.getError(), event.getDetails())) {
            return;
        }
        // Same for the refusal of a refresh or a token exchange by a token risk stage
        if ((event.getType() == EventType.REFRESH_TOKEN_ERROR || event.getType() == EventType.TOKEN_EXCHANGE_ERROR)
                && tech.humifortis.keycloak.token.TokenRiskStage.isRefusal(event.getDetails())) {
            return;
        }

        // An attempt refused by the account's temporary lockout (a Humifortis throttle or Keycloak's own): enforcement,
        // not a wrong password. Counting it would feed the detector that created the throttle and extend it forever.
        if (tech.humifortis.keycloak.caep.ThrottleLockout.isLockoutRefusal(event.getType(), event.getError())) {
            logger.debugf("[HumifortisEventListener] Not reporting a lockout refusal as a failed login (user=%s)", event.getUserId());
            return;
        }

        // Path B: standard security event
        if (MONITORED_EVENTS.contains(event.getType())) {
            if (event.getType() == EventType.UPDATE_CREDENTIAL && !isWebAuthnRegistration(event)) return;
            try {
                // a sign-in the directory could not answer is the directory's failure, not a wrong password (P7)
                boolean directoryDown = DirectoryOutage.mark(session, event);
                // a failed sign-in through an identity provider names the provider Keycloak is serving the callback of
                if (tech.humifortis.keycloak.mapper.ProviderFailure.is(event.getType()) && event.getDetails() != null) {
                    String alias = tech.humifortis.keycloak.mapper.ProviderFailure.aliasOfRequest(session);
                    if (alias != null) event.getDetails().put("identity_provider", alias);
                }
                enrichEvent(event);
                if (ServiceAccountContext.isClientCredentialsEvent(event.getType())) {
                    enrichServiceAccount(event);
                }

                // The step-up the router ran in this flow (the factor it challenged), or null when none ran.
                String stepUpMethod = stepUpMethod(event);

                // A LOGIN concluding a flow in which the router ran a step-up: the step-up succeeded. Reported
                // BEFORE the login success (it discharges the evidence the step-up answered).
                if (event.getType() == EventType.LOGIN && stepUpMethod != null) {
                    String challengeId = resolveChallengeId(event);
                    HumifortisEvent stepUp = eventMapper.fromStepUpSucceeded(event, stepUpMethod, challengeId);
                    stepUp.addMetadata("required_factor", flowNote(event, tech.humifortis.keycloak.auth.HumifortisRiskAuthenticator.NOTE_REQUIRED_FACTOR));
                    addWebAuthnKind(event, stepUp, stepUpMethod);
                    sendAsync(stepUp, EventMapper.STEP_UP_SUCCEEDED);
                }

                HumifortisEvent humiEvent = eventMapper.fromKeycloakEvent(event);
                if (directoryDown) {
                    humiEvent.setEventType(DirectoryOutage.REASON);
                    humiEvent.addMetadata(DirectoryOutage.DETAIL_REASON, DirectoryOutage.REASON);
                    humiEvent.addMetadata(DirectoryOutage.DETAIL_DIRECTORY, event.getDetails().get(DirectoryOutage.DETAIL_DIRECTORY));
                }
                // A login error AFTER the step-up was challenged is a failed step-up (a wrong code), never a
                // wrong password: it is not credential guessing.
                if (event.getType() == EventType.LOGIN_ERROR && stepUpMethod != null) {
                    humiEvent.setEventType(EventMapper.STEP_UP_FAILED);
                    humiEvent.addMetadata("mfa_method", stepUpMethod);
                    humiEvent.addMetadata("required_factor", flowNote(event, tech.humifortis.keycloak.auth.HumifortisRiskAuthenticator.NOTE_REQUIRED_FACTOR));
                    addWebAuthnKind(event, humiEvent, stepUpMethod);
                }
                if (event.getType() == EventType.UPDATE_CREDENTIAL) {
                    addRegisteredKind(event, humiEvent);
                }
                sendAsync(humiEvent, event.getType().name());

                // A LOGIN after a step-up decision that no factor answered: the realm has no MFA sub-flow, and the
                // decision report must not keep saying "step_up" for a person signed in without one.
                if (event.getType() == EventType.LOGIN && stepUpMethod == null) {
                    reportSkippedStepUp(event);
                }
            } catch (Exception e) {
                logger.errorf("[HumifortisEventListener] Error mapping/sending event %s: %s",
                        event.getType(), e.getMessage());
            }
        } else {
            logger.debugf("[HumifortisEventListener] Skipping unmonitored event: %s",
                    event.getType());
        }
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean includeRepresentation) {
        if (disabled) return;
        try {
            HumifortisEvent humiEvent = eventMapper.fromKeycloakAdminEvent(adminEvent,
                    new tech.humifortis.keycloak.serviceaccount.KeycloakAdminIdentityResolver(session));
            sendAsync(humiEvent, "admin:" + adminEvent.getOperationType());
        } catch (Exception e) {
            logger.errorf("[HumifortisEventListener] Error processing admin event: %s",
                    e.getMessage());
        }
    }

    @Override
    public void close() {}

    // ══════════════════════════════════════════════════════════════════════════
    // ENRICHMENT — Only extracts data that REQUIRES Keycloak session access.
    // GeoIP, UA parsing, and device_id are handled SERVER-SIDE by humifortis-core.
    // ══════════════════════════════════════════════════════════════════════════

    private void enrichEvent(Event event) {
        if (event.getDetails() == null) return;

        // Step 1 — Raw IP (only accessible here via Keycloak connection)
        try {
            String remoteIp = session.getContext().getConnection().getRemoteAddr();
            if (remoteIp != null && !remoteIp.isBlank()) {
                event.getDetails().put("ip", remoteIp);
            }
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] IP extraction failed: %s", e.getMessage());
        }
        // how that IP was resolved (trusted proxy configuration or not)
        try {
            ProxySettings.current().writeTo((k, v) -> event.getDetails().put(k, v));
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] proxy settings failed: %s", e.getMessage());
        }

        // Step 2 — Raw User-Agent (only accessible here via HTTP headers)
        try {
            String ua = session.getContext().getRequestHeaders().getHeaderString("User-Agent");
            if (ua != null && !ua.isBlank()) {
                event.getDetails().put("user_agent", ua);
            }
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] UA extraction failed: %s", e.getMessage());
        }

        // Round trip time: the edge's (X-Edge-RTT-Ms), else the browser's (device collector note)
        try {
            var as = session.getContext().getAuthenticationSession();
            EdgeRtt.Measure rtt = EdgeRtt.resolve(session.getContext().getRequestHeaders(),
                    as != null ? as.getAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_RTT_MS) : null);
            if (rtt != null) {
                event.getDetails().put(EdgeRtt.METADATA_KEY, String.valueOf(rtt.ms()));
                event.getDetails().put(EdgeRtt.SOURCE_KEY, rtt.source());
            }
            Integer browser = EdgeRtt.browser(as != null ? as.getAuthNote(HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_RTT_MS) : null);
            if (browser != null) event.getDetails().put(EdgeRtt.BROWSER_KEY, String.valueOf(browser));
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] RTT extraction failed: %s", e.getMessage());
        }

        // Step 3 — Session ID
        try {
            String sessionId = event.getSessionId();
            if (sessionId != null && !sessionId.isBlank()) {
                event.getDetails().put("session_id", sessionId);
            }
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] session_id extraction failed: %s", e.getMessage());
        }

        // Step 3b — flow_id: authentication session identifier (groups all events of one auth attempt).
        // Priority: authSessionId → code_id (OIDC) → sessionId (post-auth fallback).
        // Pulled from the AuthenticationSessionModel when available — more reliable than event details
        // because it is set before the flow completes and survives session transitions.
        try {
            var as = session.getContext().getAuthenticationSession();
            String flowId = null;
            // From auth session (most reliable during an active flow)
            if (as != null) {
                String authSessionParentId = as.getParentSession() != null
                        ? as.getParentSession().getId() : null;
                if (authSessionParentId != null && !authSessionParentId.isBlank()) {
                    flowId = authSessionParentId;
                }
            }
            // Fallback: event details (authSessionId key set by some Keycloak versions)
            if (flowId == null) {
                String fromDetails = event.getDetails().get("authSessionId");
                if (fromDetails != null && !fromDetails.isBlank()) flowId = fromDetails;
            }
            // Fallback: OIDC code_id
            if (flowId == null) {
                String codeId = event.getDetails().get("code_id");
                if (codeId != null && !codeId.isBlank()) flowId = codeId;
            }
            // Fallback: sessionId (post-auth, session already established)
            if (flowId == null && event.getSessionId() != null && !event.getSessionId().isBlank()) {
                flowId = event.getSessionId();
            }
            if (flowId != null) {
                event.getDetails().put("authSessionId", flowId);
            } else if (!ServiceAccountContext.isClientCredentialsEvent(event.getType())) {
                // a client_credentials request has no browser flow: the mapper derives its flow id
                logger.warnf("[HumifortisEventListener] flow_id could not be extracted for event type=%s user=%s",
                        event.getType(), event.getUserId());
            }
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] flow_id extraction failed: %s", e.getMessage());
        }

        UserContextSnapshot userContext = resolveUserContext(event);

        // Step 4 — Identity: effective roles, groups, privilege, account creation, MFA, sessions
        try {
            if (userContext != null) {
                userContext.writeTo((k, v) -> event.getDetails().put(k, v));
            }
        } catch (Exception e) {
            logger.warnf("[HumifortisEventListener] identity context failed: %s", e.getMessage());
        }

        // Step 8 — Identity provider
        try {
            String idp = event.getDetails().get("identity_provider");
            if (idp == null || idp.isBlank()) {
                event.getDetails().put("identity_provider", "local");
            }
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] identity_provider failed: %s", e.getMessage());
        }

        // Step 9 — Device signals (pushed into event details by HumifortisDeviceCollectorAuthenticator
        // via context.getEvent().detail(). If the event was fired post-flow and the detail is missing,
        // we fall back to the AuthNote — which may still be accessible depending on Keycloak version.
        // Each field is evaluated independently — a missing value for one does not block the others.)
        try {
            var as = session.getContext().getAuthenticationSession();
            // STABLE
            mergeDeviceDetail(event, as, "device_id",          HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_ID);
            mergeDeviceDetail(event, as, "device_signals",     HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_SIGNALS);
            // CONTEXTUAL
            mergeDeviceDetail(event, as, "device_tz",          HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_TZ);
            mergeDeviceDetail(event, as, "device_screen",      HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_SCREEN);
            mergeDeviceDetail(event, as, "device_lang",        HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_LANG);
            mergeDeviceDetail(event, as, "device_color_depth", HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_COLOR_DEPTH);
            // HARDWARE
            mergeDeviceDetail(event, as, "device_cpu_cores",   HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_CPU_CORES);
            mergeDeviceDetail(event, as, "device_memory_gb",   HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_MEMORY_GB);
            mergeDeviceDetail(event, as, "device_touch",       HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_TOUCH);
            mergeDeviceDetail(event, as, "device_platform",    HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_PLATFORM);
            mergeDeviceDetail(event, as, "device_connection",  HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_CONNECTION);
            // BEHAVIORAL
            mergeDeviceDetail(event, as, "device_load_ms",     HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_LOAD_MS);
            // v2.2 PASSIVE DISCRIMINATORS
            mergeDeviceDetail(event, as, "device_touch_points",   HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_TOUCH_POINTS);
            mergeDeviceDetail(event, as, "device_orientation",    HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_ORIENTATION);
            mergeDeviceDetail(event, as, "device_hash_perf_ms",   HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_HASH_PERF_MS);
            // v2.3 MATH / FPU
            mergeDeviceDetail(event, as, "device_math_hash",        HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_MATH_HASH);
            mergeDeviceDetail(event, as, "device_fpu_class",        HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_FPU_CLASS);
            mergeDeviceDetail(event, as, "device_math_anomaly",     HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_MATH_ANOMALY);
            mergeDeviceDetail(event, as, "device_math_exec_ms",     HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_MATH_EXEC_MS);
            mergeDeviceDetail(event, as, "device_math_consistency", HumifortisDeviceCollectorAuthenticator.NOTE_DEVICE_MATH_CONSISTENCY);
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] device signals enrichment failed: %s", e.getMessage());
        }

        // Step 10 — A failed login never reaches the collector step: when the login theme runs the
        // collector script (opt-in), the signals are in the very POST that failed.
        if (event.getType() == EventType.LOGIN_ERROR) {
            mergeDeviceSignalsFromLoginForm(event);
        }
    }

    /**
     * Service account (client_credentials) context: what the operator declared on the client,
     * judged against this request. Only reads the client model — nothing is written to Keycloak.
     */
    private void enrichServiceAccount(Event event) {
        try {
            // the risk stage decided this request before the token was issued: core records no second decision
            if (Boolean.TRUE.equals(session.getAttribute(tech.humifortis.keycloak.serviceaccount.ServiceAccountRiskExecutor.SESSION_ATTR_EVALUATED))) {
                event.getDetails().put(tech.humifortis.keycloak.serviceaccount.ServiceAccountRiskExecutor.DETAIL_DECISION_STAGE,
                        tech.humifortis.keycloak.serviceaccount.ServiceAccountRiskExecutor.DECISION_STAGE_TOKEN_REQUEST);
            }
            RealmModel realm = event.getRealmId() != null ? session.realms().getRealm(event.getRealmId()) : null;
            if (realm == null) realm = session.getContext().getRealm();
            if (realm == null || event.getClientId() == null) return;
            ClientModel client = realm.getClientByClientId(event.getClientId());
            Map<String, String> attributes = client != null ? client.getAttributes() : null;
            String ip = event.getIpAddress() != null ? event.getIpAddress() : event.getDetails().get("ip");
            event.getDetails().putAll(ServiceAccountContext.resolve(
                    attributes, ip, event.getDetails().get("scope"), Instant.ofEpochMilli(event.getTime())));
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] service account context failed: %s", e.getMessage());
        }
    }

    private void mergeDeviceSignalsFromLoginForm(Event event) {
        try {
            String existing = event.getDetails().get("device_id");
            if (existing != null && !existing.isBlank()) return;
            var request = session.getContext().getHttpRequest();
            if (request == null || !"POST".equalsIgnoreCase(request.getHttpMethod())) return;
            DeviceSignals signals = DeviceSignals.fromForm(request.getDecodedFormParameters());
            if (signals == null) return;
            String binding = signals.validateBinding(serverTabId(event, request), System.currentTimeMillis());
            signals.writeEventDetails((k, v) -> event.getDetails().put(k, v), binding, true);
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] device signals from the login form failed: %s", e.getMessage());
        }
    }

    /**
     * The anti-replay nonce of a login-page submission: the tab id of the login form — accepted
     * only when that tab exists in this browser's authentication session on the server (a value
     * the server issued, not one the client chose). Null when it cannot be established.
     */
    private String serverTabId(Event event, org.keycloak.http.HttpRequest request) {
        try {
            var as = session.getContext().getAuthenticationSession();
            if (as != null && as.getTabId() != null) return as.getTabId();
            String tabId = request.getUri().getQueryParameters().getFirst("tab_id");
            var realm = session.getContext().getRealm();
            if (tabId == null || realm == null || event.getClientId() == null) return null;
            var root = new org.keycloak.services.managers.AuthenticationSessionManager(session).getCurrentRootAuthenticationSession(realm);
            var client = realm.getClientByClientId(event.getClientId());
            if (root == null || client == null || root.getAuthenticationSession(client, tabId) == null) return null;
            return tabId;
        } catch (Exception e) {
            return null;
        }
    }

    // ── Step-up ───────────────────────────────────────────────────────────────

    /** The factor the step-up router challenged in this authentication session, or null when no step-up ran. */
    private void reportSkippedStepUp(Event event) {
        var as = session.getContext().getAuthenticationSession();
        RealmModel realm = session.getContext().getRealm();
        if (as == null || realm == null || event.getUserId() == null) return;
        tech.humifortis.keycloak.auth.StepUpExecution.reportIfSkipped(as, realm,
                session.users().getUserById(realm, event.getUserId()));
    }

    /** A WebAuthn credential registered (Keycloak's UPDATE_CREDENTIAL of type webauthn or webauthn-passwordless). */
    static boolean isWebAuthnRegistration(Event event) {
        String type = event.getDetails() != null ? event.getDetails().get("credential_type") : null;
        return type != null && type.startsWith("webauthn");
    }

    /** The kind of the WebAuthn credential the step-up presented, and its reference (P9). */
    private void addWebAuthnKind(Event event, HumifortisEvent humiEvent, String stepUpMethod) {
        if (!"WEBAUTHN".equals(stepUpMethod)) return;
        String kind = flowNote(event, tech.humifortis.keycloak.auth.HumifortisStepUpRouter.NOTE_MFA_KIND);
        String ref = flowNote(event, tech.humifortis.keycloak.auth.HumifortisStepUpRouter.NOTE_MFA_CREDENTIAL);
        if (kind != null) humiEvent.addMetadata("mfa_method_kind", kind);
        if (ref != null) humiEvent.addMetadata("webauthn_credential", ref);
    }

    /**
     * A registration: the credential's kind from its stored transports and the backup-eligible flag of the attestation the
     * browser posted in this same request (Keycloak does not keep the flag).
     */
    private void addRegisteredKind(Event event, HumifortisEvent humiEvent) {
        humiEvent.addMetadata("mfa_method", "WEBAUTHN");
        try {
            var realm = session.getContext().getRealm();
            var user = realm != null && event.getUserId() != null ? session.users().getUserById(realm, event.getUserId()) : null;
            if (user == null) return;
            var stored = tech.humifortis.keycloak.user.WebAuthnKinds.find(
                    tech.humifortis.keycloak.user.WebAuthnKinds.stored(user), event.getDetails().get("public_key_credential_id"));
            Boolean backup = null;
            var request = session.getContext().getHttpRequest();
            if (request != null) {
                backup = tech.humifortis.keycloak.user.WebAuthnKinds.backupEligible(
                        tech.humifortis.keycloak.user.WebAuthnKinds.authDataOfAttestation(
                                tech.humifortis.keycloak.user.WebAuthnKinds.decode(request.getDecodedFormParameters().getFirst("attestationObject"))));
            }
            humiEvent.addMetadata("mfa_method_kind", tech.humifortis.keycloak.user.WebAuthnKinds.kind(stored != null ? stored.transports() : List.of(), backup));
            if (stored != null && stored.ref() != null) humiEvent.addMetadata("webauthn_credential", stored.ref());
        } catch (RuntimeException e) {
            logger.debugf("[HumifortisEventListener] WebAuthn registration kind unreadable: %s", e.getMessage());
        }
    }

    private String stepUpMethod(Event event) {
        return flowNote(event, tech.humifortis.keycloak.auth.HumifortisStepUpRouter.NOTE_MFA_METHOD);
    }

    /** A note the authentication of this event's flow carries (the router's and the risk step's), or null. */
    private String flowNote(Event event, String note) {
        try {
            String m = noteOf(session.getContext().getAuthenticationSession(), note);
            if (m != null) return m;
            // The event of a refused factor can fire where the request has no authentication session of its own (the
            // form post of Keycloak's OTP form): the event names the root session, whose tabs carry the router's note.
            String rootId = event.getDetails() != null ? event.getDetails().get("code_id") : null;
            RealmModel realm = session.getContext().getRealm();
            if (rootId == null || rootId.isBlank() || realm == null) return null;
            var root = session.authenticationSessions().getRootAuthenticationSession(realm, rootId);
            if (root == null) return null;
            for (var tab : root.getAuthenticationSessions().values()) {
                m = noteOf(tab, note);
                if (m != null) return m;
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private static String noteOf(org.keycloak.sessions.AuthenticationSessionModel as, String note) {
        if (as == null) return null;
        String m = as.getAuthNote(note);
        return m != null && !m.isBlank() ? m : null;
    }

    /**
     * Resolves the Verified-Unblock challenge id bound to this login (dual-source,
     * mirroring {@link #stepUpMethod}). Returns null when no admin verification
     * window drove this MFA (i.e. a normal risk-based MFA).
     */
    private String resolveChallengeId(Event event) {
        // Source 1: event detail (stamped on the LOGIN event by the authenticator)
        if (event.getDetails() != null) {
            String v = event.getDetails().get(DETAIL_CHALLENGE_ID);
            if (v != null && !v.isBlank()) return v;
        }
        // Source 2: auth session note (survives the Keycloak MFA sub-flow)
        try {
            var as = session.getContext().getAuthenticationSession();
            if (as != null) {
                String v = as.getAuthNote(DETAIL_CHALLENGE_ID);
                if (v != null && !v.isBlank()) return v;
            }
        } catch (Exception ignored) {}
        return null;
    }

    // ── Shared helpers ────────────────────────────────────────────────────────

    private void sendAsync(HumifortisEvent event, String label) {
        try {
            saasClient.send(event);
        } catch (RuntimeException e) {
            logger.warnf("[HumifortisEventListener] Failed to queue [%s]: %s", label, e.getMessage());
        }
    }

    private UserContextSnapshot resolveUserContext(Event event) {
        String userId = event.getUserId();
        if (userId == null || userId.isBlank()) return null;
        RealmModel realm = event.getRealmId() != null ? session.realms().getRealm(event.getRealmId()) : null;
        if (realm == null) realm = session.getContext().getRealm();
        if (realm == null) return null;
        UserModel user = session.users().getUserById(realm, userId);
        if (user == null) return null;
        return userContextExtractor.extract(session, realm, user);
    }

    /**
     * Merges a device signal into event details.
     * Priority: event detail (set by DeviceCollector during the flow) → AuthNote fallback.
     * Each field is evaluated independently so a missing detail for one field
     * does not prevent other fields from being populated.
     */
    private void mergeDeviceDetail(Event event,
                                   org.keycloak.sessions.AuthenticationSessionModel as,
                                   String detailKey, String noteKey) {
        try {
            String existing = event.getDetails().get(detailKey);
            if (existing != null && !existing.isBlank()) return; // already present from DeviceCollector
            if (as == null) return;
            String fromNote = as.getAuthNote(noteKey);
            if (fromNote != null && !fromNote.isBlank()) {
                event.getDetails().put(detailKey, fromNote);
            }
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] mergeDeviceDetail(%s) failed: %s", detailKey, e.getMessage());
        }
    }

    // ── Deferred session revocation ────────────────────────────────────────────

    /**
     * Handles REVOKE_OTHER_SESSIONS that was deferred from the authenticator via
     * {@code AuthenticationSessionModel.setUserSessionNote("HUMIFORTIS_REVOKE_SESSIONS","true")}.
     *
     * <p>Called on LOGIN event — the new user session is fully established and its ID is known,
     * so we can correctly exclude it while revoking all other (older) sessions.
     */
    private void handleDeferredSessionRevocation(Event event) {
        try {
            String sessionId = event.getSessionId();
            String realmId   = event.getRealmId();
            if (sessionId == null || realmId == null) return;

            RealmModel realm = session.realms().getRealm(realmId);
            if (realm == null) return;

            UserSessionModel currentSession = session.sessions().getUserSession(realm, sessionId);
            if (currentSession == null) return;

            String flag = currentSession.getNote("HUMIFORTIS_REVOKE_SESSIONS");
            if (!"true".equals(flag)) return;

            // Clear flag first — idempotency
            currentSession.removeNote("HUMIFORTIS_REVOKE_SESSIONS");

            String userId = event.getUserId();
            if (userId == null) return;
            UserModel user = session.users().getUserById(realm, userId);
            if (user == null) return;

            long count = session.sessions().getUserSessionsStream(realm, user)
                    .filter(s -> !s.getId().equals(sessionId))
                    .peek(s -> {
                        session.sessions().removeUserSession(realm, s);
                        logger.debugf("[HumifortisEventListener] Revoked old session %s for user=%s",
                                s.getId(), user.getUsername());
                    })
                    .count();

            if (count > 0) {
                logger.infof("[HumifortisEventListener] REVOKE_OTHER_SESSIONS: revoked %d old session(s) " +
                        "for user=%s, kept new session=%s", count, user.getUsername(), sessionId);
            }
        } catch (Exception e) {
            logger.warnf("[HumifortisEventListener] handleDeferredSessionRevocation failed (non-blocking): %s",
                    e.getMessage());
        }
    }
}

package tech.humifortis.keycloak.caep;

import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserLoginFailureModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import tech.humifortis.keycloak.serviceaccount.ClientContainment;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class CaepActionDispatcher {
    private final KeycloakSession session;

    public CaepActionDispatcher(KeycloakSession session) {
        this.session = session;
    }

    public CaepDispatchResult dispatch(String eventName, CaepParsedSet set, CaepConfig config, RealmModel realm) {
        return switch (eventName) {
            case CaepEventRegistry.SESSION_REVOKED -> handleSessionRevoked(set, config, realm, false);
            case CaepEventRegistry.ASSURANCE_LEVEL_CHANGE -> handleStepUp(set, config, realm);
            case CaepEventRegistry.RISK_LEVEL_CHANGE -> handleStepUp(set, config, realm);
            case CaepEventRegistry.ACCOUNT_DISABLED -> handleAccountDisabled(set, config, realm);
            case CaepEventRegistry.CREDENTIAL_COMPROMISE -> handleCredentialCompromise(set, config, realm);
            case CaepEventRegistry.THROTTLE -> handleThrottle(set, realm);
            default -> CaepDispatchResult.noAction("unsupported event");
        };
    }

    private CaepDispatchResult handleSessionRevoked(CaepParsedSet set, CaepConfig config, RealmModel realm, boolean fromStepUp) {
        String action = fromStepUp ? "step_up_reauth" : "session_revoked";
        if (fromStepUp && !config.enforceStepUpAsReauth()) {
            return CaepDispatchResult.noAction("step-up reauth enforcement disabled");
        }
        if (!fromStepUp && !config.enforceSessionRevoked()) {
            return CaepDispatchResult.noAction("session revocation enforcement disabled");
        }
        try {
            if (set.sessionId() != null && !set.sessionId().isBlank()) {
                UserSessionModel target = session.sessions().getUserSession(realm, set.sessionId());
                if (target == null) return CaepDispatchResult.noAction("target session not found");
                session.sessions().removeUserSession(realm, target);
                return CaepDispatchResult.success(action);
            }
            if (set.subject() == null || set.subject().isBlank()) {
                return CaepDispatchResult.noAction("missing sub for user-level revocation");
            }
            UserModel user = session.users().getUserById(realm, resolveUserId(set.subject()));
            if (user == null) return CaepDispatchResult.noAction("target user not found");
            List<UserSessionModel> sessions = session.sessions().getUserSessionsStream(realm, user).collect(Collectors.toList());
            if (sessions.isEmpty()) return CaepDispatchResult.noAction("no active sessions for subject");
            sessions.forEach(s -> session.sessions().removeUserSession(realm, s));
            return CaepDispatchResult.success(action);
        } catch (Exception e) {
            String message = e.getMessage() == null || e.getMessage().isBlank() ? "dispatch error" : e.getMessage();
            return CaepDispatchResult.failed(action, message);
        }
    }

    /** The subject prefix of a service account: {@code service_account:keycloak:<realm id>:<client id>}. */
    static final String SERVICE_ACCOUNT_SUBJECT = "service_account:keycloak:";

    /** An analyst locked the account: disable the Keycloak user and end its sessions — or, for a service account, its client. */
    private CaepDispatchResult handleAccountDisabled(CaepParsedSet set, CaepConfig config, RealmModel realm) {
        if (set.subject() != null && set.subject().startsWith(SERVICE_ACCOUNT_SUBJECT)) return handleClientDisabled(set.subject(), realm);
        if (!config.enforceAccountDisabled()) return CaepDispatchResult.noAction("account lock enforcement disabled (hf.caep.enforce.accountDisabled)");
        try {
            UserModel user = targetUser(set, realm);
            if (user == null) return CaepDispatchResult.noAction("target user not found");
            user.setEnabled(false);
            revokeAllSessions(user, realm);
            return CaepDispatchResult.success("account_disabled");
        } catch (Exception e) {
            return CaepDispatchResult.failed("account_disabled", messageOf(e));
        }
    }

    /**
     * An analyst disabled a service account's client. The client's own opt-in decides
     * ({@code humifortis.allow_disable=true}, not exempt), not the realm switch of people's accounts.
     */
    private CaepDispatchResult handleClientDisabled(String subject, RealmModel realm) {
        String[] parts = subject.substring(SERVICE_ACCOUNT_SUBJECT.length()).split(":", 2);
        if (parts.length != 2 || parts[1].isBlank()) return CaepDispatchResult.noAction("malformed service-account subject");
        if (!parts[0].equals(realm.getId()) && !parts[0].equals(realm.getName())) {
            return CaepDispatchResult.noAction("the client belongs to another realm");
        }
        try {
            ClientModel client = realm.getClientByClientId(parts[1]);
            if (client == null) return CaepDispatchResult.noAction("target client not found");
            return switch (ClientContainment.disable(client, "analyst")) {
                case DISABLED -> CaepDispatchResult.success("client_disabled");
                case ALREADY_DISABLED -> CaepDispatchResult.noAction("client already disabled");
                case NOT_ALLOWED -> CaepDispatchResult.noAction("the client does not allow it (" + ClientContainment.ATTR_ALLOW_DISABLE + ")");
            };
        } catch (Exception e) {
            return CaepDispatchResult.failed("client_disabled", messageOf(e));
        }
    }

    /** The credentials are suspected compromised: require a new password at the next login and end the sessions. */
    private CaepDispatchResult handleCredentialCompromise(CaepParsedSet set, CaepConfig config, RealmModel realm) {
        if (!config.enforceCredentialCompromise()) return CaepDispatchResult.noAction("password reset enforcement disabled (hf.caep.enforce.credentialCompromise)");
        try {
            UserModel user = targetUser(set, realm);
            if (user == null) return CaepDispatchResult.noAction("target user not found");
            user.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
            revokeAllSessions(user, realm);
            return CaepDispatchResult.success("password_reset_required");
        } catch (Exception e) {
            return CaepDispatchResult.failed("password_reset_required", messageOf(e));
        }
    }

    /**
     * A tenant policy asked to restrict the user's attempts until a deadline: drive Keycloak's native temporary
     * lockout ({@code failedLoginNotBefore}). The deadline only ever moves forward (a redelivered or older event
     * never shortens it); a lift clears it. The password is never looked at while locked out.
     */
    private CaepDispatchResult handleThrottle(CaepParsedSet set, RealmModel realm) {
        if (set.subject() != null && set.subject().startsWith(SERVICE_ACCOUNT_SUBJECT)) {
            // a client_credentials request does not go through the user login form: not enforceable here
            return CaepDispatchResult.noAction("throttle_unsupported_for_entity_type");
        }
        JsonObject body = throttleBody(set);
        if (body == null) return CaepDispatchResult.noAction("malformed throttle event");
        boolean lifted = body.has("lifted") && body.get("lifted").isJsonPrimitive() && body.get("lifted").getAsBoolean();
        long until = body.has("until") && body.get("until").isJsonPrimitive() ? body.get("until").getAsLong() : 0L;
        try {
            UserModel user = targetUser(set, realm);
            if (user == null) return CaepDispatchResult.noAction("target user not found");
            UserLoginFailureModel failure = session.loginFailures().getUserLoginFailure(realm, user.getId());
            if (lifted) {
                // lifting needs no realm flag: it only clears what a throttle set
                if (failure == null || failure.getFailedLoginNotBefore() == 0) return CaepDispatchResult.noAction("no throttle in force");
                // the record is removed, not zeroed: the login-failure cache merges updates by their maximum, so a
                // deadline written back as 0 would be lost
                session.loginFailures().removeUserLoginFailure(realm, user.getId());
                return CaepDispatchResult.success("throttle_lifted");
            }
            if (!realm.isBruteForceProtected()) {
                // without the flag Keycloak never consults failedLoginNotBefore: say so, do not imply protection
                return CaepDispatchResult.noAction(ThrottleLockout.REASON_REALM_BRUTEFORCE_DISABLED);
            }
            if (until <= Instant.now().getEpochSecond()) return CaepDispatchResult.noAction("throttle already over");
            if (failure == null) failure = session.loginFailures().addUserLoginFailure(realm, user.getId());
            if (failure.getFailedLoginNotBefore() >= until) return CaepDispatchResult.success("throttle_already_in_force");
            failure.setFailedLoginNotBefore((int) Math.min(until, Integer.MAX_VALUE));
            return CaepDispatchResult.success("throttle");
        } catch (Exception e) {
            return CaepDispatchResult.failed("throttle", messageOf(e));
        }
    }

    /** The body of the throttle event inside the SET's {@code events} claim. */
    private static JsonObject throttleBody(CaepParsedSet set) {
        if (set.events() == null) return null;
        CaepEventRegistry registry = new CaepEventRegistry();
        for (Map.Entry<String, JsonElement> entry : set.events().entrySet()) {
            if (CaepEventRegistry.THROTTLE.equals(registry.resolve(entry.getKey())) && entry.getValue().isJsonObject()) {
                return entry.getValue().getAsJsonObject();
            }
        }
        return null;
    }

    private UserModel targetUser(CaepParsedSet set, RealmModel realm) {
        if (set.subject() == null || set.subject().isBlank()) return null;
        return session.users().getUserById(realm, resolveUserId(set.subject()));
    }

    private void revokeAllSessions(UserModel user, RealmModel realm) {
        List<UserSessionModel> sessions = session.sessions().getUserSessionsStream(realm, user).collect(Collectors.toList());
        sessions.forEach(s -> session.sessions().removeUserSession(realm, s));
    }

    private static String messageOf(Exception e) {
        return e.getMessage() == null || e.getMessage().isBlank() ? "dispatch error" : e.getMessage();
    }

    private String resolveUserId(String subject) {
        if (subject != null && subject.startsWith("user:keycloak:")) {
            int lastSeparator = subject.lastIndexOf(':');
            if (lastSeparator >= 0 && lastSeparator + 1 < subject.length()) {
                return subject.substring(lastSeparator + 1);
            }
        }
        return subject;
    }

    private CaepDispatchResult handleStepUp(CaepParsedSet set, CaepConfig config, RealmModel realm) {
        if (!config.enforceStepUp()) return CaepDispatchResult.noAction("step-up enforcement disabled");
        if (!config.enforceStepUpAsReauth()) {
            return CaepDispatchResult.failed("step_up", "step-up is not directly supported for active sessions");
        }
        return handleSessionRevoked(set, config, realm, true);
    }
}

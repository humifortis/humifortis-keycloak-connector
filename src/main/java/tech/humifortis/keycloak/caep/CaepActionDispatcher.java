package tech.humifortis.keycloak.caep;

import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;

import tech.humifortis.keycloak.serviceaccount.ClientContainment;

import java.util.List;
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

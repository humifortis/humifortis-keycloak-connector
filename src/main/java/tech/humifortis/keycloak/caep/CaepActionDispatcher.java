package tech.humifortis.keycloak.caep;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;

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

    /** An analyst locked the account: disable the Keycloak user and end its sessions. */
    private CaepDispatchResult handleAccountDisabled(CaepParsedSet set, CaepConfig config, RealmModel realm) {
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

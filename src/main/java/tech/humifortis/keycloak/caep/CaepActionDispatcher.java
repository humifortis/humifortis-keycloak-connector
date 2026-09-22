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
            UserModel user = session.users().getUserById(realm, set.subject());
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

    private CaepDispatchResult handleStepUp(CaepParsedSet set, CaepConfig config, RealmModel realm) {
        if (!config.enforceStepUp()) return CaepDispatchResult.noAction("step-up enforcement disabled");
        if (!config.enforceStepUpAsReauth()) {
            return CaepDispatchResult.failed("step_up", "step-up is not directly supported for active sessions");
        }
        return handleSessionRevoked(set, config, realm, true);
    }
}

package tech.humifortis.keycloak.listener;

import java.util.Map;

import org.keycloak.component.ComponentModel;
import org.keycloak.events.Errors;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.UserStoragePrivateUtil;

/**
 * A failed sign-in that is the directory's fault, not the person's (docs/sso-and-external-idp-e2e.spec.md, P7).
 *
 * <p>When the federated directory does not answer, Keycloak cannot look the person up and reports the sign-in as a failure
 * with no user and {@code invalid_user_credentials}: exactly what a wrong password for an unknown name looks like. Counted
 * as such, a directory outage reads as credential stuffing, and an outage during a real attack hides the attack's
 * evidence among the outage's.</p>
 *
 * <p>The connector tells them apart without calling the directory: it looks the username up in Keycloak's <em>local</em>
 * store only. A person the directory imported earlier is there, with a federation link; Keycloak failing to find her means
 * the directory failed. Such an event is reported as {@code directory_unavailable} for that person, with the directory's
 * name, and never as a failed password. A person never imported cannot be told apart and stays a failed sign-in.</p>
 */
final class DirectoryOutage {

    static final String DETAIL_REASON = "failure_reason";
    static final String REASON = "directory_unavailable";
    static final String DETAIL_DIRECTORY = "directory";

    private DirectoryOutage() {}

    /**
     * Marks the event when it is a directory outage: the local user id in the {@code userId} detail, the reason and the
     * directory. Returns true when it marked it. Never throws.
     */
    static boolean mark(KeycloakSession session, Event event) {
        try {
            if (event.getType() != EventType.LOGIN_ERROR) return false;
            if (event.getUserId() != null && !event.getUserId().isBlank()) return false;
            if (!Errors.INVALID_USER_CREDENTIALS.equals(event.getError()) && !Errors.USER_NOT_FOUND.equals(event.getError())) return false;
            Map<String, String> details = event.getDetails();
            String username = details != null ? details.get("username") : null;
            if (username == null || username.isBlank()) return false;
            RealmModel realm = session.realms().getRealm(event.getRealmId());
            if (realm == null) return false;
            UserModel local = UserStoragePrivateUtil.userLocalStorage(session).getUserByUsername(realm, username);
            if (local == null || local.getFederationLink() == null || local.getFederationLink().isBlank()) return false;
            ComponentModel provider = realm.getComponent(local.getFederationLink());
            details.put("userId", local.getId());
            details.put(DETAIL_REASON, REASON);
            details.put(DETAIL_DIRECTORY, provider != null ? provider.getName() : local.getFederationLink());
            String source = tech.humifortis.keycloak.user.UserContextExtractor.accountSource(session, realm, local);
            if (source != null) details.put("account_source", source);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Whether the event was marked as a directory outage. */
    static boolean isMarked(Event event) {
        return event.getDetails() != null && REASON.equals(event.getDetails().get(DETAIL_REASON));
    }
}

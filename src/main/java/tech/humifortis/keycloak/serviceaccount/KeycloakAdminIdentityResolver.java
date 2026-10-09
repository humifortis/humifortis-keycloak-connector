package tech.humifortis.keycloak.serviceaccount;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;

import tech.humifortis.keycloak.user.UserContextExtractor;

/** {@link AdminIdentityResolver} backed by the Keycloak session. Read-only; any failure answers "unknown". */
public final class KeycloakAdminIdentityResolver implements AdminIdentityResolver {

    private static final Logger logger = Logger.getLogger(KeycloakAdminIdentityResolver.class);

    private final KeycloakSession session;

    public KeycloakAdminIdentityResolver(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public String serviceAccountClientOfUser(String realmId, String userId) {
        try {
            RealmModel realm = realm(realmId);
            if (realm == null || userId == null) return null;
            UserModel user = session.users().getUserById(realm, userId);
            if (user == null) return null;
            String link = user.getServiceAccountClientLink();
            if (link == null || link.isBlank()) return null;
            ClientModel client = realm.getClientById(link);
            return client != null ? client.getClientId() : null;
        } catch (RuntimeException e) {
            logger.debugf("service-account lookup of user failed: %s", e.getMessage());
            return null;
        }
    }

    @Override
    public String serviceAccountClientOfClient(String realmId, String clientUuid) {
        try {
            RealmModel realm = realm(realmId);
            if (realm == null || clientUuid == null) return null;
            ClientModel client = realm.getClientById(clientUuid);
            return client != null && client.isServiceAccountsEnabled() ? client.getClientId() : null;
        } catch (RuntimeException e) {
            logger.debugf("service-account lookup of client failed: %s", e.getMessage());
            return null;
        }
    }

    @Override
    public Boolean containsPrivilegedRole(String realmId, String roleRepresentation) {
        if (roleRepresentation == null || roleRepresentation.isBlank()) return null;
        try {
            RealmModel realm = realm(realmId);
            if (realm == null) return null;
            JsonElement parsed = JsonParser.parseString(roleRepresentation);
            JsonArray roles = parsed.isJsonArray() ? parsed.getAsJsonArray() : new JsonArray();
            for (JsonElement element : roles) {
                if (!element.isJsonObject()) continue;
                JsonObject role = element.getAsJsonObject();
                RoleModel model = role.has("id") ? realm.getRoleById(role.get("id").getAsString()) : null;
                if (model != null && UserContextExtractor.isPrivilegedRole(realm, model)) return Boolean.TRUE;
            }
            return Boolean.FALSE;
        } catch (RuntimeException e) {
            logger.debugf("privileged-role check failed: %s", e.getMessage());
            return null;
        }
    }

    private RealmModel realm(String realmId) {
        RealmModel realm = realmId != null ? session.realms().getRealm(realmId) : null;
        return realm != null ? realm : session.getContext().getRealm();
    }
}

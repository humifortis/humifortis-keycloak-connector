package tech.humifortis.keycloak.serviceaccount;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.keycloak.events.admin.OperationType;

/**
 * Classification of a Keycloak admin event: what kind of change it is and which object it touches.
 * The vocabulary is closed — it is what humifortis-core's {@code admin.change} rules select on.
 */
public final class AdminChange {

    public static final String PRIVILEGE_GRANTED = "privilege_granted";
    public static final String PRIVILEGE_REVOKED = "privilege_revoked";
    public static final String CREDENTIAL_ROTATED = "credential_rotated";
    public static final String CLIENT_CONFIG_CHANGED = "client_config_changed";
    public static final String CLIENT_DELETED = "client_deleted";

    private static final Pattern USER_PATH = Pattern.compile("^users/([^/]+)(/.*)?$");
    private static final Pattern CLIENT_PATH = Pattern.compile("^clients/([^/]+)(/.*)?$");

    /** The object an admin event touches: a user or a client, by Keycloak's internal id. */
    public record Target(Kind kind, String id) {
        public enum Kind { USER, CLIENT }
    }

    private AdminChange() {}

    /** The closed change kind, or null when the event is not one of the kinds humifortis-core scores on. */
    public static String kindOf(String resourceType, OperationType op, String path) {
        String p = path == null ? "" : path.toLowerCase(Locale.ROOT);
        String o = op != null ? op.name() : "";
        // Keycloak reports a role mapping under its own resource types (the path stays users/<id>/role-mappings/…)
        boolean roleMapping = "REALM_ROLE_MAPPING".equals(resourceType) || "CLIENT_ROLE_MAPPING".equals(resourceType)
                || ("USER".equals(resourceType) && p.contains("role-mappings"));
        if (roleMapping) {
            if ("CREATE".equals(o)) return PRIVILEGE_GRANTED;
            if ("DELETE".equals(o)) return PRIVILEGE_REVOKED;
            return null;
        }
        if ("CLIENT".equals(resourceType)) {
            if (p.contains("client-secret")) {
                // regenerating the secret; deleting a rotated (old) secret is housekeeping
                return "DELETE".equals(o) ? null : CREDENTIAL_ROTATED;
            }
            if (p.split("/").length > 2) {
                return null; // a sub-resource of the client (scopes, roles…): not a change of the client itself
            }
            return "DELETE".equals(o) ? CLIENT_DELETED : CLIENT_CONFIG_CHANGED;
        }
        return null;
    }

    /** The user or client a resource path points at (its first segment pair), or null. */
    public static Target targetOf(String resourcePath) {
        if (resourcePath == null) return null;
        Matcher u = USER_PATH.matcher(resourcePath);
        if (u.matches()) return new Target(Target.Kind.USER, u.group(1));
        Matcher c = CLIENT_PATH.matcher(resourcePath);
        if (c.matches()) return new Target(Target.Kind.CLIENT, c.group(1));
        return null;
    }
}

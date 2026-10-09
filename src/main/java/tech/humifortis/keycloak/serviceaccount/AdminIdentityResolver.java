package tech.humifortis.keycloak.serviceaccount;

/**
 * Read-only questions the admin-event mapping asks Keycloak about the objects an admin event touches.
 * Every answer is "unknown" ({@code null}) when Keycloak cannot say: the mapping then keeps the plain
 * behaviour (fail-open).
 */
public interface AdminIdentityResolver {

    /** Answers nothing: used when no Keycloak session is available. */
    AdminIdentityResolver NONE = new AdminIdentityResolver() {
        @Override public String serviceAccountClientOfUser(String realmId, String userId) { return null; }
        @Override public String serviceAccountClientOfClient(String realmId, String clientUuid) { return null; }
        @Override public Boolean containsPrivilegedRole(String realmId, String roleRepresentation) { return null; }
    };

    /** The client id of the service account whose internal user is {@code userId}; null if it is no service-account user. */
    String serviceAccountClientOfUser(String realmId, String userId);

    /** The client id of the client {@code clientUuid} when it has service accounts enabled; null otherwise. */
    String serviceAccountClientOfClient(String realmId, String clientUuid);

    /**
     * Whether one of the roles in a role-mapping representation (the JSON array of role
     * representations an admin event carries) is privileged; null when it cannot be told
     * (no representation, unreadable).
     */
    Boolean containsPrivilegedRole(String realmId, String roleRepresentation);
}

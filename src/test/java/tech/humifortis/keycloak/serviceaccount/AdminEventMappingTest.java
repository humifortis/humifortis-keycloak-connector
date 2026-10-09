package tech.humifortis.keycloak.serviceaccount;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.AuthDetails;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;

import tech.humifortis.keycloak.mapper.EventMapper;
import tech.humifortis.keycloak.model.HumifortisEvent;

/** G1/G2/G3/G11: service accounts as the actor or the target of an admin event, and their context. */
class AdminEventMappingTest {

    private static final String REALM = "acme";
    private static final String SA_USER = "sa-user-uuid";
    private static final String SA_CLIENT_UUID = "sa-client-uuid";
    private static final String SA_CLIENT_ID = "billing-job";
    private static final String HUMAN = "human-admin-uuid";

    /** A fake Keycloak: one service account (client billing-job, internal user sa-user-uuid). */
    private static final class FakeResolver implements AdminIdentityResolver {
        Boolean privileged = null;
        boolean failing = false;

        @Override public String serviceAccountClientOfUser(String realmId, String userId) {
            if (failing) throw new IllegalStateException("keycloak down");
            return SA_USER.equals(userId) ? SA_CLIENT_ID : null;
        }
        @Override public String serviceAccountClientOfClient(String realmId, String clientUuid) {
            if (failing) throw new IllegalStateException("keycloak down");
            return SA_CLIENT_UUID.equals(clientUuid) ? SA_CLIENT_ID : null;
        }
        @Override public Boolean containsPrivilegedRole(String realmId, String representation) { return privileged; }
    }

    private final EventMapper mapper = new EventMapper();
    private final FakeResolver resolver = new FakeResolver();

    private static AdminEvent admin(String actorUserId, ResourceType type, OperationType op, String path) {
        AdminEvent a = new AdminEvent();
        a.setId("evt-1");
        a.setRealmId(REALM);
        a.setOperationType(op);
        a.setResourceType(type);
        a.setResourcePath(path);
        a.setTime(1_760_000_000_000L);
        AuthDetails auth = new AuthDetails();
        auth.setUserId(actorUserId);
        auth.setIpAddress("203.0.113.9");
        a.setAuthDetails(auth);
        return a;
    }

    // ── G1: the actor ───────────────────────────────────────────────────────────

    @Test
    void anAdminActionByAServiceAccountIsAttributedToTheServiceAccount() {
        HumifortisEvent e = mapper.fromKeycloakAdminEvent(
                admin(SA_USER, ResourceType.USER, OperationType.UPDATE, "users/" + HUMAN), resolver);
        assertEquals("service_account:keycloak:acme:billing-job", e.getEntityId());
        assertEquals("service_account", e.getEntityType());
        assertEquals("service_account", e.getMetadata().get("admin.actor_type"));
    }

    @Test
    void anAdminActionByAPersonStaysAUserAction() {
        HumifortisEvent e = mapper.fromKeycloakAdminEvent(
                admin(HUMAN, ResourceType.USER, OperationType.UPDATE, "users/other"), resolver);
        assertEquals("user:keycloak:acme:" + HUMAN, e.getEntityId());
        assertEquals("user", e.getEntityType());
        assertEquals("user", e.getMetadata().get("admin.actor_type"));
    }

    @Test
    void whenKeycloakCannotBeQueriedTheActorKeepsTheLegacyUserIdentity() {
        resolver.failing = true;
        HumifortisEvent e = mapper.fromKeycloakAdminEvent(
                admin(SA_USER, ResourceType.USER, OperationType.UPDATE, "users/x"), resolver);
        assertEquals("user:keycloak:acme:" + SA_USER, e.getEntityId(), "fail-open: the event is still sent");
        assertEquals("user", e.getEntityType());
    }

    @Test
    void theSingleArgumentMappingKeepsTodaysBehaviour() {
        HumifortisEvent e = mapper.fromKeycloakAdminEvent(
                admin(SA_USER, ResourceType.USER, OperationType.UPDATE, "users/x"));
        assertEquals("user:keycloak:acme:" + SA_USER, e.getEntityId());
    }

    // ── G2: the target ──────────────────────────────────────────────────────────

    @Test
    void aRoleGrantedToTheServiceAccountUserTargetsTheServiceAccount() {
        resolver.privileged = Boolean.TRUE;
        AdminEvent a = admin(HUMAN, ResourceType.USER, OperationType.CREATE,
                "users/" + SA_USER + "/role-mappings/clients/realm-mgmt-uuid");
        a.setRepresentation("[{\"id\":\"r1\",\"name\":\"realm-admin\"}]");
        HumifortisEvent e = mapper.fromKeycloakAdminEvent(a, resolver);

        assertEquals("user:keycloak:acme:" + HUMAN, e.getEntityId(), "the actor stays the entity of the event");
        Map<String, Object> m = e.getMetadata();
        assertEquals("privilege_granted", m.get("admin.change"));
        assertEquals("service_account", m.get("admin.target_type"));
        assertEquals("service_account:keycloak:acme:billing-job", m.get("admin.target_id"));
        assertEquals("false", m.get("admin.self_change"));
        assertEquals("true", m.get("admin.privileged_role"));
    }

    @Test
    void aServiceAccountGrantingItselfIsASelfChange() {
        HumifortisEvent e = mapper.fromKeycloakAdminEvent(
                admin(SA_USER, ResourceType.USER, OperationType.CREATE, "users/" + SA_USER + "/role-mappings/realm"),
                resolver);
        assertEquals("true", e.getMetadata().get("admin.self_change"));
        assertEquals("service_account", e.getMetadata().get("admin.actor_type"));
        assertFalse(e.getMetadata().containsKey("admin.privileged_role"),
                "no representation recorded: privilege is not judged");
    }

    @Test
    void anUnprivilegedGrantIsReportedAsSuch() {
        resolver.privileged = Boolean.FALSE;
        AdminEvent a = admin(HUMAN, ResourceType.USER, OperationType.CREATE, "users/" + SA_USER + "/role-mappings/realm");
        a.setRepresentation("[{\"id\":\"r2\",\"name\":\"viewer\"}]");
        assertEquals("false", mapper.fromKeycloakAdminEvent(a, resolver).getMetadata().get("admin.privileged_role"));
    }

    @Test
    void rotatingTheSecretOfAServiceAccountClientIsACredentialRotation() {
        HumifortisEvent e = mapper.fromKeycloakAdminEvent(
                admin(HUMAN, ResourceType.CLIENT, OperationType.ACTION, "clients/" + SA_CLIENT_UUID + "/client-secret"),
                resolver);
        assertEquals("credential_rotated", e.getMetadata().get("admin.change"));
        assertEquals("service_account:keycloak:acme:billing-job", e.getMetadata().get("admin.target_id"));
    }

    @Test
    void deletingAnOldRotatedSecretIsNotARotation() {
        HumifortisEvent e = mapper.fromKeycloakAdminEvent(
                admin(HUMAN, ResourceType.CLIENT, OperationType.DELETE, "clients/" + SA_CLIENT_UUID + "/client-secret/rotated"),
                resolver);
        assertFalse(e.getMetadata().containsKey("admin.change"));
    }

    @Test
    void clientChangesAreClassifiedAndOnlyServiceAccountClientsAreTargets() {
        HumifortisEvent changed = mapper.fromKeycloakAdminEvent(
                admin(HUMAN, ResourceType.CLIENT, OperationType.UPDATE, "clients/" + SA_CLIENT_UUID), resolver);
        assertEquals("client_config_changed", changed.getMetadata().get("admin.change"));
        assertEquals("service_account", changed.getMetadata().get("admin.target_type"));

        HumifortisEvent deleted = mapper.fromKeycloakAdminEvent(
                admin(HUMAN, ResourceType.CLIENT, OperationType.DELETE, "clients/" + SA_CLIENT_UUID), resolver);
        assertEquals("client_deleted", deleted.getMetadata().get("admin.change"));

        HumifortisEvent ordinaryClient = mapper.fromKeycloakAdminEvent(
                admin(HUMAN, ResourceType.CLIENT, OperationType.UPDATE, "clients/some-web-app"), resolver);
        assertEquals("client_config_changed", ordinaryClient.getMetadata().get("admin.change"));
        assertFalse(ordinaryClient.getMetadata().containsKey("admin.target_id"), "a web client is not a service account");
    }

    @Test
    void aChangeToAPersonNamesThePersonAsTheTarget() {
        HumifortisEvent e = mapper.fromKeycloakAdminEvent(
                admin(HUMAN, ResourceType.USER, OperationType.CREATE, "users/someone/role-mappings/realm"), resolver);
        assertEquals("privilege_granted", e.getMetadata().get("admin.change"));
        assertEquals("user", e.getMetadata().get("admin.target_type"));
        assertEquals("user:keycloak:acme:someone", e.getMetadata().get("admin.target_id"));
        assertFalse(e.getMetadata().containsKey("admin.self_change"), "self change is a service-account context");
    }

    @Test
    void anAdministratorEndingSessionsIsARevocationOfTheTargetNeverALogout() {
        for (AdminEvent a : new AdminEvent[] {
                admin(HUMAN, ResourceType.USER, OperationType.ACTION, "users/victim/logout"),
                admin(HUMAN, ResourceType.USER, OperationType.DELETE, "users/victim/sessions"),
                admin(HUMAN, ResourceType.USER_SESSION, OperationType.DELETE, "sessions/abc")}) {
            HumifortisEvent e = mapper.fromKeycloakAdminEvent(a, resolver);
            assertEquals("admin_sessions_revoked", e.getEventType(), a.getResourcePath());
            assertEquals("user:keycloak:acme:" + HUMAN, e.getEntityId(), "attributed to the administrator who acted");
        }
        HumifortisEvent byUser = mapper.fromKeycloakAdminEvent(
                admin(HUMAN, ResourceType.USER, OperationType.ACTION, "users/victim/logout"), resolver);
        assertEquals("user:keycloak:acme:victim", byUser.getMetadata().get("admin.target_id"));
    }

    @Test
    void aRevocationIsClassifiedForTheDefendersMove() {
        HumifortisEvent e = mapper.fromKeycloakAdminEvent(
                admin(HUMAN, ResourceType.USER, OperationType.DELETE, "users/" + SA_USER + "/role-mappings/realm"), resolver);
        assertEquals("privilege_revoked", e.getMetadata().get("admin.change"));
    }

    @Test
    void theClassificationKeepsEveryExistingAdminEventType() {
        // event_type triage is unchanged by the new attributes
        HumifortisEvent e = mapper.fromKeycloakAdminEvent(
                admin(HUMAN, ResourceType.USER, OperationType.CREATE, "users/" + SA_USER + "/role-mappings/realm"), resolver);
        assertEquals("role_assigned", e.getEventType());
    }

    @Test
    void keycloaksOwnRoleMappingResourceTypesAreClassifiedAndMapped() {
        resolver.privileged = Boolean.TRUE;
        for (ResourceType type : new ResourceType[] {ResourceType.REALM_ROLE_MAPPING, ResourceType.CLIENT_ROLE_MAPPING}) {
            AdminEvent a = admin(HUMAN, type, OperationType.CREATE, "users/" + SA_USER + "/role-mappings/clients/rm-uuid");
            a.setRepresentation("[{\"id\":\"r1\"}]");
            HumifortisEvent e = mapper.fromKeycloakAdminEvent(a, resolver);
            assertEquals("role_assigned", e.getEventType(), type.name());
            assertEquals("privilege_granted", e.getMetadata().get("admin.change"), type.name());
            assertEquals("service_account:keycloak:acme:billing-job", e.getMetadata().get("admin.target_id"), type.name());
            assertEquals("true", e.getMetadata().get("admin.privileged_role"), type.name());
        }
        HumifortisEvent revoked = mapper.fromKeycloakAdminEvent(
                admin(HUMAN, ResourceType.REALM_ROLE_MAPPING, OperationType.DELETE, "users/" + SA_USER + "/role-mappings/realm"), resolver);
        assertEquals("role_revoked", revoked.getEventType());
        assertEquals("privilege_revoked", revoked.getMetadata().get("admin.change"));
    }

    // ── AdminChange: the closed vocabulary ──────────────────────────────────────

    @Test
    void targetPathsAreParsed() {
        assertEquals(new AdminChange.Target(AdminChange.Target.Kind.USER, "u1"), AdminChange.targetOf("users/u1/role-mappings/realm"));
        assertEquals(new AdminChange.Target(AdminChange.Target.Kind.CLIENT, "c1"), AdminChange.targetOf("clients/c1"));
        assertNull(AdminChange.targetOf("realms/acme"));
        assertNull(AdminChange.targetOf(null));
    }

    // ── G3: roles of the service-account user are forwarded for CLIENT_LOGIN ────

    @Test
    void theRolesAndPrivilegeResolvedForTheServiceAccountUserAreForwarded() {
        Event login = new Event();
        login.setId("login-1");
        login.setType(EventType.CLIENT_LOGIN);
        login.setRealmId(REALM);
        login.setClientId(SA_CLIENT_ID);
        login.setTime(1_760_000_000_000L);
        Map<String, String> details = new HashMap<>();
        details.put("user_roles", "realm-management:manage-users,viewer");
        details.put("is_privileged", "true");
        details.put("privileged_reason", "role:realm-management:manage-users");
        login.setDetails(details);

        HumifortisEvent e = mapper.fromKeycloakEvent(login);
        assertEquals("service_account", e.getEntityType());
        assertEquals("realm-management:manage-users,viewer", e.getMetadata().get("user_roles"));
        assertEquals("true", e.getMetadata().get("is_privileged"));
        assertEquals("role:realm-management:manage-users", e.getMetadata().get("privileged_reason"));
    }

    // ── G11: owner ──────────────────────────────────────────────────────────────

    @Test
    void theDeclaredOwnerIsForwardedAndOtherwiseAbsent() {
        Map<String, String> out = ServiceAccountContext.resolve(
                Map.of(ServiceAccountContext.ATTR_OWNER, "  payments-team@acme.test "), null, null, java.time.Instant.now());
        assertEquals("payments-team@acme.test", out.get(ServiceAccountContext.KEY_OWNER));
        assertFalse(ServiceAccountContext.resolve(Map.of(), null, null, java.time.Instant.now())
                .containsKey(ServiceAccountContext.KEY_OWNER));
        assertTrue(ServiceAccountContext.KEYS.contains(ServiceAccountContext.KEY_OWNER));
    }

    @Test
    void anOverlongOwnerIsBounded() {
        String owner = "x".repeat(1000);
        Map<String, String> out = ServiceAccountContext.resolve(
                Map.of(ServiceAccountContext.ATTR_OWNER, owner), null, null, java.time.Instant.now());
        assertEquals(ServiceAccountContext.MAX_OWNER_CHARS, out.get(ServiceAccountContext.KEY_OWNER).length());
    }
}

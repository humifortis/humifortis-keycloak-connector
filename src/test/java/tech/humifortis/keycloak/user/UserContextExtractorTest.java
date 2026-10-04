package tech.humifortis.keycloak.user;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.UserSessionProvider;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class UserContextExtractorTest {

    private final UserContextExtractor extractor = new UserContextExtractor();

    @Mock UserModel user;
    @Mock SubjectCredentialManager credentials;
    @Mock RoleModel adminRole;
    @Mock RoleModel userRole;

    static RoleModel realmRole(String name) {
        RoleModel r = mock(RoleModel.class);
        lenient().when(r.getName()).thenReturn(name);
        lenient().when(r.isClientRole()).thenReturn(false);
        lenient().when(r.isComposite()).thenReturn(false);
        return r;
    }

    static RoleModel clientRole(String clientId, String name) {
        RoleModel r = mock(RoleModel.class);
        ClientModel c = mock(ClientModel.class);
        lenient().when(c.getClientId()).thenReturn(clientId);
        lenient().when(r.getName()).thenReturn(name);
        lenient().when(r.isClientRole()).thenReturn(true);
        lenient().when(r.getContainer()).thenReturn(c);
        lenient().when(r.isComposite()).thenReturn(false);
        return r;
    }

    static GroupModel group(String name, GroupModel parent, RoleModel... roles) {
        GroupModel g = mock(GroupModel.class);
        lenient().when(g.getName()).thenReturn(name);
        lenient().when(g.getParent()).thenReturn(parent);
        lenient().when(g.getRoleMappingsStream()).thenAnswer(i -> Stream.of(roles));
        return g;
    }

    @Test
    void extractMfaMethods_returnsSupportedMethodsInCredentialOrder() {
        CredentialModel otp = new CredentialModel();
        otp.setType("otp");
        CredentialModel webauthnPasswordless = new CredentialModel();
        webauthnPasswordless.setType("webauthn-passwordless");

        when(user.credentialManager()).thenReturn(credentials);
        when(credentials.getStoredCredentialsStream()).thenReturn(Stream.of(otp, webauthnPasswordless));

        assertEquals(List.of("TOTP", "WEBAUTHN_PASSWORDLESS"), extractor.extractMfaMethods(user));
    }

    @Test
    void hasMfaEnrolled_returnsFalseWhenOnlyUnsupportedCredentialsExist() {
        CredentialModel password = new CredentialModel();
        password.setType("password");

        when(user.credentialManager()).thenReturn(credentials);
        when(credentials.getStoredCredentialsStream()).thenReturn(Stream.of(password));

        assertFalse(extractor.hasMfaEnrolled(user));
    }

    @Test
    void hasPrivilegedRole_detectsAdminStyleRoles() {
        when(adminRole.getName()).thenReturn("realm-admin");
        when(userRole.getName()).thenReturn("user");

        when(user.getRoleMappingsStream()).thenReturn(Stream.of(adminRole, userRole));

        assertTrue(extractor.hasPrivilegedRole(user));
    }

    // ── effective roles and groups ────────────────────────────────────────────

    @Test
    void effectiveRoles_includeGroupInheritedAndCompositeRoles_clientRolesPrefixed() {
        RoleModel manageUsers = clientRole("realm-management", "manage-users");
        RoleModel composite = realmRole("it-staff");
        RoleModel viewer = realmRole("viewer");
        when(composite.isComposite()).thenReturn(true);
        when(composite.getCompositesStream()).thenAnswer(i -> Stream.of(viewer));
        GroupModel it = group("it", null);
        GroupModel admins = group("admins", it, manageUsers);
        when(user.getRoleMappingsStream()).thenAnswer(i -> Stream.of(composite));
        when(user.getGroupsStream()).thenAnswer(i -> Stream.of(admins));

        List<String> roles = extractor.extractRoleNames(user);
        assertEquals(List.of("it-staff", "realm-management:manage-users", "viewer"), roles);
        assertEquals(List.of("/it/admins"), extractor.extractGroupPaths(user));
    }

    @Test
    void anApplicationRoleNamedAdminIsNotThePlatformAdmin() {
        assertFalse(UserContextExtractor.isBuiltInPrivileged("my-app:admin"));
        assertTrue(UserContextExtractor.isBuiltInPrivileged("realm-management:manage-users"));
        assertTrue(UserContextExtractor.isBuiltInPrivileged("master-realm:manage-users"));
        assertTrue(UserContextExtractor.isBuiltInPrivileged("admin"));
    }

    @Test
    void privileged_viaBuiltInRole_viaRealmAttributeRole_viaGroup() {
        RealmModel realm = mock(RealmModel.class);
        assertEquals("role:realm-management:manage-users",
                UserContextExtractor.privilegedReason(realm, List.of("realm-management:manage-users"), List.of()));
        when(realm.getAttribute(UserContextExtractor.ATTR_PRIVILEGED_ROLES)).thenReturn("finance-admin, my-app:admin");
        assertEquals("role:my-app:admin", UserContextExtractor.privilegedReason(realm, List.of("my-app:admin"), List.of()));
        when(realm.getAttribute(UserContextExtractor.ATTR_PRIVILEGED_GROUPS)).thenReturn("/finance");
        assertEquals("group:/finance/admins", UserContextExtractor.privilegedReason(realm, List.of("viewer"), List.of("/finance/admins")));
        assertNull(UserContextExtractor.privilegedReason(realm, List.of("viewer"), List.of("/financeX")), "a prefix is a path, not a string prefix");
    }

    @Test
    void groupsAndRolesAreBoundedAndSortedDeterministically() {
        List<String> many = new ArrayList<>();
        for (int i = 0; i < 150; i++) many.add(String.format("/g/%03d", i));
        UserContextExtractor.Bounded b = UserContextExtractor.bound(many);
        assertTrue(b.truncated());
        assertEquals(UserContextExtractor.MAX_ITEMS, b.values().size());
        assertEquals("/g/000", b.values().get(0));
        UserContextExtractor.Bounded tooLong = UserContextExtractor.bound(List.of("x".repeat(300), "/ok"));
        assertEquals(List.of("/ok"), tooLong.values());
        assertTrue(tooLong.truncated());
        List<String> wide = new ArrayList<>();
        for (int i = 0; i < 60; i++) wide.add(String.format("/%03d/", i) + "y".repeat(100));
        assertTrue(String.join(",", UserContextExtractor.bound(wide).values()).length() <= UserContextExtractor.MAX_JOINED_CHARS);
    }

    // ── account age ───────────────────────────────────────────────────────────

    @Test
    void accountCreation_fromKeycloakTimestamp() {
        RealmModel realm = mock(RealmModel.class);
        Instant now = Instant.parse("2026-10-03T00:00:00Z");
        when(user.getCreatedTimestamp()).thenReturn(Instant.parse("2026-09-01T00:00:00Z").toEpochMilli());
        Instant[] out = new Instant[1];
        assertEquals("keycloak", UserContextExtractor.extractAccountCreation(realm, user, now, out));
        assertEquals(Instant.parse("2026-09-01T00:00:00Z"), out[0]);
    }

    @Test
    void accountCreation_fromLdapGeneralizedTime_whenKeycloakHasNone() {
        RealmModel realm = mock(RealmModel.class);
        when(user.getCreatedTimestamp()).thenReturn(null);
        when(user.getFirstAttribute("createTimestamp")).thenReturn("20240115103000Z");
        Instant[] out = new Instant[1];
        assertEquals("attribute:createTimestamp", UserContextExtractor.extractAccountCreation(realm, user, Instant.parse("2026-10-03T00:00:00Z"), out));
        assertEquals(Instant.parse("2024-01-15T10:30:00Z"), out[0]);
    }

    @Test
    void accountCreation_fromConfiguredIsoAttribute() {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getAttribute(UserContextExtractor.ATTR_CREATED_ATTRIBUTES)).thenReturn("hr_start_date");
        when(user.getCreatedTimestamp()).thenReturn(null);
        when(user.getFirstAttribute("hr_start_date")).thenReturn("2025-03-01T08:00:00+01:00");
        Instant[] out = new Instant[1];
        assertEquals("attribute:hr_start_date", UserContextExtractor.extractAccountCreation(realm, user, Instant.parse("2026-10-03T00:00:00Z"), out));
        assertEquals(Instant.parse("2025-03-01T07:00:00Z"), out[0]);
    }

    @Test
    void accountCreation_unknownOrFutureIsNeverSent() {
        RealmModel realm = mock(RealmModel.class);
        Instant now = Instant.parse("2026-10-03T00:00:00Z");
        when(user.getCreatedTimestamp()).thenReturn(now.plusSeconds(86_400).toEpochMilli());
        Instant[] out = new Instant[1];
        assertNull(UserContextExtractor.extractAccountCreation(realm, user, now, out));
        assertNull(out[0]);
    }

    @Test
    void timestampParsing() {
        assertEquals(Instant.parse("2024-01-15T10:30:00Z"), UserContextExtractor.parseTimestamp("20240115103000.0Z"));
        assertEquals(Instant.parse("2024-01-15T09:30:00Z"), UserContextExtractor.parseTimestamp("20240115103000+0100"));
        assertNull(UserContextExtractor.parseTimestamp("yesterday"));
        assertNull(UserContextExtractor.parseTimestamp(" "));
    }

    // ── snapshot → payload ────────────────────────────────────────────────────

    @Test
    void snapshotCarriesGroupsPrivilegeAndAccountCreation() {
        KeycloakSession session = mock(KeycloakSession.class, Answers.RETURNS_DEEP_STUBS);
        RealmModel realm = mock(RealmModel.class);
        RoleModel manageUsers = clientRole("realm-management", "manage-users");
        GroupModel admins = group("admins", group("it", null), manageUsers);
        when(user.getRoleMappingsStream()).thenAnswer(i -> Stream.empty());
        when(user.getGroupsStream()).thenAnswer(i -> Stream.of(admins));
        when(user.credentialManager()).thenReturn(credentials);
        when(credentials.getStoredCredentialsStream()).thenAnswer(i -> Stream.empty());
        when(user.getCreatedTimestamp()).thenReturn(Instant.parse("2026-09-03T00:00:00Z").toEpochMilli());
        when(session.sessions().getUserSessionsStream(realm, user)).thenAnswer(i -> Stream.empty());

        UserContextSnapshot s = extractor.build(session, realm, user, Instant.parse("2026-10-03T00:00:00Z"));
        Map<String, String> out = new HashMap<>();
        s.writeTo(out::put);
        assertEquals("true", out.get("is_privileged"));
        assertEquals("role:realm-management:manage-users", out.get("privileged_reason"), "privilege inherited from a group is seen");
        assertEquals("/it/admins", out.get("user_groups"));
        assertEquals("realm-management:manage-users", out.get("user_roles"));
        assertEquals("2026-09-03T00:00:00Z", out.get("account_created_at"));
        assertEquals("keycloak", out.get("account_created_source"));
        assertEquals("30", out.get("account_age_days"));
        assertEquals("false", out.get("mfa_enrolled"));
    }

    @SuppressWarnings("unused")
    private static void unused(UserProvider p, UserSessionProvider s) {}
}

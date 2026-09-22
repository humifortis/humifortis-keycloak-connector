package tech.humifortis.keycloak.user;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Set;

public class UserContextExtractor {

    private static final Set<String> PRIVILEGED_ROLES = Set.of(
            "admin", "realm-admin", "manage-users", "manage-realm",
            "manage-clients", "manage-identity-providers", "impersonation",
            "create-realm", "manage-authorization"
    );

    public UserContextSnapshot extract(KeycloakSession session, RealmModel realm, UserModel user) {
        List<String> mfaMethods = extractMfaMethods(user);
        List<String> roleNames = extractRoleNames(user);
        Long accountAgeDays = extractAccountAgeDays(user);
        long activeSessionCount = session.sessions().getUserSessionsStream(realm, user).count();
        return new UserContextSnapshot(
                user.getUsername(),
                user.getEmail(),
                user.isEmailVerified(),
                mfaMethods,
                roleNames,
                !mfaMethods.isEmpty(),
                hasPrivilegedRole(roleNames),
                accountAgeDays,
                activeSessionCount
        );
    }

    public List<String> extractMfaMethods(UserModel user) {
        return user.credentialManager().getStoredCredentialsStream()
                .map(cred -> switch (cred.getType()) {
                    case "otp" -> "TOTP";
                    case "webauthn" -> "WEBAUTHN";
                    case "webauthn-passwordless" -> "WEBAUTHN_PASSWORDLESS";
                    default -> null;
                })
                .filter(java.util.Objects::nonNull)
                .toList();
    }

    public boolean hasMfaEnrolled(UserModel user) {
        return !extractMfaMethods(user).isEmpty();
    }

    public boolean hasPrivilegedRole(UserModel user) {
        return hasPrivilegedRole(extractRoleNames(user));
    }

    public List<String> extractRoleNames(UserModel user) {
        return user.getRoleMappingsStream()
                .map(RoleModel::getName)
                .toList();
    }

    public Long extractAccountAgeDays(UserModel user) {
        if (user.getCreatedTimestamp() == null) return null;
        return ChronoUnit.DAYS.between(
                Instant.ofEpochMilli(user.getCreatedTimestamp()),
                Instant.now());
    }

    private boolean hasPrivilegedRole(List<String> roleNames) {
        return roleNames.stream().anyMatch(PRIVILEGED_ROLES::contains);
    }
}

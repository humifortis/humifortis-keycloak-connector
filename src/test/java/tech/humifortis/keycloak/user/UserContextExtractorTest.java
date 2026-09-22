package tech.humifortis.keycloak.user;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserContextExtractorTest {

    private final UserContextExtractor extractor = new UserContextExtractor();

    @Mock UserModel user;
    @Mock SubjectCredentialManager credentials;
    @Mock RoleModel adminRole;
    @Mock RoleModel userRole;

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
}

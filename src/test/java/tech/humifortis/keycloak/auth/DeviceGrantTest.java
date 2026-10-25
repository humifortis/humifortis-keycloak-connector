package tech.humifortis.keycloak.auth;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.grants.device.DeviceGrantType;
import org.keycloak.sessions.AuthenticationSessionModel;

class DeviceGrantTest {

    private static final String NOTE = DeviceGrantType.OAUTH2_DEVICE_VERIFIED_USER_CODE;

    private static AuthenticationFlowContext context(String verifiedUserCode, KeycloakSession session, RealmModel realm) {
        AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
        when(authSession.getClientNote(NOTE)).thenReturn(verifiedUserCode);
        AuthenticationFlowContext ctx = mock(AuthenticationFlowContext.class);
        when(ctx.getAuthenticationSession()).thenReturn(authSession);
        when(ctx.getSession()).thenReturn(session);
        when(ctx.getRealm()).thenReturn(realm);
        return ctx;
    }

    @Test
    void theApprovalOfADeviceIsRecognisedByTheVerifiedUserCode() {
        AuthenticationSessionModel with = mock(AuthenticationSessionModel.class);
        when(with.getClientNote(NOTE)).thenReturn("ABCD-EFGH");
        assertTrue(DeviceGrant.isApproval(with));
        assertFalse(DeviceGrant.isApproval(mock(AuthenticationSessionModel.class)), "an ordinary browser sign-in");
        assertFalse(DeviceGrant.isApproval(null));
    }

    @Test
    void refusingTheApprovalDeniesTheDeviceCode() {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmModel realm = mock(RealmModel.class);
        try (var device = mockStatic(DeviceGrantType.class)) {
            device.when(() -> DeviceGrantType.denyUserCode(eq(session), eq(realm), eq("ABCD-EFGH"))).thenReturn(true);
            assertTrue(DeviceGrant.denyDevice(context("ABCD-EFGH", session, realm)));
            device.verify(() -> DeviceGrantType.denyUserCode(session, realm, "ABCD-EFGH"));
        }
    }

    @Test
    void anOrdinarySignInIsNeverTouched() {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmModel realm = mock(RealmModel.class);
        try (var device = mockStatic(DeviceGrantType.class)) {
            assertFalse(DeviceGrant.denyDevice(context(null, session, realm)));
            device.verify(() -> DeviceGrantType.denyUserCode(any(), any(), any()), org.mockito.Mockito.never());
        }
    }

    @Test
    void aFaultNeverChangesTheRefusalThePersonGets() {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmModel realm = mock(RealmModel.class);
        try (var device = mockStatic(DeviceGrantType.class)) {
            device.when(() -> DeviceGrantType.denyUserCode(any(), any(), any())).thenThrow(new IllegalStateException("cache down"));
            assertFalse(DeviceGrant.denyDevice(context("ABCD-EFGH", session, realm)));
        }
    }
}

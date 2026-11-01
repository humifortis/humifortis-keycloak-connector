package tech.humifortis.keycloak.auth;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.protocol.oidc.grants.device.DeviceGrantType;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * The device authorization grant (RFC 8628, docs/sso-and-external-idp-e2e.spec.md, P12): the person approves a device in a
 * browser, so the approval is an ordinary sign-in and runs through the same flow, where Humifortis decides it.
 *
 * <p>What the flow does not do by itself is tell the device. When Humifortis refuses the sign-in, Keycloak shows the error page
 * to the person and the device's code stays <em>pending</em> until it expires: the device keeps polling for a minute or ten.
 * Refusing the approval must refuse the device too, so the code is denied and the polling client is answered
 * {@code access_denied} at once, never a token and never "still waiting".</p>
 */
public final class DeviceGrant {

    private static final Logger LOG = Logger.getLogger(DeviceGrant.class);

    private DeviceGrant() {}

    /** Whether the authentication session is the approval of a device (the user code was verified in this browser). */
    public static boolean isApproval(AuthenticationSessionModel authSession) {
        return authSession != null && authSession.getClientNote(DeviceGrantType.OAUTH2_DEVICE_VERIFIED_USER_CODE) != null;
    }

    /**
     * Denies the device code of the approval being refused. Returns true when a device code was denied; false when the
     * sign-in is not the approval of a device, or the code could not be denied. Never throws: a fault here must not change
     * the refusal the person already gets.
     */
    public static boolean denyDevice(AuthenticationFlowContext context) {
        try {
            AuthenticationSessionModel authSession = context.getAuthenticationSession();
            if (!isApproval(authSession)) return false;
            String userCode = authSession.getClientNote(DeviceGrantType.OAUTH2_DEVICE_VERIFIED_USER_CODE);
            boolean denied = DeviceGrantType.denyUserCode(context.getSession(), context.getRealm(), userCode);
            LOG.infof("[Humifortis] device approval refused: the device code is denied (%s)", denied);
            return denied;
        } catch (RuntimeException e) {
            LOG.debugf("[Humifortis] the device code could not be denied: %s", e.getMessage());
            return false;
        }
    }
}

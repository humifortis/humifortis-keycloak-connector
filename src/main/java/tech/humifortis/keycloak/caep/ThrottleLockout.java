package tech.humifortis.keycloak.caep;

import org.keycloak.events.EventType;

/**
 * The temporary lockout a Humifortis throttle is carried out with: Keycloak's own, native one. The throttle sets
 * the user's {@code failedLoginNotBefore}; the username/password form then refuses the attempt BEFORE it looks at
 * the password, with its generic message, so a refused attempt says nothing about the password's correctness.
 * It needs the realm's brute-force detection to be enabled (a realm setting, not a connector one).
 */
public final class ThrottleLockout {

    /** The error Keycloak puts on the LOGIN_ERROR of an attempt refused by a temporary lockout. */
    public static final String ERROR_TEMPORARILY_DISABLED = "user_temporarily_disabled";

    /** Stable reason reported back to core when the throttle cannot be carried out. */
    public static final String REASON_REALM_BRUTEFORCE_DISABLED = "realm_bruteforce_disabled";

    private ThrottleLockout() {
    }

    /**
     * An attempt refused because the account is locked out is enforcement, never a wrong password: reporting it
     * as a failed login would feed the detector that created the throttle and extend it forever.
     */
    public static boolean isLockoutRefusal(EventType type, String error) {
        return type == EventType.LOGIN_ERROR && ERROR_TEMPORARILY_DISABLED.equals(error);
    }
}

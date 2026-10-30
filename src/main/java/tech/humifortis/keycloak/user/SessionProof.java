package tech.humifortis.keycloak.user;

import java.util.LinkedHashMap;
import java.util.Map;

import org.keycloak.models.UserSessionModel;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * The session's last proof of the identity (docs/session-assurance-sas.spec.md, S2): the ladder level of the step that
 * completed, when, and the kind of WebAuthn credential it used. Humifortis reads it at every later decision on the session
 * (single sign-on reuse, token refresh) to compute the session's assurance; without it those decisions have no observed
 * proof.
 *
 * <p>Recorded as user-session notes through the authentication session, so that Keycloak carries them onto the user
 * session it creates or continues. The last completed proof wins: a fresh password after a passkey is a weaker but newer
 * proof, and both the level and the freshness say so. Never throws: a sign-in never depends on it.</p>
 */
public final class SessionProof {

    public static final String NOTE_LEVEL = "HUMIFORTIS_AUTH_LEVEL";
    public static final String NOTE_TIME = "HUMIFORTIS_AUTH_TIME";
    public static final String NOTE_KIND = "HUMIFORTIS_AUTH_FACTOR_KIND";

    /** The metadata keys core reads (internal/core/assurance: MetaAuthLevel, MetaAuthTime, MetaAuthFactorKind, MetaSessionIdle). */
    public static final String META_LEVEL = "auth_level";
    public static final String META_TIME = "auth_time";
    public static final String META_KIND = "auth_factor_kind";
    public static final String META_IDLE = "session_idle_seconds";

    private static final int MAX_LEVEL = 3;

    private SessionProof() {}

    /** Records a completed proof of the given ladder level (1 a password or a code, 2 an app, 3 phishing-resistant). */
    public static void record(AuthenticationSessionModel as, int level, String factorKind, long nowSec) {
        if (as == null || level < 1) return;
        try {
            as.setUserSessionNote(NOTE_LEVEL, String.valueOf(Math.min(level, MAX_LEVEL)));
            as.setUserSessionNote(NOTE_TIME, String.valueOf(nowSec));
            // a proof without a WebAuthn credential has no kind: the note is cleared, never left from an earlier proof
            as.setUserSessionNote(NOTE_KIND, factorKind != null && !factorKind.isBlank() ? factorKind.trim().toLowerCase() : "");
        } catch (RuntimeException e) {
            // the proof is evidence for later decisions, never a condition of this one
        }
    }

    /** The proof of a user session as metadata of an evaluation; empty when none was recorded. */
    public static Map<String, String> metadata(UserSessionModel us, long nowSec) {
        Map<String, String> out = new LinkedHashMap<>();
        if (us == null) return out;
        try {
            String level = us.getNote(NOTE_LEVEL);
            String time = us.getNote(NOTE_TIME);
            if (!valid(level) || !valid(time)) return out;
            out.put(META_LEVEL, level);
            out.put(META_TIME, time);
            String kind = us.getNote(NOTE_KIND);
            if (kind != null && !kind.isBlank()) out.put(META_KIND, kind);
            int refreshed = us.getLastSessionRefresh();
            if (refreshed > 0) out.put(META_IDLE, String.valueOf(Math.max(0, nowSec - refreshed)));
        } catch (RuntimeException e) {
            out.clear();
        }
        return out;
    }

    private static boolean valid(String n) {
        if (n == null || n.isBlank()) return false;
        try {
            return Long.parseLong(n.trim()) > 0;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}

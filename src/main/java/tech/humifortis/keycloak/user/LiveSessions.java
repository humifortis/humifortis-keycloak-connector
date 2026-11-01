package tech.humifortis.keycloak.user;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.function.BiConsumer;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;

/**
 * The other live sessions of a person, sent with an evaluation so that Humifortis can judge their diversity
 * (docs/sso-and-external-idp-e2e.spec.md, P20): address, age, idle time, platform and User-Agent of each. The connector does no
 * geolocation or User-Agent parsing; Humifortis resolves where each session comes from and what device it is.
 *
 * <p>Bounded: at most {@link #MAX} sessions, the youngest first, and a fault reads as "no list" (fail-open).</p>
 */
public final class LiveSessions {

    /** The most sessions one evaluation carries. */
    public static final int MAX = 25;
    /** The user-session notes the listener writes at sign-in. */
    public static final String NOTE_USER_AGENT = "HUMIFORTIS_UA";
    public static final String NOTE_PLATFORM = "HUMIFORTIS_PLATFORM";
    /** The metadata key core reads the list from. */
    public static final String METADATA_KEY = "live_sessions";

    private static final int MAX_UA = 160;

    private LiveSessions() {}

    /** One session as the connector sees it. */
    public record Entry(String ip, long startedSec, long lastRefreshSec, String platform, String userAgent) {}

    /**
     * The entries of the person's live sessions other than {@code currentSessionId}, as the list core reads:
     * {@code ip|age seconds|idle seconds|platform|user agent}, comma separated (no field holds a comma).
     */
    public static String format(List<Entry> sessions, long nowSec) {
        List<String> out = new ArrayList<>();
        sessions.stream()
                .filter(s -> s.ip() != null && !s.ip().isBlank())
                .sorted(Comparator.comparingLong(Entry::startedSec).reversed())
                .limit(MAX)
                .forEach(s -> out.add(String.join("|",
                        clean(s.ip()),
                        String.valueOf(Math.max(0, nowSec - s.startedSec())),
                        String.valueOf(Math.max(0, nowSec - s.lastRefreshSec())),
                        clean(s.platform()),
                        truncate(clean(s.userAgent()), MAX_UA))));
        return String.join(",", out);
    }

    /** No separator of the list or of an entry may appear inside a field. */
    static String clean(String v) {
        if (v == null) return "";
        return v.replace(',', ' ').replace('|', ' ').replace('\n', ' ').replace('\r', ' ').trim();
    }

    private static String truncate(String v, int max) {
        return v.length() <= max ? v : v.substring(0, max);
    }

    /** Writes the list into the evaluation metadata; nothing is written when the person has no other live session. */
    public static void writeTo(KeycloakSession session, RealmModel realm, UserModel user, String currentSessionId, BiConsumer<String, String> put) {
        try {
            long now = System.currentTimeMillis() / 1000L;
            List<Entry> entries = new ArrayList<>();
            session.sessions().getUserSessionsStream(realm, user)
                    .filter(s -> !s.getId().equals(currentSessionId))
                    .limit(MAX * 2L)
                    .forEach(s -> entries.add(entryOf(s)));
            String list = format(entries, now);
            if (!list.isEmpty()) put.accept(METADATA_KEY, list);
        } catch (RuntimeException e) {
            // a fault never stops an evaluation: the diversity is then not judged
        }
    }

    private static Entry entryOf(UserSessionModel s) {
        return new Entry(s.getIpAddress(), s.getStarted(), s.getLastSessionRefresh(), s.getNote(NOTE_PLATFORM), s.getNote(NOTE_USER_AGENT));
    }
}

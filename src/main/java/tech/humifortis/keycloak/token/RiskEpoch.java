package tech.humifortis.keycloak.token;

import org.keycloak.models.UserSessionModel;

/**
 * The risk epoch (docs/sso-and-external-idp-e2e.spec.md, P23): Humifortis counts the changes of a person's risk level and says
 * the count with each decision. The connector notes it on the user session each time it lets a sign-in, a refresh or an
 * exchange through, and sends it back at the next touch as the epoch the artefact was issued in, so the decision record can say
 * how many changes of risk happened since. It never changes what the connector does.
 */
public final class RiskEpoch {

    /** The user session note holding the epoch the session's tokens were last issued in. */
    public static final String NOTE = "HUMIFORTIS_RISK_EPOCH";
    /** The metadata key core reads the issue-time epoch from. */
    public static final String METADATA_KEY = "token_risk_epoch";

    private RiskEpoch() {}

    /** The epoch noted on the session, or null when none was (a session older than the epoch, or no decision yet). */
    public static Long of(UserSessionModel session) {
        if (session == null) return null;
        return parse(session.getNote(NOTE));
    }

    /** Notes the epoch; a zero or missing epoch (the person's risk never changed) leaves the session as it is. */
    public static void record(UserSessionModel session, long epoch) {
        if (session == null || epoch <= 0) return;
        session.setNote(NOTE, String.valueOf(epoch));
    }

    static Long parse(String note) {
        if (note == null || note.isBlank()) return null;
        try {
            long v = Long.parseLong(note.trim());
            return v > 0 ? v : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }
}

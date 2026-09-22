package tech.humifortis.keycloak.caep;

import org.jboss.logging.Logger;

import java.time.Instant;

public final class CaepAuditLogger {
    private static final Logger LOG = Logger.getLogger("tech.humifortis.caep.audit");

    private CaepAuditLogger() {}

    public static void log(CaepAuditRecord r) {
        LOG.infof("{\"ts\":\"%s\",\"jti\":\"%s\",\"iss\":\"%s\",\"realm\":\"%s\",\"event\":\"%s\"," +
                        "\"sub\":\"%s\",\"sid\":\"%s\",\"decision_id\":\"%s\",\"received_ts\":\"%s\",\"event_ts\":\"%s\"," +
                        "\"validation\":\"%s\",\"processing\":\"%s\",\"action\":\"%s\",\"error\":\"%s\"}",
                Instant.now(),
                s(r.jti()),
                s(r.issuer()),
                s(r.realm()),
                s(r.eventType()),
                s(r.subject()),
                s(r.sessionId()),
                s(r.decisionId()),
                s(r.receivedTimestamp()),
                s(r.eventTimestamp()),
                s(r.validationResult()),
                s(r.processingResult()),
                s(r.action()),
                s(r.error()));
    }

    private static String s(String value) {
        if (value == null) return "";
        return value.replaceAll("[\\n\\r\\t\\\\\"<>]", "_");
    }
}

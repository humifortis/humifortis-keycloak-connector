package tech.humifortis.keycloak.caep;

import org.jboss.logging.Logger;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import com.google.gson.Gson;

public final class CaepAuditLogger {
    private static final Logger LOG = Logger.getLogger("tech.humifortis.caep.audit");
    private static final Gson GSON = new Gson();

    private CaepAuditLogger() {}

    public static void log(CaepAuditRecord r) {
        Map<String, String> event = new LinkedHashMap<>();
        event.put("ts", Instant.now().toString());
        event.put("jti", s(r.jti()));
        event.put("iss", s(r.issuer()));
        event.put("realm", s(r.realm()));
        event.put("event", s(r.eventType()));
        event.put("sub", s(r.subject()));
        event.put("sid", s(r.sessionId()));
        event.put("decision_id", s(r.decisionId()));
        event.put("received_ts", s(r.receivedTimestamp()));
        event.put("event_ts", s(r.eventTimestamp()));
        event.put("validation", s(r.validationResult()));
        event.put("processing", s(r.processingResult()));
        event.put("action", s(r.action()));
        event.put("error", s(r.error()));
        LOG.info(GSON.toJson(event));
    }

    private static String s(String value) {
        if (value == null) return "";
        return value.replaceAll("[\\n\\r\\t\\\\\"<>]", "_");
    }
}

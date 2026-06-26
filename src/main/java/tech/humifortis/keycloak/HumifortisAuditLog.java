package tech.humifortis.keycloak;
import org.jboss.logging.Logger;
public final class HumifortisAuditLog {
    private static final Logger logger = Logger.getLogger("tech.humifortis.audit");
    private HumifortisAuditLog() {}
    public static void log(String event, String userId, String method,
                           String outcome, String code, String correlationId, String detail) {
        logger.infof("{\"ts\":\"%s\",\"evt\":\"%s\",\"uid\":\"%s\",\"method\":\"%s\"," +
                     "\"outcome\":\"%s\",\"code\":\"%s\",\"corr\":\"%s\",\"detail\":\"%s\"}",
                java.time.Instant.now(), sanitize(event), pseudoUser(userId),
                sanitize(method), sanitize(outcome), sanitize(code),
                sanitize(correlationId), sanitize(detail));
    }
    public static String pseudoUser(String userId) {
        if (userId == null || userId.isBlank()) return "hf:u:unknown";
        try {
            var md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] h = md.digest(userId.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return "hf:u:" + java.util.Base64.getEncoder().encodeToString(h).substring(0, 8);
        } catch (Exception e) { return "hf:u:err"; }
    }
    public static String sanitize(String s) {
        if (s == null) return "";
        return s.replaceAll("[\\n\\r\\t\\\\\"<>]", "_");
    }
}

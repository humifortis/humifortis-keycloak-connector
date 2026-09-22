package tech.humifortis.keycloak.caep;

public record CaepAuditRecord(
        String jti,
        String issuer,
        String realm,
        String eventType,
        String subject,
        String sessionId,
        String decisionId,
        String receivedTimestamp,
        String eventTimestamp,
        String validationResult,
        String processingResult,
        String action,
        String error
) {
}

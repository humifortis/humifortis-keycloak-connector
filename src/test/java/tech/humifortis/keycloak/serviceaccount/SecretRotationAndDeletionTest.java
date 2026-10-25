package tech.humifortis.keycloak.serviceaccount;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.keycloak.events.admin.OperationType;

/** CRY-6 (a rotated secret) and PRV-1 (a person deleted by an administrator): what the connector reports. */
class SecretRotationAndDeletionTest {

    private static final Instant NOW = Instant.parse("2026-10-21T12:00:00Z");
    private static final long CLIENT_CREATED = Instant.parse("2026-09-01T08:00:00Z").toEpochMilli();

    private static Map<String, String> secretCreated(Instant at) {
        return Map.of(ServiceAccountContext.ATTR_SECRET_CREATED, Long.toString(at.getEpochSecond()));
    }

    @Test
    void aSecretCreatedWithTheClientIsNotARotation() {
        // Keycloak stamps the secret within the same request as the client
        assertNull(ServiceAccountContext.secretRotationAgeDays(secretCreated(Instant.ofEpochMilli(CLIENT_CREATED).plusSeconds(2)), CLIENT_CREATED, NOW));
    }

    @Test
    void aSecretCreatedLongAfterTheClientIsARotationAndItsAgeIsInDays() {
        Instant rotated = NOW.minusSeconds(2 * 86_400 + 600);
        assertEquals("2", ServiceAccountContext.secretRotationAgeDays(secretCreated(rotated), CLIENT_CREATED, NOW));
        assertEquals("0", ServiceAccountContext.secretRotationAgeDays(secretCreated(NOW.minusSeconds(60)), CLIENT_CREATED, NOW));
    }

    @Test
    void nothingIsGuessedWhenATimeIsUnknown() {
        assertNull(ServiceAccountContext.secretRotationAgeDays(Map.of(), CLIENT_CREATED, NOW), "no secret time");
        assertNull(ServiceAccountContext.secretRotationAgeDays(secretCreated(NOW), null, NOW), "no client creation time");
        assertNull(ServiceAccountContext.secretRotationAgeDays(null, CLIENT_CREATED, NOW));
        assertNull(ServiceAccountContext.secretRotationAgeDays(Map.of(ServiceAccountContext.ATTR_SECRET_CREATED, "yesterday"), CLIENT_CREATED, NOW));
    }

    @Test
    void theKeyHasTheNameOfTheCatalogueFeature() {
        assertFalse(ServiceAccountContext.KEYS.contains(ServiceAccountContext.KEY_SECRET_ROTATION_AGE_DAYS), "added by the callers, forwarded by the mapper");
        assertEquals("service_account.secret_rotation_age_days", ServiceAccountContext.KEY_SECRET_ROTATION_AGE_DAYS);
    }

    @Test
    void anAdministratorDeletingAUserIsAUserDeletedChange() {
        assertEquals(AdminChange.USER_DELETED, AdminChange.kindOf("USER", OperationType.DELETE, "users/7f3c"));
    }

    @Test
    void otherUserOperationsAreNotADeletion() {
        assertNull(AdminChange.kindOf("USER", OperationType.UPDATE, "users/7f3c"));
        assertNull(AdminChange.kindOf("USER", OperationType.DELETE, "users/7f3c/credentials/abc"), "a credential is not the person");
        assertNull(AdminChange.kindOf("USER", OperationType.DELETE, "users/7f3c/sessions"));
    }
}

package tech.humifortis.keycloak.caep;

import com.google.gson.JsonObject;

import java.time.Instant;
import java.util.Set;

public record CaepParsedSet(
        String jti,
        String issuer,
        Set<String> audience,
        Instant issuedAt,
        Instant expiresAt,
        String subject,
        String sessionId,
        JsonObject events
) {
}

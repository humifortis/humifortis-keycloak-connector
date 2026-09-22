package tech.humifortis.keycloak.caep;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class CaepSetValidator {
    private final CaepJwksFetcher jwksFetcher;
    private final Clock clock;

    public CaepSetValidator(CaepJwksFetcher jwksFetcher, Clock clock) {
        this.jwksFetcher = jwksFetcher;
        this.clock = clock;
    }

    public CaepParsedSet validate(String token, CaepConfig config) {
        if (token == null || token.isBlank()) {
            throw new CaepValidationException(400, "Missing SET");
        }
        if (config.issuer().isBlank() || config.audience().isBlank() || config.jwksUri().isBlank()) {
            throw new CaepValidationException(401, "CAEP receiver not configured");
        }

        String[] parts = token.trim().split("\\.");
        if (parts.length != 3) throw new CaepValidationException(400, "Malformed JWT");
        String signingInput = parts[0] + "." + parts[1];
        JsonObject header = parseJson(decodeBase64Url(parts[0]), "JWT header");
        JsonObject payload = parseJson(decodeBase64Url(parts[1]), "JWT payload");
        byte[] signatureBytes = decodeBase64UrlBytes(parts[2], "JWT signature");

        String alg = getRequiredString(header, "alg", 401);
        String kid = getOptionalString(header, "kid");

        verifySignature(signingInput.getBytes(StandardCharsets.UTF_8), signatureBytes, alg, kid, config.jwksUri());
        return validateClaims(payload, config);
    }

    private CaepParsedSet validateClaims(JsonObject payload, CaepConfig config) {
        String iss = getRequiredString(payload, "iss", 401);
        if (!Objects.equals(config.issuer(), iss)) {
            throw new CaepValidationException(401, "Untrusted issuer");
        }

        Set<String> aud = readAudience(payload.get("aud"));
        if (!aud.contains(config.audience())) {
            throw new CaepValidationException(401, "Invalid audience");
        }

        String jti = getRequiredString(payload, "jti", 400);
        long iatEpoch = getRequiredLong(payload, "iat", 400);
        Instant iat = Instant.ofEpochSecond(iatEpoch);
        Instant exp = payload.has("exp") ? Instant.ofEpochSecond(getRequiredLong(payload, "exp", 400)) : null;
        Instant now = clock.instant();
        int skew = Math.max(config.clockSkewSeconds(), 0);

        if (iat.isAfter(now.plusSeconds(skew))) {
            throw new CaepValidationException(400, "Token iat in future");
        }
        if (exp != null && exp.isBefore(now.minusSeconds(skew))) {
            throw new CaepValidationException(400, "Token expired");
        }

        if (!payload.has("events") || !payload.get("events").isJsonObject()) {
            throw new CaepValidationException(400, "Missing events claim");
        }

        JsonObject events = payload.getAsJsonObject("events");
        if (events.entrySet().isEmpty()) {
            throw new CaepValidationException(400, "Empty events claim");
        }

        return new CaepParsedSet(
                jti,
                iss,
                aud,
                iat,
                exp,
                getOptionalString(payload, "sub"),
                getOptionalString(payload, "sid"),
                events
        );
    }

    private void verifySignature(byte[] signingInput, byte[] signature, String alg, String kid, String jwksUri) {
        String signatureAlg = toJavaSignatureAlg(alg);
        JsonArray keys = jwksFetcher.fetchKeys(jwksUri);
        PublicKey key = selectKey(keys, kid);
        try {
            Signature verifier = Signature.getInstance(signatureAlg);
            verifier.initVerify(key);
            verifier.update(signingInput);
            if (!verifier.verify(signature)) {
                throw new CaepValidationException(401, "Invalid signature");
            }
        } catch (CaepValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new CaepValidationException(401, "Unable to verify signature");
        }
    }

    private PublicKey selectKey(JsonArray keys, String kid) {
        PublicKey fallback = null;
        for (JsonElement keyElem : keys) {
            if (!keyElem.isJsonObject()) continue;
            JsonObject jwk = keyElem.getAsJsonObject();
            String jwkKid = getOptionalString(jwk, "kid");
            if (kid != null && !kid.isBlank() && !kid.equals(jwkKid)) continue;
            PublicKey key = parseRsaKey(jwk);
            if (kid != null && !kid.isBlank()) return key;
            if (fallback == null) fallback = key;
        }
        if (fallback != null) return fallback;
        throw new CaepValidationException(401, "No matching key");
    }

    private PublicKey parseRsaKey(JsonObject jwk) {
        String kty = getRequiredString(jwk, "kty", 401);
        if (!"RSA".equals(kty)) {
            throw new CaepValidationException(401, "Unsupported key type");
        }
        String n = getRequiredString(jwk, "n", 401);
        String e = getRequiredString(jwk, "e", 401);
        try {
            BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(n));
            BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(e));
            RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
            RSAPublicKey key = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
            return key;
        } catch (Exception ex) {
            throw new CaepValidationException(401, "Invalid JWKS key");
        }
    }

    private String toJavaSignatureAlg(String jwtAlg) {
        return switch (jwtAlg) {
            case "RS256" -> "SHA256withRSA";
            case "RS384" -> "SHA384withRSA";
            case "RS512" -> "SHA512withRSA";
            default -> throw new CaepValidationException(401, "Unsupported JWT alg");
        };
    }

    private Set<String> readAudience(JsonElement audElem) {
        Set<String> aud = new HashSet<>();
        if (audElem == null) {
            throw new CaepValidationException(401, "Missing audience");
        }
        if (audElem.isJsonPrimitive()) {
            aud.add(audElem.getAsString());
            return aud;
        }
        if (audElem.isJsonArray()) {
            for (JsonElement e : audElem.getAsJsonArray()) {
                aud.add(e.getAsString());
            }
            return aud;
        }
        throw new CaepValidationException(401, "Invalid audience claim");
    }

    private JsonObject parseJson(String content, String label) {
        try {
            return JsonParser.parseString(content).getAsJsonObject();
        } catch (Exception e) {
            throw new CaepValidationException(400, "Malformed " + label);
        }
    }

    private String decodeBase64Url(String value) {
        return new String(decodeBase64UrlBytes(value, "JWT segment"), StandardCharsets.UTF_8);
    }

    private byte[] decodeBase64UrlBytes(String value, String label) {
        try {
            return Base64.getUrlDecoder().decode(value);
        } catch (Exception e) {
            throw new CaepValidationException(400, "Malformed " + label);
        }
    }

    private String getRequiredString(JsonObject json, String field, int status) {
        String value = getOptionalString(json, field);
        if (value == null || value.isBlank()) {
            throw new CaepValidationException(status, "Missing claim: " + field);
        }
        return value;
    }

    private String getOptionalString(JsonObject json, String field) {
        JsonElement e = json.get(field);
        return (e == null || e.isJsonNull()) ? null : e.getAsString();
    }

    private long getRequiredLong(JsonObject json, String field, int status) {
        JsonElement e = json.get(field);
        if (e == null || e.isJsonNull()) throw new CaepValidationException(status, "Missing claim: " + field);
        try {
            return e.getAsLong();
        } catch (Exception ex) {
            throw new CaepValidationException(status, "Invalid claim: " + field);
        }
    }
}

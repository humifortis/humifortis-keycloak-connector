package tech.humifortis.keycloak.caep;

import org.keycloak.models.RealmModel;

public record CaepConfig(
        boolean enabled,
        String issuer,
        String audience,
        String jwksUri,
        int clockSkewSeconds,
        boolean replayEnabled,
        int replayTtlSeconds,
        boolean supportSessionRevoked,
        boolean supportAssuranceLevelChange,
        boolean enforceSessionRevoked,
        boolean enforceStepUp,
        boolean enforceStepUpAsReauth
) {
    public static final String PREFIX = "hf.caep.";

    public static CaepConfig fromRealm(RealmModel realm) {
        return new CaepConfig(
                getBool(realm, "enabled", false),
                getString(realm, "issuer", ""),
                getString(realm, "audience", ""),
                getString(realm, "jwksUri", ""),
                getInt(realm, "clockSkewSeconds", 60),
                getBool(realm, "replay.enabled", true),
                getInt(realm, "replay.ttlSeconds", 600),
                getBool(realm, "supported.sessionRevoked", true),
                getBool(realm, "supported.assuranceLevelChange", true),
                getBool(realm, "enforce.sessionRevoked", true),
                getBool(realm, "enforce.stepUp", true),
                getBool(realm, "enforce.stepUpAsReauth", false)
        );
    }

    private static String getString(RealmModel realm, String key, String defaultValue) {
        String realmValue = realm.getAttribute(PREFIX + key);
        if (realmValue != null && !realmValue.isBlank()) return realmValue.trim();
        String envValue = System.getenv(toEnv(PREFIX + key));
        if (envValue == null || envValue.isBlank()) {
            envValue = System.getenv(toSnakeEnv(PREFIX + key));
        }
        return (envValue == null || envValue.isBlank()) ? defaultValue : envValue.trim();
    }

    private static boolean getBool(RealmModel realm, String key, boolean defaultValue) {
        String value = getString(realm, key, Boolean.toString(defaultValue));
        return Boolean.parseBoolean(value);
    }

    private static int getInt(RealmModel realm, String key, int defaultValue) {
        String value = getString(realm, key, Integer.toString(defaultValue));
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ignored) {
            return defaultValue;
        }
    }

    private static String toEnv(String key) {
        return key.toUpperCase().replace('.', '_');
    }

    private static String toSnakeEnv(String key) {
        StringBuilder out = new StringBuilder();
        for (char c : key.toCharArray()) {
            if (c == '.') {
                out.append('_');
            } else if (Character.isUpperCase(c)) {
                out.append('_').append(c);
            } else {
                out.append(Character.toUpperCase(c));
            }
        }
        return out.toString();
    }
}

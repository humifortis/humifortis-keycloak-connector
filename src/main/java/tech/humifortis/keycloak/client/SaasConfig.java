package tech.humifortis.keycloak.client;

import java.util.Map;

public class SaasConfig {
    private final String apiUrl;
    private final String apiKey;
    private final int timeoutMs;
    private final boolean fallbackAllow;
    private final boolean insecureSsl;
    private final String insecureSslCertSha256;

    public SaasConfig() {
        this(System.getenv());
    }

    SaasConfig(Map<String, String> env) {
        this.apiUrl = getEnvOrDefault(env, "HUMIFORTIS_API_URL", "https://api.humifortis.educosmic.tech");
        this.apiKey = getEnvOrThrow(env, "HUMIFORTIS_API_KEY");
        this.timeoutMs = Integer.parseInt(getEnvOrDefault(env, "HUMIFORTIS_TIMEOUT_MS", "5000"));
        this.fallbackAllow = Boolean.parseBoolean(getEnvOrDefault(env, "HUMIFORTIS_FALLBACK_ALLOW", "true"));
        this.insecureSsl = HttpClientFactory.isInsecureSslEnabled(env.get("INSECURE_SSL"));
        this.insecureSslCertSha256 = emptyToNull(env.get("HUMIFORTIS_INSECURE_SSL_CERT_SHA256"));
    }

    private String getEnvOrDefault(Map<String, String> env, String key, String defaultValue) {
        String value = env.get(key);
        return value != null && !value.isEmpty() ? value : defaultValue;
    }

    private String getEnvOrThrow(Map<String, String> env, String key) {
        String value = env.get(key);
        if (value == null || value.isEmpty()) {
            throw new IllegalStateException("Required environment variable not set: " + key);
        }
        return value;
    }

    public String getApiUrl() {
        return apiUrl;
    }

    public String getApiKey() {
        return apiKey;
    }

    public int getTimeoutMs() {
        return timeoutMs;
    }

    public boolean isFallbackAllow() {
        return fallbackAllow;
    }

    public boolean isInsecureSsl() {
        return insecureSsl;
    }

    public String getInsecureSslCertSha256() {
        return insecureSslCertSha256;
    }

    private String emptyToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }
}

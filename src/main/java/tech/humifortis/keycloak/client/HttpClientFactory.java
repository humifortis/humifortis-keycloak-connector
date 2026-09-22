package tech.humifortis.keycloak.client;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.http.HttpClient;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;

public final class HttpClientFactory {

    private HttpClientFactory() {}

    public static HttpClient create(int timeoutMs, boolean insecureSsl) {
        try {
            HttpClient.Builder builder = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofMillis(timeoutMs));
            if (insecureSsl) {
                builder.sslContext(buildTrustAllSslContext());
            }
            return builder.build();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create HTTP client", e);
        }
    }

    public static boolean isInsecureSslEnabled(String value) {
        return "true".equalsIgnoreCase(value);
    }

    private static SSLContext buildTrustAllSslContext() throws Exception {
        TrustManager[] trustAll = new TrustManager[] {
                new X509TrustManager() {
                    @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    @Override public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                    @Override public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                }
        };
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAll, new SecureRandom());
        return sslContext;
    }
}

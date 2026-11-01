package tech.humifortis.keycloak.client;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.net.http.HttpClient;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.Locale;

public final class HttpClientFactory {

    private HttpClientFactory() {}

    public static HttpClient create(int timeoutMs, boolean insecureSsl, String pinnedLoopbackCertificateSha256) {
        try {
            HttpClient.Builder builder = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofMillis(timeoutMs));
            if (insecureSsl) {
                SSLParameters sslParameters = new SSLParameters();
                sslParameters.setEndpointIdentificationAlgorithm(null);
                builder.sslParameters(sslParameters);
                builder.sslContext(buildLoopbackDevelopmentSslContext(pinnedLoopbackCertificateSha256));
            }
            return builder.build();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create HTTP client", e);
        }
    }

    public static boolean isInsecureSslEnabled(String value) {
        return "true".equalsIgnoreCase(value);
    }

    private static SSLContext buildLoopbackDevelopmentSslContext(String pinnedLoopbackCertificateSha256) throws Exception {
        TrustManagerFactory trustManagerFactory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init((KeyStore) null);

        X509ExtendedTrustManager defaultTrustManager = Arrays.stream(trustManagerFactory.getTrustManagers())
                .filter(X509ExtendedTrustManager.class::isInstance)
                .map(X509ExtendedTrustManager.class::cast)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Default X509 trust manager not available"));

        X509ExtendedTrustManager loopbackTrustManager = new X509ExtendedTrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
                defaultTrustManager.checkClientTrusted(chain, authType, socket);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
                if (tryAcceptPinnedLoopbackCertificate(chain, socket != null && socket.getInetAddress() != null
                        && socket.getInetAddress().isLoopbackAddress(), pinnedLoopbackCertificateSha256)) return;
                defaultTrustManager.checkServerTrusted(chain, authType, socket);
            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
                defaultTrustManager.checkClientTrusted(chain, authType, engine);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
                if (tryAcceptPinnedLoopbackCertificate(chain, engine != null && isLoopbackHost(engine.getPeerHost()),
                        pinnedLoopbackCertificateSha256)) return;
                defaultTrustManager.checkServerTrusted(chain, authType, engine);
            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                defaultTrustManager.checkClientTrusted(chain, authType);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                defaultTrustManager.checkServerTrusted(chain, authType);
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return defaultTrustManager.getAcceptedIssuers();
            }
        };

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[] { loopbackTrustManager }, new SecureRandom());
        return sslContext;
    }

    private static boolean isLoopbackHost(String host) {
        if (host == null || host.isBlank()) return false;
        String normalized = host.toLowerCase(Locale.ROOT);
        return "localhost".equals(normalized)
                || "127.0.0.1".equals(normalized)
                || "::1".equals(normalized)
                || "[::1]".equals(normalized);
    }

    private static boolean tryAcceptPinnedLoopbackCertificate(X509Certificate[] chain,
                                                              boolean isLoopbackHost,
                                                              String pinnedLoopbackCertificateSha256) {
        if (!isLoopbackHost || pinnedLoopbackCertificateSha256 == null || chain == null || chain.length == 0) {
            return false;
        }
        return sha256(chain[0]).equalsIgnoreCase(pinnedLoopbackCertificateSha256);
    }

    private static String sha256(X509Certificate certificate) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte value : digest) {
                hex.append(String.format("%02x", value));
            }
            return hex.toString();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to fingerprint certificate", e);
        }
    }
}

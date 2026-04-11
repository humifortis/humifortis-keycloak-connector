package tech.humifortis.keycloak.client;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.jboss.logging.Logger;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

import tech.humifortis.keycloak.model.HumifortisEvent;
import tech.humifortis.keycloak.model.RiskDecision;

public class SaasClient {
    private static final Logger logger = Logger.getLogger(SaasClient.class);
    private static final String CONNECTOR_VERSION = "1.0.0";

    private final String apiUrl;
    private final String apiKey;
    private final HttpClient httpClient;
    private final Gson gson;
    private final int timeoutMs;

    public SaasClient(SaasConfig config) {
        this.apiUrl    = config.getApiUrl();
        this.apiKey    = config.getApiKey();
        this.timeoutMs = config.getTimeoutMs();
        this.gson = new GsonBuilder()
                .setDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
                .create();

        try {
            TrustManager[] trustAll = new TrustManager[]{
                new X509TrustManager() {
                    @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    @Override public void checkClientTrusted(X509Certificate[] c, String a) {}
                    @Override public void checkServerTrusted(X509Certificate[] c, String a) {}
                }
            };
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAll, new SecureRandom());
            this.httpClient = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofMillis(timeoutMs))
                    .sslContext(sslContext)
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create SSL context", e);
        }
    }

    /**
     * Single send method for ALL event types.
     * Every caller (user events, admin events, feedback events)
     * builds a HumifortisEvent and calls this.
     */
    public CompletableFuture<Void> sendEventAsync(HumifortisEvent event) {
        return CompletableFuture.runAsync(() -> {
            try {
                JsonObject payload = new JsonObject();
                payload.add("event", gson.toJsonTree(event));

                String requestUrl  = apiUrl + "/events";
                String payloadJson = payload.toString();

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(requestUrl))
                        .header("Content-Type",       "application/json")
                        .header("X-API-Key",           apiKey)
                        .header("X-Connector-Type",    "keycloak")
                        .header("X-Connector-Version", CONNECTOR_VERSION)
                        .POST(HttpRequest.BodyPublishers.ofString(payloadJson))
                        .timeout(Duration.ofMillis(timeoutMs))
                        .build();

                logger.debugf("Sending event: type=%s url=%s",
                        event.getEventType(), requestUrl);

                HttpResponse<String> response = httpClient.send(
                        request, HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() >= 200 && response.statusCode() < 300) {
                    logger.debugf("Event sent: %s", event.getEventType());
                } else {
                    logger.warnf("Event send failed: status=%d body=%s",
                            response.statusCode(), response.body());
                }
            } catch (Exception e) {
                logger.errorf("Exception sending event: %s", e.getMessage());
                throw new CompletionException("Failed to send event", e);
            }
        });
    }

    public RiskDecision getRiskDecision(String entityId) throws SaasException {
        try {
            String encoded = URLEncoder.encode(entityId, StandardCharsets.UTF_8);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(apiUrl + "/risk/" + encoded))
                    .header("X-API-Key", apiKey)
                    .timeout(Duration.ofMillis(timeoutMs))
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(
                    request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                return gson.fromJson(response.body(), RiskDecision.class);
            } else if (response.statusCode() == 404) {
                logger.debugf("Entity not found, defaulting allow: %s", entityId);
                return RiskDecision.allow();
            } else {
                throw new SaasException(
                        "API error: " + response.statusCode() + " - " + response.body());
            }
        } catch (SaasException e) {
            throw e;
        } catch (Exception e) {
            throw new SaasException("Failed to get risk decision", e);
        }
    }

    public CompletableFuture<Void> sendBlockEventAsync(String entityId, RiskDecision decision) {
        HumifortisEvent blockEvent = new HumifortisEvent();
        blockEvent.setEntityId(entityId);
        blockEvent.setEntityType("user");
        blockEvent.setEventType("auth_login_blocked");
        blockEvent.setSource("keycloak");
        blockEvent.setTimestamp(java.time.Instant.now().toString());
        blockEvent.addMetadata("reason", decision.getReason());
        if (decision.getRiskScore() != null) {
            blockEvent.addMetadata("risk_score", decision.getRiskScore());
        }
        
        return sendEventAsync(blockEvent);
    }
}
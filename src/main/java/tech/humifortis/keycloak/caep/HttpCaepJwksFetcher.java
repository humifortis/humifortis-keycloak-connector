package tech.humifortis.keycloak.caep;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class HttpCaepJwksFetcher implements CaepJwksFetcher {
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    @Override
    public JsonArray fetchKeys(String jwksUri) {
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(jwksUri))
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() < 200 || response.statusCode() > 299) {
                throw new CaepValidationException(401, "Unable to fetch JWKS");
            }
            JsonObject json = JsonParser.parseString(response.body()).getAsJsonObject();
            if (!json.has("keys") || !json.get("keys").isJsonArray()) {
                throw new CaepValidationException(401, "Invalid JWKS structure");
            }
            return json.getAsJsonArray("keys");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new CaepValidationException(401, "Unable to retrieve JWKS");
        } catch (IllegalArgumentException | IOException e) {
            throw new CaepValidationException(401, "Unable to retrieve JWKS");
        }
    }
}

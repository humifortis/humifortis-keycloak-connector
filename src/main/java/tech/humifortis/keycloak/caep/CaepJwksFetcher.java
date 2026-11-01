package tech.humifortis.keycloak.caep;

import com.google.gson.JsonArray;

public interface CaepJwksFetcher {
    JsonArray fetchKeys(String jwksUri);
}

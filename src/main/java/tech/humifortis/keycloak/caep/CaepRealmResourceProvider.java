package tech.humifortis.keycloak.caep;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class CaepRealmResourceProvider implements RealmResourceProvider {
    private final KeycloakSession session;

    public CaepRealmResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return new CaepReceiverResource(session);
    }

    @Override
    public void close() {
    }
}

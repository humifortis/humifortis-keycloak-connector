package tech.humifortis.keycloak.client;

import tech.humifortis.keycloak.model.HumifortisEvent;

/**
 * Sends Keycloak events to Humifortis. Delivery is asynchronous and resilient (see
 * {@link EventQueue}): the caller — a login, an admin action — never waits for the API.
 */
public class SaasClient {
    private final EventQueue queue;

    public SaasClient(SaasConfig config) {
        if (!config.hasApiKey()) {
            throw new IllegalStateException("Required environment variable not set: HUMIFORTIS_API_KEY");
        }
        this.queue = EventQueue.shared(config);
    }

    /** Queues the event for delivery; returns immediately. */
    public void send(HumifortisEvent event) {
        queue.submit(event);
    }
}

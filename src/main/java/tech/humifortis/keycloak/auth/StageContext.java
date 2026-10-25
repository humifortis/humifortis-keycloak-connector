package tech.humifortis.keycloak.auth;

import java.util.Map;

/**
 * What a stage that is not a browser sign-in (a refresh, a reused session) tells Humifortis about the touch it evaluates
 * (docs/sso-and-external-idp-e2e.spec.md, P19, P23).
 *
 * @param extra            facts of the touch added to the evaluation metadata (the refresh token's idle time, the client type, the
 *                         epoch the artefact was issued in...); blank values are dropped
 * @param personNetwork    whether the address and the browser of the request are the person's. A confidential client refreshes from
 *                         its own server: sending that address would judge the application's network as the person's, so the
 *                         network context is left out and the rules that read it are not evaluated
 * @param currentSessionId the session the touch belongs to: it is not one of the person's OTHER live sessions
 */
public record StageContext(Map<String, String> extra, boolean personNetwork, String currentSessionId) {

    /** The keys that describe the request's own network and browser: not the person's when {@code personNetwork} is false. */
    static final String[] NETWORK_KEYS = {
            "ip", "user_agent", "geo_country", "geo_country_source", "rtt_ms", "rtt_source", "rtt_browser_ms"
    };
}

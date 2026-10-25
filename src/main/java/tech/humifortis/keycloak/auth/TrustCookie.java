package tech.humifortis.keycloak.auth;

/**
 * Where the browser trust cookie lives. The cookie must be sent back on every request of the realm, as the browser
 * addresses it: behind a reverse proxy that serves Keycloak under a prefix (Keycloak's frontend URL, for example
 * {@code https://sso.example.com/auth}), the realm is at {@code /auth/realms/<realm>}, and a cookie scoped to
 * {@code /realms/<realm>} is never returned by the browser.
 */
final class TrustCookie {

    private TrustCookie() {
    }

    /** The cookie path of a realm for a frontend base path ("/", "/auth", "/auth/" or null for none). */
    static String path(String frontendBasePath, String realm) {
        String base = frontendBasePath == null ? "" : frontendBasePath.trim();
        while (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        if (!base.isEmpty() && !base.startsWith("/")) {
            base = "/" + base;
        }
        return base + "/realms/" + realm;
    }
}

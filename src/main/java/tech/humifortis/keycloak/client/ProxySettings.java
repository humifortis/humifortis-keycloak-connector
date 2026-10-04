package tech.humifortis.keycloak.client;

import java.util.Locale;
import java.util.Map;
import java.util.function.Function;

import org.jboss.logging.Logger;

/**
 * How this Keycloak resolves the client IP — reported with every event so Humifortis can tell
 * an IP it may trust from one a client chose.
 *
 * <p>The connector never reads X-Forwarded-For itself: the IP is what Keycloak resolved
 * ({@code connection.getRemoteAddr()}). That is only trustworthy when Keycloak believes proxy
 * headers from its proxies alone ({@code proxy-trusted-addresses}).</p>
 */
public record ProxySettings(String headersMode, Boolean trustedAddressesSet) {
    private static final Logger logger = Logger.getLogger(ProxySettings.class);

    private static volatile ProxySettings current;

    /** Read once: Keycloak's configuration does not change while it runs. */
    public static ProxySettings current() {
        ProxySettings p = current;
        if (p == null) {
            synchronized (ProxySettings.class) {
                if (current == null) {
                    current = resolve(ProxySettings::keycloakConfigValue, System.getenv());
                    current.warnIfUnsafe();
                }
                p = current;
            }
        }
        return p;
    }

    /**
     * Resolves from Keycloak's configuration (keycloak.conf, env and system properties, via
     * MicroProfile Config when present), else from the KC_* environment variables.
     */
    static ProxySettings resolve(Function<String, String> kcConfig, Map<String, String> env) {
        String mode = firstNonBlank(kcConfig.apply("kc.proxy-headers"), env.get("KC_PROXY_HEADERS"));
        String trusted = firstNonBlank(kcConfig.apply("kc.proxy-trusted-addresses"), env.get("KC_PROXY_TRUSTED_ADDRESSES"));
        String normalized = mode == null ? "none" : mode.trim().toLowerCase(Locale.ROOT);
        return new ProxySettings(normalized, trusted != null);
    }

    /** True when any client can choose its IP: proxy headers believed from every peer. */
    public boolean isUnsafe() {
        return !"none".equals(headersMode) && Boolean.FALSE.equals(trustedAddressesSet);
    }

    private void warnIfUnsafe() {
        if (isUnsafe()) {
            logger.warnf("[Humifortis] proxy-headers=%s without proxy-trusted-addresses: the client IP is taken from "
                    + "headers sent by ANY peer, so a client can choose the IP it is evaluated with. Set "
                    + "proxy-trusted-addresses to your reverse proxy's address(es).", headersMode);
        }
    }

    /** The connector metadata keys: ip_source, proxy_headers_mode, proxy_trusted_addresses_set. */
    public void writeTo(java.util.function.BiConsumer<String, String> put) {
        put.accept("ip_source", "keycloak_connection");
        put.accept("proxy_headers_mode", headersMode);
        if (trustedAddressesSet != null) put.accept("proxy_trusted_addresses_set", String.valueOf(trustedAddressesSet));
    }

    private static String keycloakConfigValue(String name) {
        try {
            Class<?> provider = Class.forName("org.eclipse.microprofile.config.ConfigProvider");
            Object config = provider.getMethod("getConfig").invoke(null);
            Object value = config.getClass().getMethod("getOptionalValue", String.class, Class.class)
                    .invoke(config, name, String.class);
            if (value instanceof java.util.Optional<?> o && o.isPresent()) return String.valueOf(o.get());
        } catch (ReflectiveOperationException | LinkageError | RuntimeException ignored) {
            // not running inside Keycloak's Quarkus distribution: the environment decides
        }
        String prop = System.getProperty(name);
        return prop != null && !prop.isBlank() ? prop : null;
    }

    private static String firstNonBlank(String a, String b) {
        if (a != null && !a.isBlank()) return a;
        return b != null && !b.isBlank() ? b : null;
    }
}

package tech.humifortis.keycloak.client;

import jakarta.ws.rs.core.HttpHeaders;

/**
 * The round trip time between the client and Keycloak, from the best source there is.
 *
 * <ol>
 *   <li><b>The edge</b> ({@code edge}): the reverse proxy in front of Keycloak writes the TCP round trip of the
 *       client's connection into {@code X-Edge-RTT-Ms} and overwrites whatever the client sent under that name.
 *       Factual, but only where such a proxy exists and is the client's peer.</li>
 *   <li><b>The browser</b> ({@code browser}): the device collector times a few tiny requests to this Keycloak and
 *       submits the shortest. It works with no proxy at all, but the client reports it (it can only make it longer, never
 *       shorter) and it includes HTTP overhead.</li>
 * </ol>
 *
 * <p>Sent as {@code rtt_ms} with {@code rtt_source}; the browser's own value also travels as {@code rtt_browser_ms}
 * whenever there is one, because the two together say more than either: a browser far slower than the edge's own
 * connection means a hop sits between them. Nothing is configured here. Neither source: nothing is sent and nothing is
 * evaluated.</p>
 */
public final class EdgeRtt {

    public static final String HEADER = "X-Edge-RTT-Ms";
    public static final String METADATA_KEY = "rtt_ms";
    public static final String SOURCE_KEY = "rtt_source";
    /** What the browser measured, sent whenever it measured one — even when the edge's value is the one in rtt_ms. */
    public static final String BROWSER_KEY = "rtt_browser_ms";
    public static final String EDGE = "edge";
    public static final String BROWSER = "browser";

    /** A round trip above a minute is not a measurement. */
    private static final int MAX_MS = 60_000;

    private EdgeRtt() {}

    /** A round trip and who measured it. */
    public record Measure(int ms, String source) {}

    /** What the edge measured, or {@code null} when absent or not a plausible number. */
    public static Integer fromHeaders(HttpHeaders headers) {
        return headers == null ? null : parse(headers.getHeaderString(HEADER));
    }

    /** The edge's measurement when there is one, else the browser's ({@code browserValue}), else {@code null}. */
    public static Measure resolve(HttpHeaders headers, String browserValue) {
        Integer edge = fromHeaders(headers);
        if (edge != null) return new Measure(edge, EDGE);
        Integer browser = parse(browserValue);
        return browser != null ? new Measure(browser, BROWSER) : null;
    }

    /** The browser's measurement as the collector submitted it, or {@code null} when absent or not plausible. */
    public static Integer browser(String raw) {
        return parse(raw);
    }

    static Integer parse(String raw) {
        if (raw == null || raw.isBlank()) return null;
        try {
            int ms = Integer.parseInt(raw.trim());
            return ms >= 0 && ms <= MAX_MS ? ms : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }
}

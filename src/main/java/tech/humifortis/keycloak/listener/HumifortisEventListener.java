package tech.humifortis.keycloak.listener;

import java.io.File;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.model.AsnResponse;
import com.maxmind.geoip2.model.CityResponse;

import tech.humifortis.keycloak.client.SaasClient;
import tech.humifortis.keycloak.client.SaasConfig;
import tech.humifortis.keycloak.mapper.EventMapper;
import tech.humifortis.keycloak.model.HumifortisEvent;
import ua_parser.Client;
import ua_parser.Parser;

public class HumifortisEventListener implements EventListenerProvider {

    private static final Logger logger =
            Logger.getLogger(HumifortisEventListener.class);

    // Must match HumifortisRiskAuthenticator constants exactly.
    private static final String DETAIL_RISK_ACTION  = "HUMIFORTIS_RISK_ACTION";
    private static final String DETAIL_RISK_SCORE   = "HUMIFORTIS_RISK_SCORE";
    private static final String DETAIL_RISK_LEVEL   = "HUMIFORTIS_RISK_LEVEL";
    private static final String DETAIL_RISK_REASON  = "HUMIFORTIS_RISK_REASON";
    private static final String DETAIL_RISK_BLOCKED = "HUMIFORTIS_RISK_BLOCKED";

    // Sentinel that identifies our risk-decision event among all CUSTOM_REQUIRED_ACTION_ERROR events.
    private static final String RISK_EVENT_ERROR = "humifortis_risk_decision";

    private static final Set<EventType> MONITORED_EVENTS = Set.of(
            EventType.LOGIN,
            EventType.LOGIN_ERROR,
            EventType.LOGOUT,
            EventType.REGISTER,
            EventType.UPDATE_PASSWORD,
            EventType.UPDATE_EMAIL,
            EventType.RESET_PASSWORD,
            EventType.RESET_PASSWORD_ERROR,
            EventType.CODE_TO_TOKEN_ERROR,
            EventType.REFRESH_TOKEN_ERROR,
            EventType.REMOVE_TOTP,
            EventType.UPDATE_TOTP,
            EventType.IMPERSONATE,
            EventType.GRANT_CONSENT,
            EventType.REVOKE_GRANT,
            EventType.DELETE_ACCOUNT
    );

    // ── MaxMind GeoIP readers (static = loaded once per JVM) ──────────────────
    private static final String CITY_DB_PATH = System.getenv()
            .getOrDefault("GEOIP_CITY_DB", "/opt/geoip/GeoLite2-City.mmdb");
    private static final String ASN_DB_PATH  = System.getenv()
            .getOrDefault("GEOIP_ASN_DB",  "/opt/geoip/GeoLite2-ASN.mmdb");

    private static final DatabaseReader CITY_READER;
    private static final DatabaseReader ASN_READER;

    // ── ua-parser (static = loaded once, thread-safe) ─────────────────────────
    private static final Parser UA_PARSER;

    static {
        DatabaseReader cityDb = null;
        DatabaseReader asnDb  = null;
        try {
            cityDb = new DatabaseReader.Builder(new File(CITY_DB_PATH)).build();
            logger.infof("[HumifortisEventListener] GeoIP City DB loaded from %s", CITY_DB_PATH);
        } catch (Exception e) {
            logger.warnf("[HumifortisEventListener] GeoIP City DB not available at %s: %s",
                    CITY_DB_PATH, e.getMessage());
        }
        try {
            asnDb = new DatabaseReader.Builder(new File(ASN_DB_PATH)).build();
            logger.infof("[HumifortisEventListener] GeoIP ASN DB loaded from %s", ASN_DB_PATH);
        } catch (Exception e) {
            logger.warnf("[HumifortisEventListener] GeoIP ASN DB not available at %s: %s",
                    ASN_DB_PATH, e.getMessage());
        }
        CITY_READER = cityDb;
        ASN_READER  = asnDb;

        Parser uaParser = null;
        try {
            uaParser = new Parser();
            logger.info("[HumifortisEventListener] ua-parser initialized");
        } catch (Exception e) {
            logger.warnf("[HumifortisEventListener] ua-parser failed to initialize: %s",
                    e.getMessage());
        }
        UA_PARSER = uaParser;
    }

    private final SaasClient     saasClient;
    private final EventMapper    eventMapper;
    private final KeycloakSession session;

    public HumifortisEventListener(KeycloakSession session) {
        try {
            SaasConfig config = new SaasConfig();
            this.saasClient  = new SaasClient(config);
            this.eventMapper = new EventMapper();
            this.session     = session;
            logger.info("[HumifortisEventListener] Initialized");
        } catch (Exception e) {
            logger.error("[HumifortisEventListener] Failed to initialize", e);
            throw new RuntimeException("Failed to initialize Humifortis Event Listener", e);
        }
    }

    // ── Entry points ──────────────────────────────────────────────────────────

    @Override
    public void onEvent(Event event) {
        logger.debugf("[HumifortisEventListener] Received event: type=%s error=%s realm=%s user=%s",
                event.getType(), event.getError(), event.getRealmId(), event.getUserId());

        // Path A: risk decision feedback event (fired by authenticator)
        if (isRiskDecisionEvent(event)) {
            emitFeedback(event);
            return;
        }

        // Path B: standard security event
        if (MONITORED_EVENTS.contains(event.getType())) {
            try {
                enrichEvent(event);
                HumifortisEvent humiEvent = eventMapper.fromKeycloakEvent(event);
                sendAsync(humiEvent, event.getType().name());
            } catch (Exception e) {
                logger.errorf("[HumifortisEventListener] Error mapping/sending event %s: %s",
                        event.getType(), e.getMessage());
            }
        } else {
            logger.debugf("[HumifortisEventListener] Skipping unmonitored event: %s",
                    event.getType());
        }
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean includeRepresentation) {
        try {
            HumifortisEvent humiEvent = eventMapper.fromKeycloakAdminEvent(adminEvent);
            sendAsync(humiEvent, "admin:" + adminEvent.getOperationType());
        } catch (Exception e) {
            logger.errorf("[HumifortisEventListener] Error processing admin event: %s",
                    e.getMessage());
        }
    }

    @Override
    public void close() {}

    // ── Enrichment pipeline ───────────────────────────────────────────────────

    /**
     * Enriches event details in order:
     *   1. User-Agent
     *   2. Remote IP
     *   3. GeoIP (country, city, ASN) — depends on IP
     *   4. device_id               — depends on UA + GeoIP results
     *
     * Each step is isolated: failure in one step never blocks the others
     * and never blocks the login flow.
     */
    private void enrichEvent(Event event) {
        if (event.getDetails() == null) return;

        // Step 1 — User-Agent
        try {
            org.keycloak.models.KeycloakContext ctx = session.getContext();
            String ua = ctx.getRequestHeaders().getHeaderString("User-Agent");
            if (ua != null && !ua.isBlank()) {
                event.getDetails().put("user_agent", ua);
            }
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] UA enrichment failed: %s", e.getMessage());
        }

        // Step 2 — Remote IP
        try {
            org.keycloak.models.KeycloakContext ctx = session.getContext();
            String remoteIp = ctx.getConnection().getRemoteAddr();
            if (remoteIp != null && !remoteIp.isBlank()) {
                event.getDetails().put("remote_ip", remoteIp);
            }
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] Remote IP enrichment failed: %s", e.getMessage());
        }

        // Step 3 — GeoIP (must run before device_id)
        try {
            String ip = event.getIpAddress();
            if (ip != null && !ip.isBlank()) {
                Map<String, String> geo = enrichGeo(ip);
                geo.forEach((k, v) -> event.getDetails().put(k, v));
            }
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] GeoIP enrichment failed: %s", e.getMessage());
        }

        // Step 4 — device_id (always computed here, never taken from form or external source)
        try {
            String deviceId = computeDeviceId(event.getDetails());
            if (deviceId != null) {
                event.getDetails().put("device_id", deviceId);
                logger.debugf("[HumifortisEventListener] device_id computed: %s",
                        deviceId.substring(0, Math.min(8, deviceId.length())) + "...");
            }
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] device_id computation failed: %s", e.getMessage());
        }
    }

    // ── device_id computation ─────────────────────────────────────────────────

    /**
     * Computes a stable, deterministic device_id from signals that are:
     *   - available server-side (no browser JS required)
     *   - stable across sessions for the same physical device
     *   - different enough to distinguish Chrome/Mac from Firefox/Mac from Chrome/Linux
     *
     * Stable components (change only when the actual device/setup changes):
     *   osFamily        — "Mac OS X", "Windows", "Linux", "Android", "iOS"
     *   osMajor         — "14", "10" — major OS version only (not minor/patch)
     *   browserFamily   — "Chrome", "Firefox", "Safari", "Edge"
     *   deviceFamily    — "Other" (desktop), "iPhone", "iPad", Samsung model, etc.
     *   geo_country     — ISO country code from MaxMind (changes on VPN/travel → intentional)
     *   asn             — Autonomous System Number (changes on VPN/ISP change → intentional)
     *
     * NOT included (too volatile):
     *   browserMajor    — changes every ~4 weeks on Chrome auto-update
     *   ip_address      — changes on every DHCP renewal or mobile network switch
     *   city            — too granular, changes on short trips
     *
     * Output: SHA-256 of the joined components, first 16 hex chars (64-bit space).
     * Collision probability is negligible for realistic user populations.
     */
    private String computeDeviceId(Map<String, String> details) {
        if (details == null) return null;

        String ua      = details.getOrDefault("user_agent", "");
        String country = details.getOrDefault("geo_country", "");
        String asn     = details.getOrDefault("asn", "");

        // Parse UA with ua-parser for accurate, structured extraction.
        // Falls back to empty strings if UA is absent or unparseable —
        // device_id will still be computed from country+asn.
        String osFamily     = "";
        String osMajor      = "";
        String browserFamily = "";
        String deviceFamily  = "";

        if (UA_PARSER != null && !ua.isBlank()) {
            try {
                Client client = UA_PARSER.parse(ua);

                osFamily     = nvl(client.os.family);
                osMajor      = nvl(client.os.major);      // major only — stable across minor updates
                browserFamily = nvl(client.userAgent.family);
                // device.family is "Other" for desktops, model string for mobile devices
                deviceFamily  = nvl(client.device.family);

                logger.debugf(
                    "[HumifortisEventListener] UA parsed — os=%s %s browser=%s device=%s country=%s asn=%s",
                    osFamily, osMajor, browserFamily, deviceFamily, country, asn);
            } catch (Exception e) {
                logger.debugf("[HumifortisEventListener] ua-parser failed for UA '%s': %s",
                        ua.length() > 60 ? ua.substring(0, 60) + "…" : ua, e.getMessage());
            }
        } else if (ua.isBlank()) {
            logger.debugf("[HumifortisEventListener] UA absent — device_id will use country+asn only");
        } else {
            logger.debugf("[HumifortisEventListener] ua-parser not available — device_id will use country+asn only");
        }

        // Concatenate stable components with a separator that cannot appear in any field value.
        // Order is fixed — changing it would invalidate all existing device_ids.
        String raw = String.join("\u0000",
                osFamily,
                osMajor,
                browserFamily,
                deviceFamily,
                country,
                asn);

        // Debug: emit the exact concatenated input used for hashing.
        // For readability replace the NUL separator with '|' so the string is visible in logs.
        try {
            String visibleRaw = raw.replace("\u0000", "|");
            logger.infof("[HumifortisEventListener] device_id raw components: %s", visibleRaw);
        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] failed to log device_id raw: %s", e.getMessage());
        }

        // SHA-256 → first 16 hex chars (8 bytes = 64-bit identifier space)
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(raw.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(16);
            for (int i = 0; i < 8; i++) {
                sb.append(String.format("%02x", hash[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            logger.warnf("[HumifortisEventListener] SHA-256 unavailable: %s", e.getMessage());
            return null;
        }
    }

    /** Null-safe trim; returns empty string for null input. */
    private static String nvl(String s) {
        return s == null ? "" : s.trim();
    }

    // ── GeoIP enrichment ──────────────────────────────────────────────────────

    /**
     * Looks up the given IP in the MaxMind City and ASN databases.
     * Returns a map of field name → value ready to be put into event details.
     * Always returns a map (possibly empty). Never throws.
     *
     * NOTE: Private IPs (RFC-1918, loopback) are substituted with 8.8.8.8
     * in dev/test environments so GeoIP lookups succeed locally. Remove
     * the substitution block before going to production.
     */
    private Map<String, String> enrichGeo(String ipStr) {
        Map<String, String> result = new HashMap<>();

        // TEMPORARY dev substitution — remove before production
        String lookupIp = ipStr;
        if (ipStr.startsWith("192.168.") || ipStr.startsWith("10.")
                || ipStr.startsWith("172.") || ipStr.equals("127.0.0.1")
                || ipStr.equals("::1")) {
            lookupIp = "8.8.8.8";
            logger.debugf("[HumifortisEventListener] Private IP %s → using test IP %s for GeoIP",
                    ipStr, lookupIp);
        }

        try {
            InetAddress addr = InetAddress.getByName(lookupIp);

            if (CITY_READER != null) {
                try {
                    CityResponse city = CITY_READER.city(addr);
                    if (city.getCountry().getIsoCode() != null)
                        result.put("geo_country", city.getCountry().getIsoCode());
                    if (city.getCity().getName() != null)
                        result.put("geo_city", city.getCity().getName());
                    if (city.getLocation().getLatitude() != null)
                        result.put("geo_lat", String.valueOf(city.getLocation().getLatitude()));
                    if (city.getLocation().getLongitude() != null)
                        result.put("geo_lon", String.valueOf(city.getLocation().getLongitude()));
                    logger.debugf("[HumifortisEventListener] City lookup %s → country=%s city=%s",
                            ipStr, city.getCountry().getIsoCode(), city.getCity().getName());
                } catch (Exception e) {
                    logger.debugf("[HumifortisEventListener] City lookup failed for %s: %s",
                            ipStr, e.getMessage());
                }
            }

            if (ASN_READER != null) {
                try {
                    AsnResponse asnResp = ASN_READER.asn(addr);
                    if (asnResp.getAutonomousSystemNumber() != null)
                        result.put("asn", String.valueOf(asnResp.getAutonomousSystemNumber()));
                    if (asnResp.getAutonomousSystemOrganization() != null)
                        result.put("asn_org", asnResp.getAutonomousSystemOrganization());
                    logger.debugf("[HumifortisEventListener] ASN lookup %s → asn=%s org=%s",
                            ipStr, asnResp.getAutonomousSystemNumber(),
                            asnResp.getAutonomousSystemOrganization());
                } catch (Exception e) {
                    logger.debugf("[HumifortisEventListener] ASN lookup failed for %s: %s",
                            ipStr, e.getMessage());
                }
            }

        } catch (Exception e) {
            logger.debugf("[HumifortisEventListener] GeoIP enrichment failed for %s: %s",
                    ipStr, e.getMessage());
        }

        logger.debugf("[HumifortisEventListener] GeoIP completed for %s — %d fields: %s",
                ipStr, result.size(), result.keySet());
        return result;
    }

    // ── Feedback path ─────────────────────────────────────────────────────────

    private boolean isRiskDecisionEvent(Event event) {
        return event.getType() == EventType.CUSTOM_REQUIRED_ACTION_ERROR
                && RISK_EVENT_ERROR.equals(event.getError());
    }

    private void emitFeedback(Event event) {
        try {
            String riskAction = detail(event, DETAIL_RISK_ACTION);
            String riskScore  = detail(event, DETAIL_RISK_SCORE);
            String riskLevel  = detail(event, DETAIL_RISK_LEVEL);
            String riskReason = detail(event, DETAIL_RISK_REASON);
            String blocked    = detail(event, DETAIL_RISK_BLOCKED);

            if (riskAction == null) {
                logger.warnf("[HumifortisEventListener] Risk decision event missing " +
                        "HUMIFORTIS_RISK_ACTION detail — skipping feedback.");
                return;
            }

            String feedbackType = resolveFeedbackType(riskAction, blocked);

            logger.infof("[HumifortisEventListener] Emitting feedback: " +
                            "feedbackType=%s action=%s score=%s level=%s blocked=%s",
                    feedbackType, riskAction, riskScore, riskLevel, blocked);

            HumifortisEvent feedback = eventMapper.fromFeedback(
                    event, feedbackType,
                    riskScore, riskLevel, riskAction, riskReason);
            sendAsync(feedback, feedbackType);

        } catch (Exception e) {
            logger.warnf("[HumifortisEventListener] Error emitting feedback event: %s",
                    e.getMessage());
        }
    }

    private String resolveFeedbackType(String riskAction, String blocked) {
        if ("ALLOW".equalsIgnoreCase(riskAction))    return "auth_decision_allow";
        if ("true".equalsIgnoreCase(blocked))        return "auth_decision_block";
        return "auth_decision_evaluated";
    }

    // ── Shared helpers ────────────────────────────────────────────────────────

    private void sendAsync(HumifortisEvent event, String label) {
        saasClient.sendEventAsync(event)
                .exceptionally(ex -> {
                    logger.warnf("[HumifortisEventListener] Failed to send [%s]: %s",
                            label, ex.getMessage());
                    return null;
                });
    }

    private String detail(Event event, String key) {
        if (event.getDetails() == null) return null;
        String v = event.getDetails().get(key);
        return (v != null && !v.isBlank()) ? v : null;
    }
}
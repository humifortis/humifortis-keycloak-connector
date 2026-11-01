package tech.humifortis.keycloak.serviceaccount;

import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

import org.keycloak.events.EventType;

/**
 * What humifortis-core needs to evaluate a Keycloak <em>service account</em> (a client using the
 * {@code client_credentials} grant): the expectations the operator declared on the client, compared
 * with what this login actually did.
 *
 * <p>The expectations are ordinary Keycloak client attributes, so they are managed where the client
 * is managed (Admin console, REST, realm import):
 *
 * <pre>
 * humifortis.source_allowlist                  comma-separated IPs or CIDRs the client may call from
 * humifortis.baseline_scopes                   the scopes the client is known to use (space or comma separated)
 * humifortis.expected_window_start_hour_utc    first UTC hour of the client's normal activity (0-23)
 * humifortis.expected_window_end_hour_utc      last UTC hour of the client's normal activity (0-23); may wrap midnight
 * humifortis.rotation_max_age_days             the rotation policy of the client secret
 * humifortis.owner                             who owns the client (a team or an email; free text, shown to analysts)
 * client.secret.creation.time                  set by Keycloak itself when the secret is created or rotated
 * </pre>
 *
 * <p>A value that is not declared, or not valid, is not sent: the detector then reports the input as
 * unavailable instead of judging against a guess.
 *
 * <p>The returned keys are the feature names of humifortis-core ({@code configs/features.yaml}).
 */
public final class ServiceAccountContext {

    public static final String ATTR_SOURCE_ALLOWLIST = "humifortis.source_allowlist";
    public static final String ATTR_BASELINE_SCOPES = "humifortis.baseline_scopes";
    public static final String ATTR_WINDOW_START_HOUR = "humifortis.expected_window_start_hour_utc";
    public static final String ATTR_WINDOW_END_HOUR = "humifortis.expected_window_end_hour_utc";
    public static final String ATTR_ROTATION_MAX_AGE_DAYS = "humifortis.rotation_max_age_days";
    public static final String ATTR_OWNER = "humifortis.owner";
    /** The audiences the client is known to exchange its token for (space or comma separated); see {@link #resolveExchange}. */
    public static final String ATTR_BASELINE_AUDIENCES = "humifortis.baseline_audiences";
    /** An audience travels as a scope with this prefix, so the one scope-escalation judgement covers both (MA-2). */
    public static final String AUDIENCE_PREFIX = "aud:";
    /** Keycloak's own attribute: epoch seconds of the creation (or last rotation) of the client secret. */
    public static final String ATTR_SECRET_CREATED = "client.secret.creation.time";

    public static final String KEY_SOURCE_ALLOWLIST_MATCH = "service_account.source_allowlist_match";
    public static final String KEY_REQUESTED_SCOPES = "service_account.requested_scopes";
    public static final String KEY_HISTORICAL_SCOPES = "service_account.historical_scopes";
    public static final String KEY_WINDOW_START_HOUR = "service_account.expected_window_start_hour_utc";
    public static final String KEY_WINDOW_END_HOUR = "service_account.expected_window_end_hour_utc";
    public static final String KEY_CREDENTIAL_AGE_DAYS = "service_account.credential_age_days";
    public static final String KEY_ROTATION_MAX_AGE_DAYS = "service_account.rotation_max_age_days";
    public static final String KEY_OWNER = "service_account.owner";
    /** Days since the secret was rotated (regenerated after the client was created); absent when it never was. Not part of KEYS: it needs the service-account user, so the callers add it. */
    public static final String KEY_SECRET_ROTATION_AGE_DAYS = "service_account.secret_rotation_age_days";
    /** A secret created less than this long after the client is the secret the client was created with, not a rotation. */
    static final long ROTATION_MARGIN_SECONDS = 30;
    static final int MAX_OWNER_CHARS = 255;

    /** Every key {@link #resolve} may produce: the ones the event mapper forwards. */
    public static final Set<String> KEYS = Set.of(
            KEY_SOURCE_ALLOWLIST_MATCH, KEY_REQUESTED_SCOPES, KEY_HISTORICAL_SCOPES,
            KEY_WINDOW_START_HOUR, KEY_WINDOW_END_HOUR, KEY_CREDENTIAL_AGE_DAYS, KEY_ROTATION_MAX_AGE_DAYS,
            KEY_OWNER);

    private static final Pattern IPV4 = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");
    private static final Pattern IPV6 = Pattern.compile("^[0-9a-fA-F:.]+$");
    private static final Pattern SPLIT = Pattern.compile("[,\\s]+");

    private ServiceAccountContext() {}

    /** The Keycloak events of a client authenticating with its own credentials (the service account). */
    public static boolean isClientCredentialsEvent(EventType type) {
        return type == EventType.CLIENT_LOGIN || type == EventType.CLIENT_LOGIN_ERROR;
    }

    /**
     * @param clientAttributes the client's attributes (may be null: the client is unknown)
     * @param sourceIp         the address Keycloak resolved for the caller
     * @param grantedScope     the {@code scope} detail of the event (space separated), null on a failure
     * @param now              the time of the event
     */
    public static Map<String, String> resolve(Map<String, String> clientAttributes, String sourceIp,
                                              String grantedScope, Instant now) {
        Map<String, String> out = new LinkedHashMap<>();
        Map<String, String> attrs = clientAttributes != null ? clientAttributes : Map.of();

        String requested = joinScopes(grantedScope);
        if (requested != null) out.put(KEY_REQUESTED_SCOPES, requested);

        String baseline = joinScopes(attrs.get(ATTR_BASELINE_SCOPES));
        if (baseline != null) out.put(KEY_HISTORICAL_SCOPES, baseline);

        Boolean match = matchesAllowlist(sourceIp, attrs.get(ATTR_SOURCE_ALLOWLIST));
        if (match != null) out.put(KEY_SOURCE_ALLOWLIST_MATCH, match.toString());

        Integer start = hour(attrs.get(ATTR_WINDOW_START_HOUR));
        Integer end = hour(attrs.get(ATTR_WINDOW_END_HOUR));
        if (start != null && end != null) {
            out.put(KEY_WINDOW_START_HOUR, start.toString());
            out.put(KEY_WINDOW_END_HOUR, end.toString());
        }

        Integer maxAge = positiveInt(attrs.get(ATTR_ROTATION_MAX_AGE_DAYS));
        Long ageDays = credentialAgeDays(attrs.get(ATTR_SECRET_CREATED), now);
        if (maxAge != null && ageDays != null) {
            out.put(KEY_ROTATION_MAX_AGE_DAYS, maxAge.toString());
            out.put(KEY_CREDENTIAL_AGE_DAYS, ageDays.toString());
        }

        String owner = attrs.get(ATTR_OWNER);
        if (owner != null && !owner.isBlank()) {
            String trimmed = owner.trim();
            out.put(KEY_OWNER, trimmed.length() > MAX_OWNER_CHARS ? trimmed.substring(0, MAX_OWNER_CHARS) : trimmed);
        }
        return out;
    }

    /**
     * Days since the secret was rotated: the secret of a client is rotated when it was created more than an hour after the
     * client itself (Keycloak creates the service-account user with the client, so its creation time is the client's).
     * Null when the secret never was rotated, or when either time is unknown: nothing is guessed.
     *
     * @param clientAttributes      the client's attributes
     * @param clientCreatedMillis   when the client was created (its service-account user's creation time), or null
     */
    public static String secretRotationAgeDays(Map<String, String> clientAttributes, Long clientCreatedMillis, Instant now) {
        if (clientAttributes == null || clientCreatedMillis == null || now == null) return null;
        String raw = clientAttributes.get(ATTR_SECRET_CREATED);
        if (raw == null || raw.isBlank()) return null;
        try {
            Instant secretCreated = Instant.ofEpochSecond(Long.parseLong(raw.trim()));
            Instant clientCreated = Instant.ofEpochMilli(clientCreatedMillis);
            if (Duration.between(clientCreated, secretCreated).getSeconds() < ROTATION_MARGIN_SECONDS) return null;
            return Long.toString(Math.max(0L, Duration.between(secretCreated, now).toDays()));
        } catch (NumberFormatException | java.time.DateTimeException e) {
            return null;
        }
    }

    /**
     * The context of a token EXCHANGE by a service account (MA-2): the same expectations as a token request, and the audience
     * the token is exchanged for judged like a scope. The audience is an {@code aud:<name>} entry of the requested scopes; the
     * audiences the operator declared ({@code humifortis.baseline_audiences}) are entries of the baseline. Scopes are judged
     * only when a scope baseline is declared, audiences only when an audience baseline is: a baseline never declared is not
     * guessed (the detector then reports the input as unavailable).
     *
     * @param requestedScopes the {@code scope} of the exchange (space separated), may be null
     * @param audiences       the {@code audience} of the exchange (space or comma separated), may be null
     */
    public static Map<String, String> resolveExchange(Map<String, String> clientAttributes, String sourceIp,
                                                      String requestedScopes, String audiences, Instant now) {
        Map<String, String> out = resolve(clientAttributes, sourceIp, null, now);
        out.remove(KEY_REQUESTED_SCOPES);
        out.remove(KEY_HISTORICAL_SCOPES);
        Map<String, String> attrs = clientAttributes != null ? clientAttributes : Map.of();
        Set<String> requested = new TreeSet<>();
        Set<String> baseline = new TreeSet<>();
        String baselineScopes = joinScopes(attrs.get(ATTR_BASELINE_SCOPES));
        if (baselineScopes != null) {
            baseline.addAll(java.util.Arrays.asList(baselineScopes.split(",")));
            String asked = joinScopes(requestedScopes);
            if (asked != null) requested.addAll(java.util.Arrays.asList(asked.split(",")));
        }
        String baselineAudiences = joinScopes(attrs.get(ATTR_BASELINE_AUDIENCES));
        if (baselineAudiences != null) {
            for (String a : baselineAudiences.split(",")) baseline.add(AUDIENCE_PREFIX + a);
            String asked = joinScopes(audiences);
            if (asked != null) for (String a : asked.split(",")) requested.add(AUDIENCE_PREFIX + a);
        }
        if (!baseline.isEmpty() && !requested.isEmpty()) {
            out.put(KEY_REQUESTED_SCOPES, String.join(",", requested));
            out.put(KEY_HISTORICAL_SCOPES, String.join(",", baseline));
        }
        return out;
    }

    /** Scopes as the comma-separated list humifortis-core reads; null when there is none. */
    static String joinScopes(String raw) {
        if (raw == null || raw.isBlank()) return null;
        Set<String> scopes = new TreeSet<>();
        for (String s : SPLIT.split(raw.trim())) {
            if (!s.isBlank()) scopes.add(s);
        }
        return scopes.isEmpty() ? null : String.join(",", scopes);
    }

    /**
     * Whether {@code ip} is covered by the allowlist; null when no judgement is possible (no
     * allowlist declared, no valid entry in it, or no usable source address).
     */
    static Boolean matchesAllowlist(String ip, String allowlist) {
        if (allowlist == null || allowlist.isBlank() || ip == null || ip.isBlank()) return null;
        byte[] address = literalAddress(ip.trim());
        if (address == null) return null;
        boolean anyValid = false;
        for (String entry : SPLIT.split(allowlist.trim())) {
            if (entry.isBlank()) continue;
            String[] parts = entry.split("/", 2);
            byte[] network = literalAddress(parts[0]);
            if (network == null) continue;
            int bits = network.length * 8;
            if (parts.length == 2) {
                try {
                    bits = Integer.parseInt(parts[1]);
                } catch (NumberFormatException e) {
                    continue;
                }
                if (bits < 0 || bits > network.length * 8) continue;
            }
            anyValid = true;
            if (network.length == address.length && samePrefix(address, network, bits)) return true;
        }
        return anyValid ? Boolean.FALSE : null;
    }

    private static boolean samePrefix(byte[] a, byte[] b, int bits) {
        int full = bits / 8;
        for (int i = 0; i < full; i++) {
            if (a[i] != b[i]) return false;
        }
        int rest = bits % 8;
        if (rest == 0) return true;
        int mask = (0xFF << (8 - rest)) & 0xFF;
        return (a[full] & mask) == (b[full] & mask);
    }

    /** The bytes of a literal IPv4/IPv6 address; null for anything else (a name is never resolved). */
    private static byte[] literalAddress(String s) {
        boolean literal = IPV4.matcher(s).matches() || (s.contains(":") && IPV6.matcher(s).matches());
        if (!literal) return null;
        try {
            return InetAddress.getByName(s).getAddress();
        } catch (Exception e) {
            return null;
        }
    }

    private static Integer hour(String raw) {
        Integer v = parseInt(raw);
        return v != null && v >= 0 && v <= 23 ? v : null;
    }

    private static Integer positiveInt(String raw) {
        Integer v = parseInt(raw);
        return v != null && v > 0 ? v : null;
    }

    private static Integer parseInt(String raw) {
        if (raw == null || raw.isBlank()) return null;
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static Long credentialAgeDays(String createdEpochSeconds, Instant now) {
        if (createdEpochSeconds == null || createdEpochSeconds.isBlank() || now == null) return null;
        try {
            Instant created = Instant.ofEpochSecond(Long.parseLong(createdEpochSeconds.trim()));
            return Math.max(0L, Duration.between(created, now).toDays());
        } catch (NumberFormatException | java.time.DateTimeException e) {
            return null;
        }
    }
}

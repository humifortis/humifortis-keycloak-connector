package tech.humifortis.keycloak.user;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.keycloak.models.ClientModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.RoleUtils;

/**
 * Collects what Keycloak knows about a user — once per request (cached on the session).
 *
 * <h3>Realm attributes (optional, Realm settings → Attributes)</h3>
 * <ul>
 *   <li>{@code hf.privileged.roles} — extra privileged roles, comma-separated
 *       ({@code finance-admin} for a realm role, {@code my-app:admin} for a client role)</li>
 *   <li>{@code hf.privileged.groups} — privileged group paths; members of subgroups count too</li>
 *   <li>{@code hf.account.createdAttributes} — user attributes holding the creation time of
 *       federated accounts (default {@code createTimestamp,whenCreated}: LDAP / Active Directory)</li>
 * </ul>
 */
public class UserContextExtractor {

    /** Administrative roles: realm roles, or roles of Keycloak's own admin clients. */
    private static final Set<String> PRIVILEGED_ROLES = Set.of(
            "admin", "realm-admin", "manage-users", "manage-realm",
            "manage-clients", "manage-identity-providers", "impersonation",
            "create-realm", "manage-authorization"
    );

    static final String ATTR_PRIVILEGED_ROLES = "hf.privileged.roles";
    static final String ATTR_PRIVILEGED_GROUPS = "hf.privileged.groups";
    static final String ATTR_CREATED_ATTRIBUTES = "hf.account.createdAttributes";
    static final String DEFAULT_CREATED_ATTRIBUTES = "createTimestamp,whenCreated";

    static final int MAX_ITEMS = 100;
    static final int MAX_ITEM_CHARS = 255;
    static final int MAX_JOINED_CHARS = 4096;

    private static final String SESSION_CACHE_PREFIX = "hf.user.ctx:";

    public UserContextSnapshot extract(KeycloakSession session, RealmModel realm, UserModel user) {
        String cacheKey = SESSION_CACHE_PREFIX + realm.getId() + ":" + user.getId();
        try {
            Object cached = session.getAttribute(cacheKey);
            if (cached instanceof UserContextSnapshot s) return s;
        } catch (RuntimeException ignored) {
            // a session without attributes (tests): no cache
        }
        UserContextSnapshot snapshot = build(session, realm, user, Instant.now());
        try {
            session.setAttribute(cacheKey, snapshot);
        } catch (RuntimeException ignored) {
            // no cache
        }
        return snapshot;
    }

    UserContextSnapshot build(KeycloakSession session, RealmModel realm, UserModel user, Instant now) {
        List<String> mfaMethods = extractMfaMethods(user);
        List<String> allRoles = extractRoleNames(user);
        List<String> allGroups = extractGroupPaths(user);
        Bounded roles = bound(allRoles);
        Bounded groups = bound(allGroups);
        String privilegedReason = privilegedReason(realm, allRoles, allGroups);
        Instant[] createdAt = new Instant[1];
        String createdSource = extractAccountCreation(realm, user, now, createdAt);
        Long ageDays = createdAt[0] != null ? ChronoUnit.DAYS.between(createdAt[0], now) : null;
        long activeSessionCount = session.sessions().getUserSessionsStream(realm, user).count();
        return new UserContextSnapshot(
                user.getUsername(),
                user.getEmail(),
                user.isEmailVerified(),
                mfaMethods,
                roles.values(), roles.truncated(),
                groups.values(), groups.truncated(),
                !mfaMethods.isEmpty(),
                privilegedReason != null,
                privilegedReason,
                createdAt[0], createdSource,
                ageDays,
                activeSessionCount
        );
    }

    public List<String> extractMfaMethods(UserModel user) {
        return user.credentialManager().getStoredCredentialsStream()
                .map(cred -> switch (cred.getType()) {
                    case "otp" -> "TOTP";
                    case "webauthn" -> "WEBAUTHN";
                    case "webauthn-passwordless" -> "WEBAUTHN_PASSWORDLESS";
                    default -> null;
                })
                .filter(java.util.Objects::nonNull)
                .toList();
    }

    public boolean hasMfaEnrolled(UserModel user) {
        return !extractMfaMethods(user).isEmpty();
    }

    public boolean hasPrivilegedRole(UserModel user) {
        return extractRoleNames(user).stream().anyMatch(UserContextExtractor::isBuiltInPrivileged);
    }

    /**
     * The user's EFFECTIVE roles: direct mappings, roles of every group (and its parents), with
     * composite roles expanded. Client roles are {@code clientId:role}, so an application role
     * named "admin" is never mistaken for the realm's administrator role.
     */
    public List<String> extractRoleNames(UserModel user) {
        Set<String> names = new TreeSet<>();
        for (RoleModel role : RoleUtils.getDeepUserRoleMappings(user)) {
            String name = roleName(role);
            if (name != null) names.add(name);
        }
        return new ArrayList<>(names);
    }

    static String roleName(RoleModel role) {
        if (role == null || role.getName() == null) return null;
        if (role.isClientRole() && role.getContainer() instanceof ClientModel client) {
            return client.getClientId() + ":" + role.getName();
        }
        return role.getName();
    }

    /** Group paths, e.g. {@code /finance/admins}. */
    public List<String> extractGroupPaths(UserModel user) {
        Set<String> paths = new TreeSet<>();
        user.getGroupsStream().forEach(g -> {
            String p = groupPath(g);
            if (p != null) paths.add(p);
        });
        return new ArrayList<>(paths);
    }

    static String groupPath(GroupModel group) {
        StringBuilder sb = new StringBuilder();
        int depth = 0;
        for (GroupModel g = group; g != null && depth < 32; g = g.getParent(), depth++) {
            if (g.getName() == null) return null;
            sb.insert(0, "/" + g.getName());
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    /** {@code role:<name>} / {@code group:<path>} for the first privilege found, else null. */
    static String privilegedReason(RealmModel realm, List<String> roles, List<String> groups) {
        Set<String> extraRoles = csv(realm.getAttribute(ATTR_PRIVILEGED_ROLES));
        for (String role : roles) {
            if (isBuiltInPrivileged(role) || extraRoles.contains(role)) return "role:" + role;
        }
        for (String privileged : csv(realm.getAttribute(ATTR_PRIVILEGED_GROUPS))) {
            String prefix = privileged.startsWith("/") ? privileged : "/" + privileged;
            for (String g : groups) {
                if (g.equals(prefix) || g.startsWith(prefix + "/")) return "group:" + g;
            }
        }
        return null;
    }

    /** Whether a role counts as privileged here: the built-in admin roles and the realm's extra privileged roles. */
    public static boolean isPrivilegedRole(RealmModel realm, RoleModel role) {
        String name = roleName(role);
        if (name == null) return false;
        return isBuiltInPrivileged(name) || csv(realm.getAttribute(ATTR_PRIVILEGED_ROLES)).contains(name);
    }

    /** A built-in admin role: a realm role, or a role of Keycloak's admin clients. */
    static boolean isBuiltInPrivileged(String role) {
        int colon = role.indexOf(':');
        if (colon < 0) return PRIVILEGED_ROLES.contains(role);
        String client = role.substring(0, colon);
        String name = role.substring(colon + 1);
        boolean adminClient = client.equals("realm-management") || client.endsWith("-realm");
        return adminClient && PRIVILEGED_ROLES.contains(name);
    }

    public Long extractAccountAgeDays(UserModel user) {
        Long ts = user.getCreatedTimestamp();
        if (ts == null || ts <= 0) return null;
        Instant created = Instant.ofEpochMilli(ts);
        Instant now = Instant.now();
        return created.isAfter(now) ? null : ChronoUnit.DAYS.between(created, now);
    }

    /**
     * Finds when the account was created: Keycloak's own timestamp, else (federated users) the
     * first configured user attribute that parses. Stores the instant in {@code out[0]} and
     * returns its source; a future time is discarded (clock skew, bad data).
     */
    static String extractAccountCreation(RealmModel realm, UserModel user, Instant now, Instant[] out) {
        Long ts = user.getCreatedTimestamp();
        if (ts != null && ts > 0) {
            Instant created = Instant.ofEpochMilli(ts);
            if (!created.isAfter(now)) {
                out[0] = created;
                return "keycloak";
            }
        }
        String configured = realm.getAttribute(ATTR_CREATED_ATTRIBUTES);
        for (String attr : csv(configured != null ? configured : DEFAULT_CREATED_ATTRIBUTES)) {
            Instant created = parseTimestamp(user.getFirstAttribute(attr));
            if (created != null && !created.isAfter(now)) {
                out[0] = created;
                return "attribute:" + attr;
            }
        }
        return null;
    }

    private static final Pattern GENERALIZED_TIME =
            Pattern.compile("^(\\d{14})(?:[.,]\\d+)?(Z|[+-]\\d{4})$");

    /** LDAP generalized time ({@code 20240115103000Z}, {@code 20240115103000.0Z}) or ISO-8601. */
    static Instant parseTimestamp(String raw) {
        if (raw == null || raw.isBlank()) return null;
        String v = raw.trim();
        Matcher m = GENERALIZED_TIME.matcher(v);
        if (m.matches()) {
            try {
                LocalDateTime local = LocalDateTime.parse(m.group(1), DateTimeFormatter.ofPattern("yyyyMMddHHmmss", Locale.ROOT));
                ZoneOffset offset = "Z".equals(m.group(2)) ? ZoneOffset.UTC : ZoneOffset.of(m.group(2).substring(0, 3) + ":" + m.group(2).substring(3));
                return local.toInstant(offset);
            } catch (RuntimeException e) {
                return null;
            }
        }
        try {
            return OffsetDateTime.parse(v).toInstant();
        } catch (DateTimeParseException e) {
            try {
                return Instant.parse(v);
            } catch (DateTimeParseException e2) {
                return null;
            }
        }
    }

    record Bounded(List<String> values, boolean truncated) {}

    /** At most 100 values of at most 255 chars, joined at most 4 KiB — a public connector bounds its payload. */
    static Bounded bound(List<String> sorted) {
        List<String> out = new ArrayList<>();
        int joined = 0;
        boolean truncated = false;
        for (String v : sorted) {
            if (v.length() > MAX_ITEM_CHARS) { truncated = true; continue; }
            int add = v.length() + (out.isEmpty() ? 0 : 1);
            if (out.size() >= MAX_ITEMS || joined + add > MAX_JOINED_CHARS) { truncated = true; break; }
            out.add(v);
            joined += add;
        }
        return new Bounded(List.copyOf(out), truncated);
    }

    private static Set<String> csv(String raw) {
        Set<String> out = new TreeSet<>();
        if (raw == null) return out;
        Arrays.stream(raw.split(",")).map(String::trim).filter(s -> !s.isEmpty()).forEach(out::add);
        return out;
    }
}

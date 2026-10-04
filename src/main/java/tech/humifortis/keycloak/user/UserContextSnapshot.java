package tech.humifortis.keycloak.user;

import java.time.Instant;
import java.util.List;

/**
 * What Keycloak knows about the user, collected once per request.
 *
 * @param roleNames            EFFECTIVE roles (direct, from groups, composites expanded); client
 *                             roles as {@code clientId:role}; sorted, bounded
 * @param groups               group paths ({@code /finance/admins}); sorted, bounded
 * @param privilegedReason     why the user counts as privileged ({@code role:<name>} or
 *                             {@code group:<path>}), null when not privileged
 * @param accountCreatedAt     account creation time, null when unknown
 * @param accountCreatedSource {@code keycloak} or {@code attribute:<name>} (federated users)
 */
public record UserContextSnapshot(
        String username,
        String email,
        boolean emailVerified,
        List<String> mfaMethods,
        List<String> roleNames,
        boolean rolesTruncated,
        List<String> groups,
        boolean groupsTruncated,
        boolean mfaEnrolled,
        boolean privileged,
        String privilegedReason,
        Instant accountCreatedAt,
        String accountCreatedSource,
        Long accountAgeDays,
        long activeSessionCount
) {
    /** The identity fields every Humifortis event carries, as connector metadata keys. */
    public void writeTo(java.util.function.BiConsumer<String, String> put) {
        put.accept("email_verified", String.valueOf(emailVerified));
        if (!mfaMethods.isEmpty()) put.accept("mfa_methods", String.join(",", mfaMethods));
        put.accept("mfa_enrolled", String.valueOf(mfaEnrolled));
        if (!roleNames.isEmpty()) put.accept("user_roles", String.join(",", roleNames));
        if (rolesTruncated) put.accept("user_roles_truncated", "true");
        if (!groups.isEmpty()) put.accept("user_groups", String.join(",", groups));
        if (groupsTruncated) put.accept("user_groups_truncated", "true");
        put.accept("is_privileged", String.valueOf(privileged));
        if (privilegedReason != null) put.accept("privileged_reason", privilegedReason);
        if (accountCreatedAt != null) {
            put.accept("account_created_at", accountCreatedAt.toString());
            put.accept("account_created_source", accountCreatedSource);
        }
        if (accountAgeDays != null) put.accept("account_age_days", String.valueOf(accountAgeDays));
        put.accept("active_session_count", String.valueOf(activeSessionCount));
    }
}

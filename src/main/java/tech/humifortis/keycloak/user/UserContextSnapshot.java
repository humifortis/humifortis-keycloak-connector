package tech.humifortis.keycloak.user;

import java.util.List;

public record UserContextSnapshot(
        String username,
        String email,
        boolean emailVerified,
        List<String> mfaMethods,
        List<String> roleNames,
        boolean mfaEnrolled,
        boolean privileged,
        Long accountAgeDays,
        long activeSessionCount
) {}

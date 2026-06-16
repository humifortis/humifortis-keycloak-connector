package tech.humifortis.keycloak.model;

import java.util.Optional;

/**
 * Risk assessment result returned by HumifortisRiskEvaluator.
 * Standalone — no dependency on keycloak-adaptive-authn framework.
 */
public class Risk {

    /**
     * Ordered risk scores (ordinal used for event telemetry).
     * Order: from most negative/safe to most extreme/dangerous.
     */
    public enum Score {
        NEGATIVE_HIGH,
        NEGATIVE_LOW,
        NONE,
        INVALID,
        VERY_SMALL,
        SMALL,
        MEDIUM,
        HIGH,
        VERY_HIGH,
        EXTREME
    }

    private final Score score;
    private final String reason;

    private Risk(Score score, String reason) {
        this.score = score;
        this.reason = reason;
    }

    public static Risk of(Score score, String reason) {
        return new Risk(score, reason);
    }

    public Score getScore() {
        return score;
    }

    public Optional<String> getReason() {
        return Optional.ofNullable(reason);
    }
}


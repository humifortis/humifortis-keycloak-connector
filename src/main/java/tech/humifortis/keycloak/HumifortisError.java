package tech.humifortis.keycloak;

/**
 * Catalogue des codes d'erreur Humifortis.
 *
 * Format : HF-XXXX
 *   1xxx = Offline / indisponibilité API
 *   2xxx = Décision de sécurité (playbook)
 *   3xxx = Mauvaise configuration terrain
 *   4xxx = Problème utilisateur (MFA, compte)
 *   5xxx = Erreur interne inattendue
 *
 * Chaque code est stable entre versions.
 * Documentation : https://docs.humifortis.com/errors/{code}
 */
public enum HumifortisError {

    // ── 1xxx — API Offline ────────────────────────────────────────────────
    SERVICE_TIMEOUT        ("HF-1001", "Service temporarily unavailable"),
    SERVICE_CIRCUIT_OPEN   ("HF-1002", "Service temporarily unavailable"),
    SERVICE_HTTP_ERROR     ("HF-1003", "Service temporarily unavailable"),
    SERVICE_AUTH_FAILURE   ("HF-1004", "Service configuration error"),
    SERVICE_PARSE_ERROR    ("HF-1005", "Service response invalid"),

    // ── 2xxx — Décisions playbook ─────────────────────────────────────────
    ACCESS_DENIED_RISK     ("HF-2001", "Access denied by security policy"),
    ACCOUNT_LOCKED         ("HF-2002", "Account locked — suspicious activity detected"),
    UNKNOWN_ACTION         ("HF-2003", "Access denied — unrecognized policy action"),

    // ── 3xxx — Configuration ──────────────────────────────────────────────
    MISCONFIGURED_URL      ("HF-3001", "Authentication misconfigured — contact administrator"),
    MISCONFIGURED_APIKEY   ("HF-3002", "Authentication misconfigured — contact administrator"),

    // ── 4xxx — Utilisateur ────────────────────────────────────────────────
    MFA_NO_METHOD          ("HF-4001", "No authentication method available"),
    MFA_EMAIL_UNVERIFIED   ("HF-4002", "Email verification required to proceed"),
    MFA_INVALID_CODE       ("HF-4003", "Invalid or expired authentication code"),
    MFA_CHALLENGE_FAILED   ("HF-4004", "Step-up authentication failed"),

    // ── 5xxx — Erreurs internes ───────────────────────────────────────────
    INTERNAL_ERROR         ("HF-5001", "Unexpected authentication error"),
    ROUTER_ERROR           ("HF-5002", "Unexpected authentication routing error");

    public final String code;
    public final String summary;

    HumifortisError(String code, String summary) {
        this.code    = code;
        this.summary = summary;
    }

    /**
     * Keycloak i18n message key — maps to hf.error.{name_lowercase} in messages_*.properties.
     * Example: ACCESS_DENIED_RISK → "hf.error.access_denied_risk"
     */
    public String messageKey() {
        return "hf.error." + name().toLowerCase();
    }

    /**
     * Keycloak i18n detail key — maps to hf.error.{name_lowercase}.detail.
     */
    public String messageDetailKey() {
        return messageKey() + ".detail";
    }

    /**
     * Message court pour l'utilisateur — jamais de détail technique.
     */
    public String userMessage() {
        return summary + "  (ref: " + code + ")";
    }

    /**
     * Message structuré pour les logs SOC.
     */
    public String logMessage(String technicalDetail) {
        return "[" + code + "] " + summary + " — " + technicalDetail;
    }
}


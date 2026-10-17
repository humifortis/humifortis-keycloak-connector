package tech.humifortis.keycloak.auth;

import com.google.gson.annotations.SerializedName;

import java.util.List;

/**
 * The evaluation context of a decision, as Humifortis returns it for {@code include=context}
 * (docs/risk-as-data.spec.md, section 6). Only the fields the connector reads are mapped: Gson ignores the rest, so a
 * server that adds a field never breaks a connector.
 */
public final class EvaluationContext {

    /** The major version this connector understands. A context of another major is treated as missing (D11). */
    public static final String SUPPORTED_MAJOR = "1";

    @SerializedName("context_version") public String contextVersion;
    @SerializedName("record_id")       public String recordId;
    public List<Attr>    attributes;
    public List<Signal>  signals;
    public Risk          risk;
    public Decision      decision;

    public static final class Attr {
        public String  name;
        public Object  value;
        public boolean unavailable;
        public boolean sensitive;
    }

    public static final class Signal {
        public String  rule;
        public boolean shadow;
    }

    public static final class Risk {
        public double score;
        public String level;
    }

    public static final class Decision {
        public String  action;
        @SerializedName("enforced_action") public String enforcedAction;
        @SerializedName("policy_source")   public String policySource;
        public String  rule;
        @SerializedName("would_action")    public String wouldAction;
        /** An explicit deny: the connector enforces it whatever the flow contains (D17). */
        public boolean mandatory;
        public List<Reason> reasons;
    }

    public static final class Reason {
        public String rule;
        public String title;
        public String rationale;
    }

    /**
     * Whether this context can be used. A missing context, an unknown major version or a context without a risk level or
     * a decision is not: the login then behaves as {@code server} source (D11) and a missing context never opens a door.
     */
    public static boolean usable(EvaluationContext c) {
        if (c == null || c.contextVersion == null || c.risk == null || c.decision == null) return false;
        if (c.risk.level == null || c.risk.level.isBlank()) return false;
        return c.contextVersion.equals(SUPPORTED_MAJOR) || c.contextVersion.startsWith(SUPPORTED_MAJOR + ".");
    }
}

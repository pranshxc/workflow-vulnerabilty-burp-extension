package com.workflowscanner.analysis;

/**
 * Outcome of the {@link ReportabilityGate#decide} call.
 *
 * <p>The gate is the final filter between LLM analysis + validation
 * and the production of Burp audit issues. Without it, the tool
 * was creating weak advisories from unvalidated LLM hypotheses,
 * unconfirmed validation results, and read-only session-only
 * candidate patterns. The gate is the single place where
 * "is this worth a Burp issue?" is decided.
 *
 * <p>Each outcome has two parts:
 * <ol>
 *   <li><b>shouldReport</b> — true for {@link #REPORT_CONFIRMED} and
 *       {@link #REPORT_NEEDS_REVIEW}, false for the SUPPRESS_* values.</li>
 *   <li><b>reason</b> — short human-readable explanation so the
 *       extension log can show why a finding was promoted or
 *       suppressed.</li>
 * </ol>
 *
 * <p>Precedence (highest first):
 * <ol>
 *   <li>REPORT_CONFIRMED — any strict (CONFIRMED) validation proof</li>
 *   <li>SUPPRESS_PUBLIC_RESOURCE — the candidate looks like a
 *       public resource (blockchain wallet / token price) where
 *       unauthenticated reads are not IDOR</li>
 *   <li>SUPPRESS_VALIDATION_FAILED — all validation tests failed
 *       (ERROR / NOT_CONFIRMED) and the user has not opted in to
 *       receiving failed-validation hypotheses</li>
 *   <li>SUPPRESS_LOW_SIGNAL — none of the above, and no probable
 *       validation, no explicit edges, no state-changing steps,
 *       no critical workflow type</li>
 *   <li>SUPPRESS_READ_ONLY_SESSION_ONLY — the candidate is
 *       session-only with all GET/HEAD steps and no probable
 *       validation (downgraded from SUPPRESS_LOW_SIGNAL when
 *       the user did not enable "analyze read-only candidates")</li>
 *   <li>REPORT_NEEDS_REVIEW — the rest: has probable validation
 *       OR has explicit edges OR has state-changing steps OR
 *       is a critical workflow type (AUTH, PAYMENT, etc.)</li>
 * </ol>
 *
 * <p>Note that {@link #SUPPRESS_READ_ONLY_SESSION_ONLY} is now an
 * alias of {@link #SUPPRESS_LOW_SIGNAL} for read-only session-only
 * patterns; the dedicated value is kept for clarity in the log
 * output and so the gate can distinguish them if the user opts in
 * to analyzing read-only candidates.
 */
public enum ReportabilityDecision {

    /** Strict (CONFIRMED) validation proof — Burp issue, full severity. */
    REPORT_CONFIRMED(true, "Strict validation proof (CONFIRMED)"),
    /** Has probable validation OR explicit edges OR state-changing steps OR critical workflow type. */
    REPORT_NEEDS_REVIEW(true, "Has probable validation / explicit edges / state-changing steps / critical workflow type"),
    /** Verdict confidence was zero (LLM did not commit to a finding). */
    SUPPRESS_ZERO_CONFIDENCE(false, "Verdict confidence is 0.0 — LLM did not commit to a finding"),
    /** LLM-only finding with no validation; user has not opted in via reportLLMOnlyFindings. */
    SUPPRESS_LLM_ONLY(false, "LLM-only finding with no validation; reportLLMOnlyFindings=false"),
    /** Unconfirmed finding; user has not opted in via reportUnconfirmedFindings. */
    SUPPRESS_UNCONFIRMED(false, "Unconfirmed finding; reportUnconfirmedFindings=false"),
    /** Public blockchain / token / price resource pattern with no auth-bound ownership proof. */
    SUPPRESS_PUBLIC_RESOURCE(false, "Public-resource pattern (blockchain wallet / token price) with no ownership proof"),
    /** Telemetry / feature-flag / collect / metrics / faro endpoint (infrastructure polling). */
    SUPPRESS_INFRASTRUCTURE_POLLING(false, "Telemetry / feature-flag / metrics endpoint (infrastructure polling)"),
    /** All validation tests failed or were skipped and user has not opted in to failed hypotheses. */
    SUPPRESS_VALIDATION_FAILED(false, "All validation tests failed / not confirmed"),
    /** Read-only GET sequence on a session-only candidate with no explicit edges. */
    SUPPRESS_READ_ONLY_SESSION_ONLY(false, "Read-only session-only candidate, no validation, no explicit edges"),
    /** General low-signal fallback (catches session-only, no explicit edges, no state-change, no critical type). */
    SUPPRESS_LOW_SIGNAL(false, "Low-signal: no validation, no explicit edges, no state-changing steps, unknown workflow type");

    private final boolean shouldReport;
    private final String defaultReason;

    ReportabilityDecision(boolean shouldReport, String defaultReason) {
        this.shouldReport = shouldReport;
        this.defaultReason = defaultReason;
    }

    public boolean shouldReport() {
        return shouldReport;
    }

    public String defaultReason() {
        return defaultReason;
    }

    public boolean isSuppressed() {
        return !shouldReport;
    }
}

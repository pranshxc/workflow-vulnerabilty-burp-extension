package com.workflowscanner.validation;

import java.util.ArrayList;
import java.util.List;

/**
 * Result of a vulnerability validation test.
 * Contains full evidence including original and test responses,
 * comparison metrics, and human-readable explanation.
 *
 * <p><b>Proof model (validation rework):</b>
 * The previous model collapsed validation outcomes into a single
 * {@code boolean confirmed} flag. That is too optimistic: response
 * similarity, success keywords, and 2xx status are not the same thing as
 * "the server actually accepted the attacker's mutation and changed
 * business state." This class now carries a tri-state
 * {@link ProofLevel} (CONFIRMED, PROBABLE, NOT_CONFIRMED, ERROR) and a
 * list of business-state observations ({@link StateCheck}).
 *
 * <ul>
 *   <li><b>CONFIRMED</b> — a concrete business effect was observed
 *       (new object id appeared, status moved to completed/approved,
 *       attacker-controlled value persisted, etc.).</li>
 *   <li><b>PROBABLE</b> — the test response is suspiciously similar to a
 *       success but no concrete business effect was observed; needs
 *       human review.</li>
 *   <li><b>NOT_CONFIRMED</b> — the server explicitly rejected the test
 *       request, or the response was structurally different.</li>
 *   <li><b>ERROR</b> — the test could not be executed (mutation failed,
 *       replay error, scope violation, etc.).</li>
 * </ul>
 *
 * The {@code confirmed} boolean is kept as a derived accessor for
 * backward compatibility; it returns true when {@code proofLevel} is
 * CONFIRMED or PROBABLE.
 */
public class ValidationResult {

    public enum Strategy {
        STEP_SKIP,
        VALUE_MANIPULATION,
        REPLAY,
        RACE_CONDITION,
        IDOR,
        STATE_EFFECT
    }

    public enum ProofLevel {
        /** Business effect observed: real evidence the server accepted the attack. */
        CONFIRMED,
        /** Response is similar to success but no business effect was proven. */
        PROBABLE,
        /** Server rejected the test, or response is clearly different. */
        NOT_CONFIRMED,
        /** Test could not be executed (mutation failed, replay error, etc.). */
        ERROR
    }

    private String testName;
    private Strategy strategy;
    private ProofLevel proofLevel = ProofLevel.NOT_CONFIRMED;
    private double confidence;          // 0.0 - 1.0
    private String evidence;            // Human-readable explanation
    private int originalStatusCode;
    private int testStatusCode;
    private String originalResponseSnippet;
    private String testResponseSnippet;
    private double responseSimilarity;  // 0.0 - 1.0
    private String diff;                // Key differences
    private boolean dryRun;             // True if this was a dry-run (not actually executed)
    private long durationMs;

    // Business-state observations collected during the test. Empty list
    // means no business effect was observed. The list is the source of
    // truth for "CONFIRMED" promotion: if any check here observed a
    // concrete effect, the proof level is upgraded to CONFIRMED.
    private final List<StateCheck> stateChecks = new ArrayList<>();

    public ValidationResult() {}

    public ValidationResult(String testName, Strategy strategy) {
        this.testName = testName;
        this.strategy = strategy;
    }

    /**
     * Build a formatted report string.
     */
    public String toReport() {
        StringBuilder sb = new StringBuilder();
        sb.append("Test: ").append(testName).append('\n');
        sb.append("Strategy: ").append(strategy).append('\n');
        sb.append("Status: ").append(formatProofLevel(proofLevel)).append('\n');
        sb.append("Confidence: ").append(String.format("%.2f", confidence)).append('\n');
        if (dryRun) {
            sb.append("[DRY RUN - not actually executed]\n");
        }
        if (!stateChecks.isEmpty()) {
            sb.append("Business effects observed:\n");
            for (StateCheck check : stateChecks) {
                sb.append("  - ").append(check.summarize()).append('\n');
            }
        }
        sb.append("Evidence:\n").append(evidence != null ? evidence : "N/A").append('\n');
        if (originalStatusCode > 0) {
            sb.append("Original response: ").append(originalStatusCode).append('\n');
            sb.append("Test response: ").append(testStatusCode).append('\n');
            sb.append("Similarity: ").append(String.format("%.0f%%", responseSimilarity * 100)).append('\n');
        }
        if (diff != null && !diff.isEmpty()) {
            sb.append("Differences: ").append(diff).append('\n');
        }
        return sb.toString();
    }

    private static String formatProofLevel(ProofLevel level) {
        if (level == null) return "UNKNOWN";
        switch (level) {
            case CONFIRMED:    return "CONFIRMED \u2713";
            case PROBABLE:     return "PROBABLE \u26A0";
            case NOT_CONFIRMED: return "NOT CONFIRMED \u2717";
            case ERROR:        return "ERROR \u26D4";
            default:           return level.name();
        }
    }

    /**
     * Backward-compatible boolean: true when the proof level is CONFIRMED
     * or PROBABLE. Code that previously treated "confirmed" as a single
     * signal still gets a meaningful value, but advisory creation should
     * prefer {@link #getProofLevel()} and require CONFIRMED for auto-creation.
     */
    public boolean isConfirmed() {
        return proofLevel == ProofLevel.CONFIRMED || proofLevel == ProofLevel.PROBABLE;
    }

    /**
     * Strict accessor: true only when the test produced a CONFIRMED proof.
     * Use this when the question is "should we auto-create a high-severity
     * Burp issue for this result?"
     */
    public boolean isConfirmedStrict() {
        return proofLevel == ProofLevel.CONFIRMED;
    }

    /**
     * Set the proof level. If the new level is CONFIRMED and existing
     * state checks include a concrete business effect, the level stays
     * CONFIRMED. Otherwise this overwrites the current level.
     */
    public void setProofLevel(ProofLevel level) {
        this.proofLevel = level != null ? level : ProofLevel.NOT_CONFIRMED;
    }

    /**
     * Add a business-state observation. Adding any check that observed a
     * concrete effect (see {@link StateCheck#isEffectObserved()}) upgrades
     * the proof level to CONFIRMED — the response-similarity heuristic
     * alone is not enough to call something a confirmed vulnerability.
     */
    public void addStateCheck(StateCheck check) {
        if (check == null) return;
        stateChecks.add(check);
        if (check.isEffectObserved() && proofLevel != ProofLevel.ERROR) {
            proofLevel = ProofLevel.CONFIRMED;
        }
    }

    public List<StateCheck> getStateChecks() {
        return stateChecks;
    }

    // --- Getters and Setters ---

    public String getTestName() { return testName; }
    public void setTestName(String testName) { this.testName = testName; }

    public Strategy getStrategy() { return strategy; }
    public void setStrategy(Strategy strategy) { this.strategy = strategy; }

    /**
     * Set the confirmed flag for backward compatibility. Maps to
     * {@code proofLevel = CONFIRMED} when true and {@code proofLevel =
     * NOT_CONFIRMED} when false. Prefer {@link #setProofLevel} for new code.
     */
    public void setConfirmed(boolean confirmed) {
        this.proofLevel = confirmed ? ProofLevel.CONFIRMED : ProofLevel.NOT_CONFIRMED;
    }

    public ProofLevel getProofLevel() { return proofLevel; }

    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = confidence; }

    public String getEvidence() { return evidence; }
    public void setEvidence(String evidence) { this.evidence = evidence; }

    public int getOriginalStatusCode() { return originalStatusCode; }
    public void setOriginalStatusCode(int code) { this.originalStatusCode = code; }

    public int getTestStatusCode() { return testStatusCode; }
    public void setTestStatusCode(int code) { this.testStatusCode = code; }

    public String getOriginalResponseSnippet() { return originalResponseSnippet; }
    public void setOriginalResponseSnippet(String s) { this.originalResponseSnippet = s; }

    public String getTestResponseSnippet() { return testResponseSnippet; }
    public void setTestResponseSnippet(String s) { this.testResponseSnippet = s; }

    public double getResponseSimilarity() { return responseSimilarity; }
    public void setResponseSimilarity(double s) { this.responseSimilarity = s; }

    public String getDiff() { return diff; }
    public void setDiff(String diff) { this.diff = diff; }

    public boolean isDryRun() { return dryRun; }
    public void setDryRun(boolean dryRun) { this.dryRun = dryRun; }

    public long getDurationMs() { return durationMs; }
    public void setDurationMs(long durationMs) { this.durationMs = durationMs; }

    @Override
    public String toString() {
        return String.format("[%s] %s: %s (%.2f)",
                strategy, testName,
                proofLevel == null ? "UNKNOWN" : proofLevel.name(),
                confidence);
    }
}

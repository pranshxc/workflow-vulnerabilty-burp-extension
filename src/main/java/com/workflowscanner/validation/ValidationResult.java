package com.workflowscanner.validation;

/**
 * Result of a vulnerability validation test.
 * Contains full evidence including original and test responses,
 * comparison metrics, and human-readable explanation.
 */
public class ValidationResult {

    public enum Strategy {
        STEP_SKIP,
        VALUE_MANIPULATION,
        REPLAY,
        RACE_CONDITION,
        IDOR
    }

    private String testName;
    private Strategy strategy;
    private boolean confirmed;          // True if vulnerability confirmed
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
        sb.append("Status: ").append(confirmed ? "CONFIRMED \u2713" : "NOT CONFIRMED \u2717").append('\n');
        sb.append("Confidence: ").append(String.format("%.2f", confidence)).append('\n');
        if (dryRun) {
            sb.append("[DRY RUN - not actually executed]\n");
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

    // --- Getters and Setters ---

    public String getTestName() { return testName; }
    public void setTestName(String testName) { this.testName = testName; }

    public Strategy getStrategy() { return strategy; }
    public void setStrategy(Strategy strategy) { this.strategy = strategy; }

    public boolean isConfirmed() { return confirmed; }
    public void setConfirmed(boolean confirmed) { this.confirmed = confirmed; }

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
                strategy, testName, confirmed ? "CONFIRMED" : "NOT CONFIRMED", confidence);
    }
}

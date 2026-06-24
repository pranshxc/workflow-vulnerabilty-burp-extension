package com.workflowscanner.validation;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Smart response comparison that understands what "success" vs "failure" looks like.
 * Compares HTTP responses across multiple dimensions.
 *
 * <p><b>Proof-level separation (validation rework):</b>
 * The old {@link #isVulnerabilityConfirmed} method collapsed every heuristic
 * into a single boolean. That treats "both responses are 200 and have the
 * same shape" as a confirmed finding, which produces many false positives
 * in practice (e.g. a price=0.01 mutation returns the same checkout page).
 * The new {@link #classifyProof} method returns a tri-state
 * {@link ValidationResult.ProofLevel}:
 *
 * <ul>
 *   <li>{@code NOT_CONFIRMED} — server rejected, response is clearly different,
 *       or the original was a 4xx/5xx (the test cannot have succeeded).</li>
 *   <li>{@code PROBABLE} — response is suspiciously similar to a success but
 *       no concrete business-state effect was observed. Needs human review.</li>
 *   <li>{@code CONFIRMED} is reserved for code that observed an actual
 *       business-state change; this comparator never returns CONFIRMED on
 *       similarity alone.</li>
 * </ul>
 */
public class ResponseComparator {

    private static final Set<String> SUCCESS_KEYWORDS = Set.of(
            "success", "confirmed", "approved", "completed", "accepted",
            "created", "updated", "ok", "done", "processed", "valid");

    private static final Set<String> FAILURE_KEYWORDS = Set.of(
            "error", "denied", "unauthorized", "forbidden", "invalid",
            "failed", "rejected", "expired", "not found", "not allowed");

    /**
     * Compare an original response with a test response.
     */
    public static ComparisonResult compare(int origStatus, String origBody,
                                            int testStatus, String testBody) {
        ComparisonResult result = new ComparisonResult();

        // 1. Status code comparison
        result.sameStatusCode = (origStatus == testStatus);
        result.origStatus = origStatus;
        result.testStatus = testStatus;
        boolean origSuccess = isSuccessStatus(origStatus);
        boolean testSuccess = isSuccessStatus(testStatus);
        result.bothSuccessful = origSuccess && testSuccess;

        // 2. Body similarity (Jaccard on word sets)
        result.bodySimilarity = computeJaccardSimilarity(
                origBody != null ? origBody : "",
                testBody != null ? testBody : "");

        // 3. Success/failure keyword detection
        String origLower = origBody != null ? origBody.toLowerCase() : "";
        String testLower = testBody != null ? testBody.toLowerCase() : "";
        result.origHasSuccessKeywords = containsAny(origLower, SUCCESS_KEYWORDS);
        result.testHasSuccessKeywords = containsAny(testLower, SUCCESS_KEYWORDS);
        result.origHasFailureKeywords = containsAny(origLower, FAILURE_KEYWORDS);
        result.testHasFailureKeywords = containsAny(testLower, FAILURE_KEYWORDS);

        // 4. Size comparison
        int origSize = origBody != null ? origBody.length() : 0;
        int testSize = testBody != null ? testBody.length() : 0;
        result.sizeDifference = Math.abs(origSize - testSize);
        result.sizeRatio = origSize > 0 ? (double) testSize / origSize : 0;

        // 5. Build evidence summary
        result.buildEvidence();

        return result;
    }

    /**
     * Classify the comparison result into a proof level. Pure response
     * comparison cannot prove a business-logic bug by itself; this method
     * therefore never returns {@code CONFIRMED} directly. Callers that have
     * a {@link StateCheck} should call
     * {@link ValidationResult#addStateCheck} which will promote the proof
     * level to CONFIRMED when concrete effects were observed.
     */
    public static ValidationResult.ProofLevel classifyProof(ComparisonResult comparison) {
        if (comparison == null) {
            return ValidationResult.ProofLevel.ERROR;
        }
        // If the original was not even a success, the test cannot have
        // succeeded — that is a definite non-confirm.
        if (!isSuccessStatus(comparison.origStatus)) {
            return ValidationResult.ProofLevel.NOT_CONFIRMED;
        }
        // The test response is a clear rejection.
        if (comparison.testStatus >= 400) {
            return ValidationResult.ProofLevel.NOT_CONFIRMED;
        }
        if (comparison.testHasFailureKeywords && !comparison.testHasSuccessKeywords) {
            return ValidationResult.ProofLevel.NOT_CONFIRMED;
        }
        // The test "looks successful" but we have no business-effect proof.
        // This is the largest source of false positives in the old code;
        // we surface it explicitly as PROBABLE.
        if (comparison.bothSuccessful
                && (comparison.bodySimilarity > 0.5
                        || (comparison.testHasSuccessKeywords
                                && !comparison.testHasFailureKeywords))) {
            return ValidationResult.ProofLevel.PROBABLE;
        }
        // Different shape from the original.
        return ValidationResult.ProofLevel.NOT_CONFIRMED;
    }

    /**
     * Backward-compatible boolean. Returns true when the comparison looks
     * like a successful attack (i.e. the new {@code classifyProof} would
     * return PROBABLE). For full proof-level semantics, prefer
     * {@link #classifyProof} and combine with a {@link StateCheck}.
     */
    public static boolean isVulnerabilityConfirmed(ComparisonResult comparison) {
        return classifyProof(comparison) == ValidationResult.ProofLevel.PROBABLE;
    }

    private static boolean isSuccessStatus(int status) {
        return status >= 200 && status < 400;
    }

    private static boolean containsAny(String text, Set<String> keywords) {
        for (String keyword : keywords) {
            if (text.contains(keyword)) return true;
        }
        return false;
    }

    /**
     * Compute Jaccard similarity between two texts based on word sets.
     */
    static double computeJaccardSimilarity(String text1, String text2) {
        if (text1.isEmpty() && text2.isEmpty()) return 1.0;
        if (text1.isEmpty() || text2.isEmpty()) return 0.0;

        Set<String> words1 = new HashSet<>(Arrays.asList(text1.toLowerCase().split("\\s+")));
        Set<String> words2 = new HashSet<>(Arrays.asList(text2.toLowerCase().split("\\s+")));

        Set<String> intersection = new HashSet<>(words1);
        intersection.retainAll(words2);

        Set<String> union = new HashSet<>(words1);
        union.addAll(words2);

        return union.isEmpty() ? 0.0 : (double) intersection.size() / union.size();
    }

    /**
     * Result of comparing two HTTP responses.
     */
    public static class ComparisonResult {
        public boolean sameStatusCode;
        public int origStatus;
        public int testStatus;
        public boolean bothSuccessful;
        public double bodySimilarity;
        public boolean origHasSuccessKeywords;
        public boolean testHasSuccessKeywords;
        public boolean origHasFailureKeywords;
        public boolean testHasFailureKeywords;
        public int sizeDifference;
        public double sizeRatio;
        public String evidence;

        void buildEvidence() {
            StringBuilder sb = new StringBuilder();
            sb.append("Status: ").append(origStatus).append(" vs ").append(testStatus);
            sb.append(sameStatusCode ? " (same)" : " (different)").append('\n');
            sb.append("Body similarity: ").append(String.format("%.0f%%", bodySimilarity * 100)).append('\n');
            if (testHasSuccessKeywords) sb.append("Test response contains success keywords\n");
            if (testHasFailureKeywords) sb.append("Test response contains failure keywords\n");
            sb.append("Size difference: ").append(sizeDifference).append(" chars");
            this.evidence = sb.toString();
        }
    }
}

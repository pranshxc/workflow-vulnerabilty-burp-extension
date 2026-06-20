package com.workflowscanner.validation;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Smart response comparison that understands what "success" vs "failure" looks like.
 * Compares HTTP responses across multiple dimensions.
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
     * Determine if a test response indicates the vulnerability was confirmed.
     * The test "succeeded" (from attacker's perspective) if the server accepted
     * the manipulated/skipped/replayed request similarly to the original.
     */
    public static boolean isVulnerabilityConfirmed(ComparisonResult comparison) {
        // If test got a success status and original also got success -> likely confirmed
        if (comparison.bothSuccessful && comparison.bodySimilarity > 0.5) {
            return true;
        }
        // If test has success keywords and no failure keywords -> likely confirmed
        if (comparison.testHasSuccessKeywords && !comparison.testHasFailureKeywords
                && isSuccessStatus(comparison.testStatus)) {
            return true;
        }
        // If responses are very similar (>80%) and both successful -> confirmed
        if (comparison.bodySimilarity > 0.8 && comparison.bothSuccessful) {
            return true;
        }
        return false;
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

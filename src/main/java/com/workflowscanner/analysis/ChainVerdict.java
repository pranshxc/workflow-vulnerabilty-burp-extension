package com.workflowscanner.analysis;

import com.workflowscanner.graph.RequestNode;
import com.workflowscanner.llm.LLMAnalysisResult;
import com.workflowscanner.llm.SuggestedTest;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Chain-level verdict aggregated from node-level LLM analysis results.
 * Includes analysis state, timing, and fingerprint for deduplication.
 */
public class ChainVerdict {

    private String chainId;
    private String fingerprint;
    private List<RequestNode> chain;
    private String overallVerdict;       // VULNERABLE, SUSPICIOUS, SAFE
    private double overallConfidence;
    private String vulnerabilityType;
    private String attackNarrative;
    private List<LLMAnalysisResult> nodeResults;
    private List<SuggestedTest> suggestedTests;
    private List<HeuristicPreFilter.HeuristicSignal> heuristicSignals;
    private AnalysisState state;
    private long startTime;
    private long endTime;
    private String errorMessage;

    public ChainVerdict() {
        this.nodeResults = new ArrayList<>();
        this.suggestedTests = new ArrayList<>();
        this.heuristicSignals = new ArrayList<>();
        this.state = AnalysisState.QUEUED;
    }

    /**
     * Aggregate node-level results into a chain-level verdict.
     *
     * Rules:
     * - If ANY node is VULNERABLE with confidence > 0.7 -> chain is VULNERABLE
     * - If multiple nodes are SUSPICIOUS -> chain may be VULNERABLE (escalate)
     * - If all nodes are SAFE -> chain is SAFE
     * - Confidence = weighted average (higher weight for VULNERABLE nodes)
     */
    public void aggregateResults() {
        if (nodeResults == null || nodeResults.isEmpty()) {
            overallVerdict = "SAFE";
            overallConfidence = 0.0;
            return;
        }

        int vulnerableCount = 0;
        int suspiciousCount = 0;
        double totalWeightedConfidence = 0;
        double totalWeight = 0;
        String topVulnType = null;
        StringBuilder narrative = new StringBuilder();
        List<SuggestedTest> allTests = new ArrayList<>();

        for (LLMAnalysisResult result : nodeResults) {
            if (result == null) continue;

            double weight;
            if (result.isVulnerable()) {
                vulnerableCount++;
                weight = 3.0;
                if (topVulnType == null && result.getVulnerabilityType() != null) {
                    topVulnType = result.getVulnerabilityType();
                }
                if (result.getAttackScenario() != null) {
                    narrative.append(result.getAttackScenario()).append("\n\n");
                }
            } else if (result.isSuspicious()) {
                suspiciousCount++;
                weight = 1.5;
            } else {
                weight = 1.0;
            }

            totalWeightedConfidence += result.getConfidence() * weight;
            totalWeight += weight;

            if (result.getSuggestedTests() != null) {
                allTests.addAll(result.getSuggestedTests());
            }
        }

        // Determine overall verdict
        if (vulnerableCount > 0) {
            // Check if any VULNERABLE node has confidence > 0.7
            boolean highConfidenceVuln = nodeResults.stream()
                    .anyMatch(r -> r != null && r.isVulnerable() && r.getConfidence() > 0.7);
            overallVerdict = highConfidenceVuln ? "VULNERABLE" : "SUSPICIOUS";
        } else if (suspiciousCount >= 2) {
            // Multiple suspicious nodes -> escalate
            overallVerdict = "SUSPICIOUS";
        } else if (suspiciousCount == 1) {
            overallVerdict = "SUSPICIOUS";
        } else {
            overallVerdict = "SAFE";
        }

        overallConfidence = totalWeight > 0 ? totalWeightedConfidence / totalWeight : 0.0;
        vulnerabilityType = topVulnType;
        attackNarrative = narrative.length() > 0 ? narrative.toString().trim() : null;
        suggestedTests = allTests;
    }

    public boolean isVulnerable() { return "VULNERABLE".equals(overallVerdict); }
    public boolean isSuspicious() { return "SUSPICIOUS".equals(overallVerdict); }
    public boolean isSafe() { return "SAFE".equals(overallVerdict); }

    public long getDurationMs() {
        return endTime > 0 && startTime > 0 ? endTime - startTime : 0;
    }

    /**
     * Generate a fingerprint for deduplication.
     * Based on sorted (method+path) pairs in the chain.
     */
    public static String generateFingerprint(List<RequestNode> chain) {
        if (chain == null || chain.isEmpty()) return "";
        return chain.stream()
                .map(n -> (n.getMethod() != null ? n.getMethod() : "") + ":" + (n.getPath() != null ? n.getPath() : ""))
                .sorted()
                .collect(Collectors.joining("|"));
    }

    // --- Getters and Setters ---

    public String getChainId() { return chainId; }
    public void setChainId(String chainId) { this.chainId = chainId; }

    public String getFingerprint() { return fingerprint; }
    public void setFingerprint(String fingerprint) { this.fingerprint = fingerprint; }

    public List<RequestNode> getChain() { return chain; }
    public void setChain(List<RequestNode> chain) { this.chain = chain; }

    public String getOverallVerdict() { return overallVerdict; }
    public void setOverallVerdict(String overallVerdict) { this.overallVerdict = overallVerdict; }

    public double getOverallConfidence() { return overallConfidence; }
    public void setOverallConfidence(double overallConfidence) { this.overallConfidence = overallConfidence; }

    public String getVulnerabilityType() { return vulnerabilityType; }
    public void setVulnerabilityType(String vulnerabilityType) { this.vulnerabilityType = vulnerabilityType; }

    public String getAttackNarrative() { return attackNarrative; }
    public void setAttackNarrative(String attackNarrative) { this.attackNarrative = attackNarrative; }

    public List<LLMAnalysisResult> getNodeResults() { return nodeResults; }
    public void setNodeResults(List<LLMAnalysisResult> nodeResults) { this.nodeResults = nodeResults; }

    public List<SuggestedTest> getSuggestedTests() { return suggestedTests; }
    public void setSuggestedTests(List<SuggestedTest> suggestedTests) { this.suggestedTests = suggestedTests; }

    public List<HeuristicPreFilter.HeuristicSignal> getHeuristicSignals() { return heuristicSignals; }
    public void setHeuristicSignals(List<HeuristicPreFilter.HeuristicSignal> signals) { this.heuristicSignals = signals; }

    public AnalysisState getState() { return state; }
    public void setState(AnalysisState state) { this.state = state; }

    public long getStartTime() { return startTime; }
    public void setStartTime(long startTime) { this.startTime = startTime; }

    public long getEndTime() { return endTime; }
    public void setEndTime(long endTime) { this.endTime = endTime; }

    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }

    @Override
    public String toString() {
        return String.format("Chain[%s] %s (%.2f) - %s - %dms",
                chainId, overallVerdict, overallConfidence,
                vulnerabilityType != null ? vulnerabilityType : "none",
                getDurationMs());
    }
}

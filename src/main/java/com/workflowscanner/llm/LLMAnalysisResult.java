package com.workflowscanner.llm;

import java.util.ArrayList;
import java.util.List;

/**
 * Structured result from LLM analysis of a graph node.
 * Parsed from the LLM's JSON response by LLMResponseParser.
 */
public class LLMAnalysisResult {

    private String verdict;           // VULNERABLE, SUSPICIOUS, SAFE
    private double confidence;        // 0.0 - 1.0
    private String vulnerabilityType; // step_skipping, value_manipulation, etc.
    private String reasoning;         // Detailed explanation
    private String attackScenario;    // Step-by-step exploit description
    private List<String> affectedParameters;
    private List<SuggestedTest> suggestedTests;
    private String chainContextUpdate; // Summary for future node context

    public LLMAnalysisResult() {
        this.affectedParameters = new ArrayList<>();
        this.suggestedTests = new ArrayList<>();
    }

    /**
     * Check if this result indicates a potential vulnerability.
     */
    public boolean isVulnerable() {
        return "VULNERABLE".equals(verdict);
    }

    /**
     * Check if this result is suspicious (needs investigation).
     */
    public boolean isSuspicious() {
        return "SUSPICIOUS".equals(verdict);
    }

    /**
     * Check if this result is safe.
     */
    public boolean isSafe() {
        return "SAFE".equals(verdict);
    }

    // --- Getters and Setters ---

    public String getVerdict() { return verdict; }
    public void setVerdict(String verdict) { this.verdict = verdict; }

    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = confidence; }

    public String getVulnerabilityType() { return vulnerabilityType; }
    public void setVulnerabilityType(String vulnerabilityType) { this.vulnerabilityType = vulnerabilityType; }

    public String getReasoning() { return reasoning; }
    public void setReasoning(String reasoning) { this.reasoning = reasoning; }

    public String getAttackScenario() { return attackScenario; }
    public void setAttackScenario(String attackScenario) { this.attackScenario = attackScenario; }

    public List<String> getAffectedParameters() { return affectedParameters; }
    public void setAffectedParameters(List<String> affectedParameters) {
        this.affectedParameters = affectedParameters != null ? affectedParameters : new ArrayList<>();
    }

    public List<SuggestedTest> getSuggestedTests() { return suggestedTests; }
    public void setSuggestedTests(List<SuggestedTest> suggestedTests) {
        this.suggestedTests = suggestedTests != null ? suggestedTests : new ArrayList<>();
    }

    public String getChainContextUpdate() { return chainContextUpdate; }
    public void setChainContextUpdate(String chainContextUpdate) { this.chainContextUpdate = chainContextUpdate; }

    @Override
    public String toString() {
        return String.format("%s (%.2f) - %s", verdict, confidence,
                vulnerabilityType != null ? vulnerabilityType : "none");
    }
}

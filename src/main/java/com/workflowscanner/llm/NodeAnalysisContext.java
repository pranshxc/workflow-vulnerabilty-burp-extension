package com.workflowscanner.llm;

import java.util.ArrayList;
import java.util.List;

/**
 * Context from a previously analyzed node, used to enrich future LLM prompts.
 * Built from LLMAnalysisResult after each node analysis.
 */
public class NodeAnalysisContext {

    private int nodeIndex;
    private String host;
    private String path;
    private String summary;          // Condensed summary of the node
    private String verdict;          // VULNERABLE, SUSPICIOUS, SAFE
    private String keyFindings;      // Brief findings
    private List<String> stateInfo;  // State/tokens/IDs discovered

    public NodeAnalysisContext() {
        this.stateInfo = new ArrayList<>();
    }

    /**
     * Build context from an analysis result and the analyzed node.
     */
    public static NodeAnalysisContext fromResult(LLMAnalysisResult result,
                                                  int nodeIndex, String host, String path) {
        NodeAnalysisContext ctx = new NodeAnalysisContext();
        ctx.setNodeIndex(nodeIndex);
        ctx.setHost(host);
        ctx.setPath(path);
        ctx.setVerdict(result.getVerdict());

        // Build summary from reasoning (first 200 chars)
        if (result.getReasoning() != null) {
            String reasoning = result.getReasoning();
            ctx.setSummary(reasoning.length() > 200
                    ? reasoning.substring(0, 200) + "..."
                    : reasoning);
        }

        // Key findings
        StringBuilder findings = new StringBuilder();
        if (result.getVulnerabilityType() != null && !"null".equals(result.getVulnerabilityType())) {
            findings.append(result.getVulnerabilityType());
        }
        if (result.getAffectedParameters() != null && !result.getAffectedParameters().isEmpty()) {
            findings.append(" [params: ").append(String.join(", ", result.getAffectedParameters())).append(']');
        }
        ctx.setKeyFindings(findings.toString());

        // State info from chain_context_update
        List<String> stateInfo = new ArrayList<>();
        if (result.getChainContextUpdate() != null && !result.getChainContextUpdate().isEmpty()) {
            stateInfo.add(result.getChainContextUpdate());
        }
        ctx.setStateInfo(stateInfo);

        return ctx;
    }

    // --- Getters and Setters ---

    public int getNodeIndex() { return nodeIndex; }
    public void setNodeIndex(int nodeIndex) { this.nodeIndex = nodeIndex; }

    public String getHost() { return host; }
    public void setHost(String host) { this.host = host; }

    public String getPath() { return path; }
    public void setPath(String path) { this.path = path; }

    public String getSummary() { return summary; }
    public void setSummary(String summary) { this.summary = summary; }

    public String getVerdict() { return verdict; }
    public void setVerdict(String verdict) { this.verdict = verdict; }

    public String getKeyFindings() { return keyFindings; }
    public void setKeyFindings(String keyFindings) { this.keyFindings = keyFindings; }

    public List<String> getStateInfo() { return stateInfo; }
    public void setStateInfo(List<String> stateInfo) { this.stateInfo = stateInfo; }
}

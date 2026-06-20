package com.workflowscanner.advisory;

import com.workflowscanner.analysis.ChainVerdict;
import com.workflowscanner.analysis.HeuristicPreFilter;
import com.workflowscanner.graph.RequestNode;
import com.workflowscanner.llm.LLMAnalysisResult;
import com.workflowscanner.validation.ValidationResult;

import java.util.List;

/**
 * Builds rich HTML-formatted issue detail for Burp's issue detail pane.
 * Includes workflow chain, attack scenario, LLM reasoning, validation results,
 * affected parameters, and heuristic signals.
 */
public class IssueDetailBuilder {

    /**
     * Build the full HTML detail for an advisory.
     */
    public static String buildDetail(ChainVerdict verdict, List<ValidationResult> validationResults) {
        StringBuilder html = new StringBuilder();

        // Title
        String vulnType = verdict.getVulnerabilityType() != null
                ? formatVulnType(verdict.getVulnerabilityType()) : "Workflow Vulnerability";
        html.append("<h3>Workflow Vulnerability: ").append(esc(vulnType)).append("</h3>\n");

        // Summary
        html.append("<h4>Summary</h4>\n<p>");
        if (verdict.getAttackNarrative() != null && !verdict.getAttackNarrative().isEmpty()) {
            html.append(esc(truncate(verdict.getAttackNarrative(), 500)));
        } else {
            html.append("A workflow vulnerability was detected in a multi-step request chain. ");
            html.append("Overall verdict: <b>").append(esc(verdict.getOverallVerdict())).append("</b>");
            html.append(" (confidence: ").append(String.format("%.0f%%", verdict.getOverallConfidence() * 100)).append(").");
        }
        html.append("</p>\n");

        // Workflow Chain
        html.append("<h4>Workflow Chain</h4>\n<ol>\n");
        if (verdict.getChain() != null) {
            for (int i = 0; i < verdict.getChain().size(); i++) {
                RequestNode node = verdict.getChain().get(i);
                html.append("  <li>");
                html.append(esc(node.getMethod())).append(" ").append(esc(node.getPath()));
                html.append(" &rarr; ").append(node.getStatusCode());

                // Mark vulnerable nodes
                if (verdict.getNodeResults() != null && i < verdict.getNodeResults().size()) {
                    LLMAnalysisResult nodeResult = verdict.getNodeResults().get(i);
                    if (nodeResult != null && nodeResult.isVulnerable()) {
                        html.append(" &larr; <b style='color:red'>VULNERABLE</b>");
                    } else if (nodeResult != null && nodeResult.isSuspicious()) {
                        html.append(" &larr; <b style='color:orange'>SUSPICIOUS</b>");
                    }
                }
                html.append("</li>\n");
            }
        }
        html.append("</ol>\n");

        // LLM Analysis
        html.append("<h4>LLM Analysis</h4>\n");
        if (verdict.getNodeResults() != null) {
            for (int i = 0; i < verdict.getNodeResults().size(); i++) {
                LLMAnalysisResult result = verdict.getNodeResults().get(i);
                if (result == null || result.isSafe()) continue;

                html.append("<p><b>Node ").append(i + 1).append("</b>: ");
                html.append(esc(result.getVerdict()));
                html.append(" (").append(String.format("%.0f%%", result.getConfidence() * 100)).append(")");
                if (result.getVulnerabilityType() != null) {
                    html.append(" - ").append(esc(result.getVulnerabilityType()));
                }
                html.append("<br>\n");
                if (result.getReasoning() != null) {
                    html.append("<i>").append(esc(truncate(result.getReasoning(), 500))).append("</i>");
                }
                html.append("</p>\n");
            }
        }

        // Attack Scenario
        if (verdict.getAttackNarrative() != null && !verdict.getAttackNarrative().isEmpty()) {
            html.append("<h4>Attack Scenario</h4>\n<p>");
            html.append(esc(verdict.getAttackNarrative()).replace("\n", "<br>\n"));
            html.append("</p>\n");
        }

        // Validation Results
        if (validationResults != null && !validationResults.isEmpty()) {
            html.append("<h4>Validation Results</h4>\n");
            for (ValidationResult vr : validationResults) {
                String icon = vr.isConfirmed() ? "&#10003;" : "&#10007;";
                String color = vr.isConfirmed() ? "green" : "gray";
                html.append("<p style='color:").append(color).append("'>");
                html.append(icon).append(" <b>").append(esc(vr.getTestName())).append("</b>");
                html.append(" [").append(vr.getStrategy()).append("]");
                if (vr.isDryRun()) html.append(" (dry run)");
                html.append("<br>\n");
                if (vr.getEvidence() != null) {
                    html.append(esc(vr.getEvidence()).replace("\n", "<br>\n"));
                }
                html.append("</p>\n");
            }
        }

        // Affected Parameters
        if (verdict.getNodeResults() != null) {
            List<String> allParams = new java.util.ArrayList<>();
            for (LLMAnalysisResult r : verdict.getNodeResults()) {
                if (r != null && r.getAffectedParameters() != null) {
                    allParams.addAll(r.getAffectedParameters());
                }
            }
            if (!allParams.isEmpty()) {
                html.append("<h4>Affected Parameters</h4>\n<ul>\n");
                for (String param : allParams) {
                    html.append("  <li>").append(esc(param)).append("</li>\n");
                }
                html.append("</ul>\n");
            }
        }

        // Heuristic Signals
        if (verdict.getHeuristicSignals() != null && !verdict.getHeuristicSignals().isEmpty()) {
            html.append("<h4>Heuristic Signals</h4>\n<ul>\n");
            for (HeuristicPreFilter.HeuristicSignal signal : verdict.getHeuristicSignals()) {
                html.append("  <li>[").append(signal.type).append("] ");
                html.append(esc(signal.description)).append("</li>\n");
            }
            html.append("</ul>\n");
        }

        // Metadata
        html.append("<h4>Metadata</h4>\n<p>");
        html.append("Chain ID: ").append(esc(verdict.getChainId())).append("<br>\n");
        html.append("Analysis duration: ").append(verdict.getDurationMs()).append("ms<br>\n");
        html.append("Overall confidence: ").append(String.format("%.0f%%", verdict.getOverallConfidence() * 100));
        html.append("</p>\n");

        return html.toString();
    }

    private static String formatVulnType(String type) {
        if (type == null) return "Unknown";
        return type.replace("_", " ").substring(0, 1).toUpperCase()
                + type.replace("_", " ").substring(1);
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;");
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }
}

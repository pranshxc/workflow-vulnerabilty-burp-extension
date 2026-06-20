package com.workflowscanner.llm;

import com.workflowscanner.graph.RequestEdge;
import com.workflowscanner.graph.RequestNode;

import java.util.List;
import java.util.Map;

/**
 * Builds the user message prompt for LLM analysis of a graph node.
 * Includes full request/response data, relationship context, parameter flow,
 * and accumulated analysis context from previous nodes.
 */
public class PromptBuilder {

    /**
     * Build the complete user message for analyzing a node.
     *
     * @param node             The node to analyze
     * @param edges            Edges connected to this node
     * @param contextManager   Context from previous analyses
     * @param allNodes         All nodes in the graph (for cross-referencing)
     * @return The formatted user message string
     */
    public static String buildPrompt(RequestNode node, List<RequestEdge> edges,
                                      LLMContextManager contextManager,
                                      Map<String, RequestNode> allNodes) {
        StringBuilder sb = new StringBuilder();

        // Section 1: Node header
        sb.append("## Graph Node #").append(node.getNodeIndex()).append("\n\n");

        // Section 2: Previous chain context
        appendChainContext(sb, contextManager, node);

        // Section 3: Current request
        appendRequest(sb, node);

        // Section 4: Response
        appendResponse(sb, node);

        // Section 5: Relationships
        appendRelationships(sb, edges, allNodes);

        // Section 6: Parameter flow
        appendParameterFlow(sb, node, edges, allNodes);

        // Section 7: Analysis instruction
        sb.append("### Analysis Task\n");
        sb.append("Analyze this node for workflow vulnerabilities. ");
        sb.append("Consider the full chain context above.\n");

        return sb.toString();
    }

    private static void appendChainContext(StringBuilder sb, LLMContextManager contextManager,
                                            RequestNode currentNode) {
        List<NodeAnalysisContext> previous = contextManager.getRelevantContext(
                currentNode.getHost(), 10);

        if (previous.isEmpty()) {
            sb.append("### Workflow Chain Context\n");
            sb.append("This is the first node being analyzed in this chain.\n\n");
            return;
        }

        sb.append("### Workflow Chain Context\n");
        sb.append("Previous analysis results in this chain:\n\n");

        for (NodeAnalysisContext ctx : previous) {
            sb.append("- **Node #").append(ctx.getNodeIndex()).append("**: ");
            sb.append(ctx.getVerdict());
            if (ctx.getKeyFindings() != null && !ctx.getKeyFindings().isEmpty()) {
                sb.append(" - ").append(ctx.getKeyFindings());
            }
            sb.append('\n');
            if (ctx.getStateInfo() != null) {
                for (String info : ctx.getStateInfo()) {
                    sb.append("  - State: ").append(info).append('\n');
                }
            }
        }
        sb.append('\n');
    }

    private static void appendRequest(StringBuilder sb, RequestNode node) {
        sb.append("### Current Request\n");
        sb.append("Method: ").append(node.getMethod()).append('\n');
        sb.append("URL: ").append(node.getUrl()).append('\n');

        // Request headers
        if (node.getRequest() != null && node.getRequest().getRequestHeaders() != null) {
            sb.append("Headers:\n");
            for (Map.Entry<String, List<String>> entry :
                    node.getRequest().getRequestHeaders().entrySet()) {
                for (String value : entry.getValue()) {
                    sb.append("  ").append(entry.getKey()).append(": ").append(value).append('\n');
                }
            }
        }

        // Request body
        if (node.getRequest() != null && node.getRequest().getRequestBody() != null
                && !node.getRequest().getRequestBody().isEmpty()) {
            sb.append("Body:\n");
            sb.append(truncate(node.getRequest().getRequestBody(), 4000)).append('\n');
        }
        sb.append('\n');
    }

    private static void appendResponse(StringBuilder sb, RequestNode node) {
        sb.append("### Response\n");
        sb.append("Status: ").append(node.getStatusCode()).append('\n');

        // Response headers
        if (node.getRequest() != null && node.getRequest().getResponseHeaders() != null) {
            sb.append("Headers:\n");
            for (Map.Entry<String, List<String>> entry :
                    node.getRequest().getResponseHeaders().entrySet()) {
                for (String value : entry.getValue()) {
                    sb.append("  ").append(entry.getKey()).append(": ").append(value).append('\n');
                }
            }
        }

        // Response body
        if (node.getRequest() != null && node.getRequest().getResponseBody() != null
                && !node.getRequest().getResponseBody().isEmpty()) {
            sb.append("Body:\n");
            sb.append(truncate(node.getRequest().getResponseBody(), 4000)).append('\n');
        }
        sb.append('\n');
    }

    private static void appendRelationships(StringBuilder sb, List<RequestEdge> edges,
                                             Map<String, RequestNode> allNodes) {
        if (edges == null || edges.isEmpty()) {
            sb.append("### Relationships\nNo relationships detected for this node.\n\n");
            return;
        }

        sb.append("### Relationships\n");
        for (RequestEdge edge : edges) {
            String otherNodeId = edge.getSourceNodeId();
            String direction = "from";
            RequestNode otherNode = allNodes.get(otherNodeId);
            if (otherNode == null) {
                otherNodeId = edge.getTargetNodeId();
                direction = "to";
                otherNode = allNodes.get(otherNodeId);
            }

            sb.append("- Connected ").append(direction).append(" Node #");
            if (otherNode != null) {
                sb.append(otherNode.getNodeIndex());
                sb.append(" (").append(otherNode.getMethod()).append(' ').append(otherNode.getPath()).append(')');
            } else {
                sb.append("?");
            }
            sb.append(" via ").append(edge.getType());
            sb.append(" (confidence: ").append(String.format("%.2f", edge.getConfidence())).append(')');
            sb.append('\n');
            if (edge.getEvidence() != null) {
                sb.append("  Evidence: ").append(edge.getEvidence()).append('\n');
            }
        }
        sb.append('\n');
    }

    private static void appendParameterFlow(StringBuilder sb, RequestNode node,
                                             List<RequestEdge> edges,
                                             Map<String, RequestNode> allNodes) {
        Map<String, Object> params = node.getExtractedParams();
        if (params == null || params.isEmpty()) return;

        sb.append("### Parameters in This Request\n");
        for (Map.Entry<String, Object> entry : params.entrySet()) {
            String value = entry.getValue() != null ? entry.getValue().toString() : "";
            sb.append("- ").append(entry.getKey()).append(": ");
            sb.append(truncate(value, 100)).append('\n');
        }
        sb.append('\n');
    }

    /**
     * Estimate token count for a string (chars / 4 approximation).
     */
    public static int estimateTokens(String text) {
        if (text == null) return 0;
        return text.length() / 4;
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) return "";
        if (s.length() <= maxLen) return s;
        return s.substring(0, maxLen) + "\n... [truncated, " + (s.length() - maxLen) + " chars omitted]";
    }
}

package com.workflowscanner.llm;

import com.workflowscanner.analysis.ApplicationModel;
import com.workflowscanner.classification.RequestClassification;
import com.workflowscanner.classification.RequestIntent;
import com.workflowscanner.graph.RequestEdge;
import com.workflowscanner.graph.RequestNode;
import com.workflowscanner.workflow.WorkflowCandidate;
import com.workflowscanner.workflow.WorkflowType;

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

    // ========================================================================
    // 3-Prompt Builders (workflow rework)
    // ========================================================================

    /**
     * Prompt 1: Classify the workflow candidate — identify its business purpose,
     * workflow type, and determine if it's a genuine workflow.
     */
    public static String buildWorkflowClassifyPrompt(WorkflowCandidate candidate,
                                                     ApplicationModel appModel) {
        StringBuilder sb = new StringBuilder();

        sb.append("## Workflow Classification Task\n\n");
        sb.append("Analyze this request sequence and determine if it represents a real workflow.\n\n");

        // Candidate metadata
        sb.append("### Candidate Overview\n");
        sb.append("Score: ").append(String.format("%.1f", candidate.getWorkflowScore())).append("\n");
        sb.append("Type (heuristic): ").append(candidate.getWorkflowType()).append("\n");
        sb.append("Steps: ").append(candidate.getSteps().size()).append("\n\n");

        // Steps
        sb.append("### Request Steps\n");
        for (int i = 0; i < candidate.getSteps().size(); i++) {
            RequestNode node = candidate.getSteps().get(i);
            sb.append("Step ").append(i + 1).append(": ");
            sb.append(node != null ? node.getMethod() + " " + (node.getPath() != null ? node.getPath() : "") : "?");
            sb.append(" [").append(node != null ? node.getStatusCode() : "?").append("]");

            RequestClassification cls = node != null ? node.getClassification() : null;
            if (cls != null) {
                sb.append(" Intent: ").append(cls.getIntent());
                sb.append(" BusinessScore: ").append(String.format("%.2f", cls.getBusinessScore()));
            }
            sb.append("\n");

            if (node != null && node.getUrl() != null) {
                sb.append("  URL: ").append(node.getUrl()).append("\n");
            }
        }

        // Application context
        if (appModel != null) sb.append("\n").append(appModel.toPromptContext());

        // Classification question
        sb.append("\n### Classification Questions\n");
        sb.append("1. Is this a genuine business workflow (e.g., checkout, auth, payment)?\n");
        sb.append("2. What type of workflow is this? (auth, checkout, profile-update, search, admin, api-call, unknown)\n");
        sb.append("3. What is the business purpose?\n");
        sb.append("4. Are there any steps that don't belong (noise)?\n\n");

        sb.append("Respond in JSON:\n");
        sb.append("{\n");
        sb.append("  \"is_workflow\": true|false,\n");
        sb.append("  \"workflow_type\": \"auth|checkout|payment|profile|search|admin|api|unknown\",\n");
        sb.append("  \"business_purpose\": \"Brief description\",\n");
        sb.append("  \"confidence\": 0.0-1.0,\n");
        sb.append("  \"workflow_context\": \"Summary of what this workflow does and its key characteristics\",\n");
        sb.append("  \"noise_steps\": [step_numbers_that_dont_belong]\n");
        sb.append("}\n");

        return sb.toString();
    }

    /**
     * Prompt 2: Generate vulnerability hypotheses given the workflow classification.
     */
    public static String buildHypothesesPrompt(WorkflowCandidate candidate,
                                               String workflowContext,
                                               String workflowType,
                                               ApplicationModel appModel) {
        StringBuilder sb = new StringBuilder();

        sb.append("## Vulnerability Hypotheses Generation\n\n");

        // Workflow context summary
        sb.append("### Workflow Context\n");
        sb.append("Type: ").append(workflowType).append("\n");
        sb.append("Steps: ").append(candidate.getSteps().size()).append("\n");
        sb.append("Context: ").append(workflowContext).append("\n\n");

        // Steps summary
        sb.append("### Steps\n");
        for (int i = 0; i < candidate.getSteps().size(); i++) {
            RequestNode node = candidate.getSteps().get(i);
            if (node != null) {
                sb.append("- Step ").append(i + 1).append(": ").append(node.getMethod())
                        .append(" ").append(node.getPath());
                if (node.getUrl() != null) {
                    sb.append(" (").append(node.getUrl()).append(")");
                }
                RequestClassification cls = node.getClassification();
                if (cls != null) {
                    sb.append(" [").append(cls.getIntent()).append("]");
                }
                sb.append("\n");
            }
        }

        // Application context
        if (appModel != null) sb.append("\n").append(appModel.toPromptContext());

        // Attack mental models reminder
        sb.append("\n### Attack Mental Models to Consider\n");
        sb.append("1. THE SKIPPER: Can steps be skipped? Does step N verify step N-1 completed?\n");
        sb.append("2. THE REPEATER: Can one-time actions be repeated? Missing idempotency?\n");
        sb.append("3. THE MANIPULATOR: Can values be changed between steps?\n");
        sb.append("4. THE PARALLEL EXECUTOR: Race conditions with concurrent requests?\n");
        sb.append("5. THE STATE CONFUSER: Can the system be put into inconsistent state?\n\n");

        sb.append("### Output Format — JSON Array\n");
        sb.append("Generate 2-5 specific, testable hypotheses:\n");
        sb.append("{\n");
        sb.append("  \"hypotheses\": [\n");
        sb.append("    {\n");
        sb.append("      \"attack_type\": \"step_skipping|value_manipulation|race_condition|state_confusion|replay|idor|missing_rate_limit\",\n");
        sb.append("      \"description\": \"What could go wrong and how\",\n");
        sb.append("      \"affected_steps\": [1, 3],\n");
        sb.append("      \"likelihood\": \"high|medium|low\",\n");
        sb.append("      \"impact\": \"high|medium|low\"\n");
        sb.append("    }\n");
        sb.append("  ]\n");
        sb.append("}\n");

        return sb.toString();
    }

    /**
     * Prompt 3: Validate a single step against the hypotheses.
     * Replaces the old single-step analysis prompt.
     */
    public static String buildValidationPrompt(RequestNode node,
                                               List<RequestEdge> edges,
                                               LLMContextManager contextManager,
                                               Map<String, RequestNode> allNodes,
                                               List<String> hypotheses,
                                               String workflowContext,
                                               String workflowType,
                                               ApplicationModel appModel) {
        StringBuilder sb = new StringBuilder();

        sb.append("## Step Validation Task\n\n");

        // Workflow context
        sb.append("### Workflow Context\n");
        sb.append("Type: ").append(workflowType).append("\n");
        sb.append(truncate(workflowContext, 1000)).append("\n\n");

        // Active hypotheses
        if (hypotheses != null && !hypotheses.isEmpty()) {
            sb.append("### Active Hypotheses to Validate\n");
            for (int i = 0; i < hypotheses.size(); i++) {
                sb.append(i + 1).append(". ").append(hypotheses.get(i)).append("\n");
            }
            sb.append("\n");
        }

        // Previous chain context
        appendChainContext(sb, contextManager, node);

        // Current request
        sb.append("### Current Request\n");
        sb.append("Method: ").append(node.getMethod()).append("\n");
        sb.append("URL: ").append(node.getUrl() != null ? node.getUrl() : node.getPath() != null ? node.getPath() : "").append("\n");

        // Intent classification
        RequestClassification cls = node.getClassification();
        if (cls != null) {
            sb.append("Intent: ").append(cls.getIntent()).append("\n");
            sb.append("Business Score: ").append(String.format("%.2f", cls.getBusinessScore())).append("\n");
        }

        if (node.getRequest() != null && node.getRequest().getRequestHeaders() != null) {
            sb.append("Headers:\n");
            for (Map.Entry<String, List<String>> entry :
                    node.getRequest().getRequestHeaders().entrySet()) {
                for (String value : entry.getValue()) {
                    sb.append("  ").append(entry.getKey()).append(": ").append(value).append("\n");
                }
            }
        }

        if (node.getRequest() != null && node.getRequest().getRequestBody() != null
                && !node.getRequest().getRequestBody().isEmpty()) {
            sb.append("Body:\n");
            sb.append(truncate(node.getRequest().getRequestBody(), 4000)).append("\n");
        }
        sb.append("\n");

        // Response
        sb.append("### Response\n");
        sb.append("Status: ").append(node.getStatusCode()).append("\n");
        if (node.getRequest() != null && node.getRequest().getResponseHeaders() != null) {
            sb.append("Headers:\n");
            for (Map.Entry<String, List<String>> entry :
                    node.getRequest().getResponseHeaders().entrySet()) {
                for (String value : entry.getValue()) {
                    sb.append("  ").append(entry.getKey()).append(": ").append(value).append("\n");
                }
            }
        }
        if (node.getRequest() != null && node.getRequest().getResponseBody() != null
                && !node.getRequest().getResponseBody().isEmpty()) {
            sb.append("Body:\n");
            sb.append(truncate(node.getRequest().getResponseBody(), 4000)).append("\n");
        }
        sb.append("\n");

        // Relationships
        appendRelationships(sb, edges, allNodes);

        // Parameters
        appendParameterFlow(sb, node, edges, allNodes);

        // Application model context
        if (appModel != null) {
            String appCtx = appModel.toPromptContext();
            if (appCtx.length() > 500) {
                sb.append(truncate(appCtx, 500)).append("\n");
            } else {
                sb.append(appCtx).append("\n");
            }
        }

        // Validation instruction
        sb.append("### Analysis Task\n");
        sb.append("For each active hypothesis above, determine if this step is involved in the vulnerability. ");
        sb.append("Consider the full chain context and the specific request/response data.\n");

        return sb.toString();
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) return "";
        if (s.length() <= maxLen) return s;
        return s.substring(0, maxLen) + "\n... [truncated, " + (s.length() - maxLen) + " chars omitted]";
    }
}

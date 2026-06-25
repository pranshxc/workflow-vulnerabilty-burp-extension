package com.workflowscanner.workflow;

import com.workflowscanner.classification.BusinessKeywordRules;
import com.workflowscanner.classification.RequestIntent;
import com.workflowscanner.classification.RequestClassification;
import com.workflowscanner.config.ExtensionConfig;
import com.workflowscanner.graph.EdgeType;
import com.workflowscanner.graph.RequestEdge;
import com.workflowscanner.graph.RequestNode;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Scores workflow candidates for vulnerability analysis priority.
 * Higher scores indicate workflows more likely to contain exploitable vulnerabilities.
 *
 * Scores read from ExtensionConfig: >= workflowScoreThreshold → LLM analysis,
 * >= workflowCandidateThreshold → display only, below → suppressed.
 */
public class WorkflowScorer {

    private final ExtensionConfig config;

    public WorkflowScorer(ExtensionConfig config) {
        this.config = config;
    }

    /**
     * Score a workflow candidate and populate evidence breakdown.
     */
    public double score(WorkflowCandidate candidate) {
        if (candidate == null || candidate.getSteps().isEmpty()) return 0.0;

        List<RequestNode> steps = candidate.getSteps();
        List<RequestEdge> edges = candidate.getSupportingEdges();

        double score = 0.0;

        // Positive signals
        double stateChangeScore = scoreStateChangingMethods(steps);
        double keywordScore = scoreBusinessKeywords(steps);
        double objectFlowScore = scoreObjectFlows(candidate);
        double diversityScore = scoreMethodDiversity(steps);
        double structuralScore = scoreStructuralSignals(steps, edges);

        score += stateChangeScore;
        score += keywordScore;
        score += objectFlowScore;
        score += diversityScore;
        score += structuralScore;

        // Negative signals (penalties)
        double penaltyScore = penalizeStaticContent(steps);
        penaltyScore += penalizePolling(steps);
        penaltyScore += penalizeWeakStructure(steps, edges);
        penaltyScore += penalizeRepetition(steps);
        score -= penaltyScore;

        // Populate evidence with score breakdown
        WorkflowEvidence evidence = candidate.getEvidence();
        if (stateChangeScore > 0) evidence.addObjectFlow(String.format("score:state-change=%.1f", stateChangeScore));
        if (keywordScore > 0) evidence.addObjectFlow(String.format("score:keywords=%.1f", keywordScore));
        if (objectFlowScore > 0) evidence.addObjectFlow(String.format("score:object-flows=%.1f", objectFlowScore));
        if (diversityScore > 0) evidence.addObjectFlow(String.format("score:diversity=%.1f", diversityScore));
        if (structuralScore > 0) evidence.addObjectFlow(String.format("score:structural=%.1f", structuralScore));
        if (penaltyScore > 0) evidence.addObjectFlow(String.format("score:penalties=-%.1f", penaltyScore));
        evidence.setConfidence(Math.min(1.0, score / 100.0));

        return score;
    }

    private double scoreStateChangingMethods(List<RequestNode> steps) {
        int count = 0;
        for (RequestNode node : steps) {
            if (BusinessKeywordRules.isStateChanging(node.getMethod())) count++;
        }
        return count * 5.0;
    }

    private double scoreBusinessKeywords(List<RequestNode> steps) {
        double score = 0.0;
        for (RequestNode node : steps) {
            String path = node.getPath() != null ? node.getPath().toLowerCase() : "";
            if (BusinessKeywordRules.isFinancialPath(path)) score += 7.0;
            else if (BusinessKeywordRules.isAuthPath(path)) score += 5.0;
            else score += BusinessKeywordRules.scorePath(path) * 1.5;
        }
        return score;
    }

    private double scoreObjectFlows(WorkflowCandidate candidate) {
        double score = 0.0;
        for (RequestEdge edge : candidate.getSupportingEdges()) {
            // WORKFLOW_SEQUENCE is intentionally NOT scored here —
            // it is a derived structural edge produced by
            // WorkflowDetector after a candidate is finalized, not
            // a real object-flow signal. Adding it would let
            // session-derived candidates double-count the
            // "workflow exists" signal as object-flow evidence.
            if (edge.getType() == EdgeType.PARAM_REUSE) score += 6.0;
            else if (edge.getType() == EdgeType.RESPONSE_CORRELATION) score += 4.0;
            else if (edge.getType() == EdgeType.REDIRECT) score += 2.0;
        }
        return score;
    }

    private double scoreMethodDiversity(List<RequestNode> steps) {
        Set<String> methods = new HashSet<>();
        for (RequestNode node : steps) {
            methods.add(node.getMethod() != null ? node.getMethod().toUpperCase() : "GET");
        }
        return methods.size() * 2.0;
    }

    private double scoreStructuralSignals(List<RequestNode> steps,
                                          List<RequestEdge> edges) {
        double score = 0.0;

        // Redirect after POST (state change confirmation)
        for (int i = 0; i < steps.size() - 1; i++) {
            RequestNode current = steps.get(i);
            RequestNode next = steps.get(i + 1);
            if ("POST".equalsIgnoreCase(current.getMethod())
                    && current.isRedirect()
                    && next.getStatusCode() == 200) {
                score += 4.0;
            }
        }

        // Terminal confirmation page
        RequestNode last = steps.get(steps.size() - 1);
        String lastPath = last.getPath() != null ? last.getPath().toLowerCase() : "";
        if (lastPath.contains("confirm") || lastPath.contains("success")
                || lastPath.contains("complete") || last.getStatusCode() == 201) {
            score += 5.0;
        }

        // Money/role parameters present
        for (RequestNode node : steps) {
            if (hasCriticalParams(node)) {
                score += 8.0;
                break;
            }
        }

        // State-changing method count
        int stateChanges = 0;
        for (RequestNode node : steps) {
            if (BusinessKeywordRules.isStateChanging(node.getMethod())) stateChanges++;
        }
        score += Math.min(stateChanges, 5) * 4.0;

        return score;
    }

    private double penalizeStaticContent(List<RequestNode> steps) {
        int staticCount = 0;
        for (RequestNode node : steps) {
            RequestClassification cls = node.getClassification();
            if (cls != null && cls.getIntent() == RequestIntent.STATIC_ASSET) {
                staticCount++;
            }
        }
        return staticCount * 10.0;
    }

    private double penalizePolling(List<RequestNode> steps) {
        int pollingCount = 0;
        for (RequestNode node : steps) {
            RequestClassification cls = node.getClassification();
            if (cls != null && cls.getIntent() == RequestIntent.BACKGROUND_POLLING) {
                pollingCount++;
            }
        }
        return pollingCount * 5.0;
    }

    private double penalizeWeakStructure(List<RequestNode> steps,
                                          List<RequestEdge> edges) {
        // If the only edges are TIME_WINDOW (a context-only edge
        // type RelationshipDetector no longer emits), penalize
        // heavily. WORKFLOW_SEQUENCE is a derived structural edge
        // and does not by itself indicate weak structure — it is
        // added after the candidate is finalized, so applying a
        // penalty here would penalize every session-derived
        // candidate, which is the opposite of the intended UX.
        if (edges != null && !edges.isEmpty()) {
            boolean onlyTimeWindow = edges.stream()
                    .allMatch(e -> e.getType() == EdgeType.TIME_WINDOW);
            if (onlyTimeWindow) return 15.0;
        }
        return 0.0;
    }

    private double penalizeRepetition(List<RequestNode> steps) {
        Set<String> seenEndpoints = new HashSet<>();
        int repeats = 0;
        for (RequestNode node : steps) {
            String key = node.getMethod() + ":" + node.getPath();
            if (!seenEndpoints.add(key)) repeats++;
        }
        return repeats * 2.0;
    }

    private boolean hasCriticalParams(RequestNode node) {
        if (node.getExtractedParams() == null) return false;
        return BusinessKeywordRules.hasCriticalParameters(node.getExtractedParams().keySet());
    }

    /**
     * Sort candidates by score (highest first).
     */
    public List<WorkflowCandidate> prioritize(List<WorkflowCandidate> candidates) {
        candidates.sort((a, b) -> Double.compare(b.getWorkflowScore(), a.getWorkflowScore()));
        return candidates;
    }
}

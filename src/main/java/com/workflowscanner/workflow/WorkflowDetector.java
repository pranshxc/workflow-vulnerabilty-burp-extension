package com.workflowscanner.workflow;

import com.workflowscanner.classification.EdgeStrength;
import com.workflowscanner.classification.RequestClassification;
import com.workflowscanner.config.ExtensionConfig;
import com.workflowscanner.graph.EdgeType;
import com.workflowscanner.graph.RequestEdge;
import com.workflowscanner.graph.RequestGraph;
import com.workflowscanner.graph.RequestNode;
import com.workflowscanner.graph.RelationshipDetector;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * Main workflow detection orchestrator.
 * Replaces RequestGraph.getWorkflowChains() as the source of workflow candidates
 * for the analysis pipeline.
 *
 * Pipeline:
 * 1. Collect all graph nodes, filter to workflow-relevant
 * 2. Segment by session via WorkflowSessionizer
 * 3. Attach supporting edges for each candidate
 * 4. Detect WorkflowType and build WorkflowEvidence
 * 5. Score via WorkflowScorer
 * 6. Return sorted, scored candidates
 */
public class WorkflowDetector {

    private final WorkflowSessionizer sessionizer;
    private final WorkflowScorer scorer;
    private final ExtensionConfig config;
    private final ExtensionLogger logger;
    private final List<Consumer<WorkflowCandidate>> candidateListeners = new ArrayList<>();
    private List<WorkflowCandidate> lastResults = new ArrayList<>();
    
    // Graph references for edge-aware detection (set externally)
    private RequestGraph graph;
    private RelationshipDetector relationshipDetector;

    public WorkflowDetector(ExtensionConfig config, ExtensionLogger logger) {
        this.config = config;
        this.sessionizer = new WorkflowSessionizer(config, logger);
        this.scorer = new WorkflowScorer(config);
        this.logger = logger;
    }
    
    /**
     * Read-only preview of candidates — no scoring, no listener publishing, no side effects.
     * Safe to call from UI refresh thread.
     * Returns candidates segmented by session (not merged), in chronological order.
     */
    public List<WorkflowCandidate> previewCandidates(List<RequestNode> allNodes) {
        if (allNodes == null || allNodes.isEmpty()) return List.of();

        // Filter to workflow-relevant
        List<RequestNode> relevantNodes = allNodes.stream()
                .filter(n -> {
                    RequestClassification cls = n.getClassification();
                    return cls != null && cls.isWorkflowRelevant();
                })
                .toList();

        // Segment by session (stateless)
        List<WorkflowCandidate> candidates = WorkflowSessionizer.segmentFullGraph(
                relevantNodes, config, logger);

        // Chronological order
        candidates.sort(Comparator.comparingLong(WorkflowCandidate::getStartTime));
        return candidates;
    }

    /**
     * Set the graph and relationship detector for edge-aware detection.
     * Must be called before {@link #detect(List, RequestGraph, RelationshipDetector)}.
     */
    public void setGraphContext(RequestGraph graph, RelationshipDetector relationshipDetector) {
        this.graph = graph;
        this.relationshipDetector = relationshipDetector;
    }

    /**
     * Detect workflow candidates with supporting graph edge attachment.
     * Preferred over {@link #detect(List)} as it uses graph structure
     * (PARAM_REUSE, REDIRECT, REFERRER, RESPONSE_CORRELATION edges) to
     * strengthen candidate evidence and scoring.
     * Falls back to the session-only mode if graph context is not set.
     *
     * @param allNodes all graph nodes
     * @return sorted list of workflow candidates (highest score first)
     */
    public List<WorkflowCandidate> detect(List<RequestNode> allNodes) {
        if (graph != null && relationshipDetector != null) {
            return detect(allNodes, graph, relationshipDetector);
        }
        // Fallback: session-only detection without edge attachment
        return detectSessionOnly(allNodes);
    }

    /**
     * Detect workflow candidates with supporting graph edge attachment.
     * Internal method that takes explicit graph references.
     *
     * Pipeline:
     * 1. Filter to workflow-relevant nodes
     * 2. Segment by session (stateless, no scoring)
     * 3. Sort chronologically by candidate start time
     * 4. Merge candidates with strong cross-candidate edges
     * 5. Attach internal supporting edges
     * 6. Score once
     * 7. Prioritize
     *
     * Note: Scoring happens exactly once, after merging. This avoids
     * duplicated score evidence and ensures merged candidates get
     * a single, accurate score.
     */
    public List<WorkflowCandidate> detect(List<RequestNode> allNodes,
                                           RequestGraph graph,
                                           RelationshipDetector detector) {
        if (allNodes == null || allNodes.isEmpty()) return List.of();

        // 1. Filter to workflow-relevant nodes
        List<RequestNode> relevantNodes = new ArrayList<>();
        int suppressedCount = 0;
        for (RequestNode node : allNodes) {
            RequestClassification cls = node.getClassification();
            if (cls != null && cls.isWorkflowRelevant()) {
                relevantNodes.add(node);
            } else {
                suppressedCount++;
            }
        }

        logger.log(LogCategory.GRAPH, LogLevel.INFO, "WorkflowDetector",
                "Filtering graph: " + allNodes.size() + " total nodes, "
                        + relevantNodes.size() + " workflow-relevant, "
                        + suppressedCount + " suppressed");

        // 2. Segment by session (stateless, no scoring)
        List<WorkflowCandidate> segmented = WorkflowSessionizer.segmentFullGraph(
                relevantNodes, config, logger);
        if (segmented.isEmpty()) return List.of();

        logger.log(LogCategory.GRAPH, LogLevel.INFO, "WorkflowDetector",
                "Segmented into " + segmented.size() + " session candidates");

        // 3. Sort chronologically by candidate start time before merging
        List<WorkflowCandidate> chronological = new ArrayList<>(segmented);
        chronological.sort(Comparator.comparingLong(WorkflowCandidate::getStartTime));

        // 4. Merge candidates with strong cross-candidate edges
        List<WorkflowCandidate> merged = mergeCandidatesByStrongEdges(
                chronological, graph, detector);

        // 5. Attach supporting edges within each candidate
        for (WorkflowCandidate candidate : merged) {
            attachSupportingEdges(candidate, graph, detector);
        }

        // 6. Score once — after all merging and edge attachment
        for (WorkflowCandidate candidate : merged) {
            double score = scorer.score(candidate);
            candidate.setWorkflowScore(score);
        }

        // 7. Prioritize
        List<WorkflowCandidate> prioritized = scorer.prioritize(merged);

        logger.log(LogCategory.GRAPH, LogLevel.INFO, "WorkflowDetector",
                "Edge-aware detection: " + prioritized.size()
                        + " candidates (merged from " + segmented.size()
                        + " session candidates) with supporting edges.");

        lastResults = prioritized;
        return prioritized;
    }

    /**
     * Merge session-split candidates that have STRONG cross-candidate edges.
     * Conditions:
     * - STRONG edge type PARAM_REUSE, REDIRECT, or USER_DEFINED
     * - Same host and compatible session
     * - Candidate A is chronologically before candidate B
     * - Gap between A's last step and B's first step <= session window
     */
    private List<WorkflowCandidate> mergeCandidatesByStrongEdges(
            List<WorkflowCandidate> candidates,
            RequestGraph graph,
            RelationshipDetector detector) {

        if (candidates.size() < 2) return new ArrayList<>(candidates);

        long sessionWindowMs = config.getWorkflowSessionWindowMs();
        List<WorkflowCandidate> merged = new ArrayList<>();
        Set<String> consumed = new HashSet<>();

        for (int i = 0; i < candidates.size(); i++) {
            if (consumed.contains(candidates.get(i).getId())) continue;

            WorkflowCandidate a = candidates.get(i);
            boolean anyMerge = false;

            for (int j = i + 1; j < candidates.size(); j++) {
                if (consumed.contains(candidates.get(j).getId())) continue;
                WorkflowCandidate b = candidates.get(j);

                if (shouldMerge(a, b, graph, detector, sessionWindowMs)) {
                    // Merge b into a
                    for (RequestNode step : b.getSteps()) {
                        a.addStep(step);
                    }
                    // Carry over evidence
                    if (a.getEvidence() != null && b.getEvidence() != null) {
                        for (String signal : b.getEvidence().getContinuationSignals()) {
                            a.getEvidence().addContinuationSignal("merged: " + signal);
                        }
                    }
                    // Re-sort steps by timestamp
                    List<RequestNode> sortedSteps = new ArrayList<>(a.getSteps());
                    sortedSteps.sort(Comparator.comparingLong(RequestNode::getTimestamp));
                    // Clear and re-add in order
                    a.getSteps().clear();
                    for (RequestNode step : sortedSteps) {
                        a.addStep(step);
                    }
                    consumed.add(b.getId());
                    anyMerge = true;

                    logger.log(LogCategory.GRAPH, LogLevel.INFO, "WorkflowDetector",
                            "Merged candidate " + b.getId() + " into " + a.getId()
                                    + " (strong cross-candidate edges)");
                }
            }

            if (!consumed.contains(a.getId())) {
                merged.add(a);
                consumed.add(a.getId());
            }
        }

        return merged;
    }

    /**
     * Check if candidate B should be merged into candidate A.
     */
    private boolean shouldMerge(WorkflowCandidate a, WorkflowCandidate b,
                                 RequestGraph graph,
                                 RelationshipDetector detector,
                                 long sessionWindowMs) {
        // Same host
        String hostA = firstHost(a);
        String hostB = firstHost(b);
        if (hostA == null || hostB == null || !hostA.equalsIgnoreCase(hostB)) return false;

        // Compatible session keys
        if (!sessionsCompatible(a.getSessionKey(), b.getSessionKey())) return false;

        // A before B chronologically
        long aLastTs = a.getLastStep() != null ? a.getLastStep().getTimestamp() : 0;
        long bFirstTs = b.getSteps().isEmpty() ? 0 : b.getSteps().get(0).getTimestamp();
        if (aLastTs >= bFirstTs) return false;

        // Gap between A's last and B's first <= session window
        long gap = bFirstTs - aLastTs;
        if (gap > sessionWindowMs) return false;

        // Find strong cross-candidate edges of relevant types
        for (RequestNode sourceNode : a.getSteps()) {
            for (RequestNode targetNode : b.getSteps()) {
                List<RequestEdge> between = findEdgesBetween(graph, sourceNode, targetNode);
                for (RequestEdge edge : between) {
                    EdgeStrength strength = detector.getEdgeStrength(edge, sourceNode, targetNode);
                    if (strength == EdgeStrength.STRONG) {
                        EdgeType type = edge.getType();
                        if (type == EdgeType.PARAM_REUSE
                                || type == EdgeType.REDIRECT
                                || type == EdgeType.USER_DEFINED) {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    /**
     * Check if two session keys are compatible for merging.
     * They merge if they share the same host and auth hash.
     * Casts to SessionKey and uses typed accessors — never parses toString().
     */
    private boolean sessionsCompatible(SessionKey keyA, SessionKey keyB) {
        if (keyA == null || keyB == null) return false;

        // Must share the same host
        if (!keyA.getHost().equalsIgnoreCase(keyB.getHost())) return false;

        String authA = keyA.getAuthCookieHash();
        String authB = keyB.getAuthCookieHash();

        // Both have auth — must match exactly
        if (!authA.isEmpty() && !authB.isEmpty()) {
            return authA.equals(authB);
        }

        // One or both lack auth — allow merge (edge strength provides the signal)
        return true;
    }

    private String firstHost(WorkflowCandidate c) {
        if (c.getSteps().isEmpty()) return null;
        return c.getSteps().get(0).getHost();
    }

    /**
     * Attach supporting edges from the graph to a candidate.
     * Examines all pairs of steps within the candidate and attaches
     * edges where EdgeStrength is STRONG or MEDIUM.
     */
    private void attachSupportingEdges(WorkflowCandidate candidate,
                                        RequestGraph graph,
                                        RelationshipDetector detector) {
        List<RequestNode> steps = candidate.getSteps();
        if (steps == null || steps.size() < 2) return;

        Set<String> stepIds = steps.stream()
                .map(RequestNode::getId)
                .collect(Collectors.toSet());
        Set<String> addedEdgeKeys = new HashSet<>();

        for (int i = 0; i < steps.size(); i++) {
            for (int j = i + 1; j < steps.size(); j++) {
                RequestNode source = steps.get(i);
                RequestNode target = steps.get(j);
                List<RequestEdge> betweenEdges = findEdgesBetween(graph, source, target);

                for (RequestEdge edge : betweenEdges) {
                    // Use a composite key to avoid duplicate edges
                    String edgeKey = edge.getSourceNodeId() + "->" + edge.getTargetNodeId() + ":" + edge.getType();
                    if (!addedEdgeKeys.add(edgeKey)) continue;

                    EdgeStrength strength = detector.getEdgeStrength(edge, source, target);
                    if (strength == EdgeStrength.STRONG || strength == EdgeStrength.MEDIUM) {
                        candidate.addEdge(edge);
                        // Populate evidence
                        if (candidate.getEvidence() != null) {
                            candidate.getEvidence().addContinuationSignal(
                                    "edge:" + edge.getType() + ":" + strength
                                            + " " + truncate(edge.getEvidence(), 80));
                        }
                    }
                }
            }
        }

        if (!candidate.getSupportingEdges().isEmpty()) {
            logger.log(LogCategory.GRAPH, LogLevel.DEBUG, "WorkflowDetector",
                    "Attached " + candidate.getSupportingEdges().size()
                            + " supporting edges to candidate " + candidate.getId());
        }
    }

    /**
     * Find all edges between two nodes in the graph (either direction).
     */
    private List<RequestEdge> findEdgesBetween(RequestGraph graph,
                                                RequestNode nodeA,
                                                RequestNode nodeB) {
        List<RequestEdge> result = new ArrayList<>();
        for (RequestEdge edge : graph.getEdgesForNode(nodeA.getId())) {
            if (edge.getSourceNodeId().equals(nodeB.getId())
                    || edge.getTargetNodeId().equals(nodeB.getId())) {
                result.add(edge);
            }
        }
        for (RequestEdge edge : graph.getEdgesForNode(nodeB.getId())) {
            if (!result.contains(edge)
                    && (edge.getSourceNodeId().equals(nodeA.getId())
                    || edge.getTargetNodeId().equals(nodeA.getId()))) {
                result.add(edge);
            }
        }
        return result;
    }

    private String truncate(String s, int maxLen) {
        if (s == null) return "";
        return s.length() <= maxLen ? s : s.substring(0, maxLen) + "...";
    }

    /**
     * Session-only detection: filter by workflow relevance, segment by session,
     * score, prioritize. No edge attachment.
     * Uses stateless full-graph segmentation — safe for UI/analysis threads.
     *
     * This method publishes candidate events via listeners.
     * For read-only preview (no side effects), use {@link #previewCandidates(List)}.
     */
    public List<WorkflowCandidate> detectSessionOnly(List<RequestNode> allNodes) {
        if (allNodes == null || allNodes.isEmpty()) return List.of();

        double analysisThreshold = config.getWorkflowScoreThreshold();
        double displayThreshold = config.getWorkflowCandidateThreshold();

        // 1. Filter to workflow-relevant nodes only
        List<RequestNode> relevantNodes = new ArrayList<>();
        int suppressedCount = 0;

        for (RequestNode node : allNodes) {
            RequestClassification cls = node.getClassification();
            if (cls != null && cls.isWorkflowRelevant()) {
                relevantNodes.add(node);
            } else {
                suppressedCount++;
            }
        }

        logger.log(LogCategory.GRAPH, LogLevel.INFO, "WorkflowDetector",
                "Filtering graph: " + allNodes.size() + " total nodes, "
                        + relevantNodes.size() + " workflow-relevant, "
                        + suppressedCount + " suppressed");

        // 2. Segment by session into candidates (stateless full-graph mode)
        List<WorkflowCandidate> candidates = WorkflowSessionizer.segmentFullGraph(
                relevantNodes, config, logger);

        if (candidates.isEmpty()) {
            logger.log(LogCategory.GRAPH, LogLevel.INFO, "WorkflowDetector",
                    "No workflow candidates detected.");
            return List.of();
        }

        // 3. Score each candidate
        for (WorkflowCandidate candidate : candidates) {
            double score = scorer.score(candidate);
            candidate.setWorkflowScore(score);

            logger.log(LogCategory.GRAPH, LogLevel.DEBUG, "WorkflowDetector",
                    "Candidate " + candidate.getId() + ": score=" + score
                            + " type=" + candidate.getWorkflowType()
                            + " steps=" + candidate.size()
                            + " (" + candidate.getStartReason() + ")");
        }

        // 4. Prioritize by score
        List<WorkflowCandidate> prioritized = scorer.prioritize(candidates);

        // 5. Log summary
        long aboveThreshold = prioritized.stream()
                .filter(c -> c.getWorkflowScore() >= analysisThreshold)
                .count();
        long displayOnly = prioritized.stream()
                .filter(c -> c.getWorkflowScore() >= displayThreshold
                        && c.getWorkflowScore() < analysisThreshold)
                .count();

        logger.log(LogCategory.GRAPH, LogLevel.INFO, "WorkflowDetector",
                "Detected " + prioritized.size() + " candidates: "
                        + aboveThreshold + " ready for LLM, "
                        + displayOnly + " display-only, "
                        + (prioritized.size() - aboveThreshold - displayOnly) + " low-score");

        // 6. Notify listeners for each new candidate
        for (WorkflowCandidate candidate : prioritized) {
            if (candidate.getWorkflowScore() >= displayThreshold) {
                for (Consumer<WorkflowCandidate> listener : candidateListeners) {
                    try { listener.accept(candidate); } catch (Exception ignored) {}
                }
            }
        }

        lastResults = prioritized;
        return prioritized;
    }

    /**
     * Get only candidates that score above the LLM analysis threshold.
     */
    public List<WorkflowCandidate> getAnalysisReadyCandidates() {
        double analysisThreshold = config.getWorkflowScoreThreshold();
        return lastResults.stream()
                .filter(c -> c.getWorkflowScore() >= analysisThreshold)
                .toList();
    }

    /**
     * Get only candidates that score above the display threshold but below analysis.
     */
    public List<WorkflowCandidate> getDisplayOnlyCandidates() {
        double analysisThreshold = config.getWorkflowScoreThreshold();
        double displayThreshold = config.getWorkflowCandidateThreshold();
        return lastResults.stream()
                .filter(c -> c.getWorkflowScore() >= displayThreshold
                        && c.getWorkflowScore() < analysisThreshold)
                .toList();
    }

    public void addCandidateListener(Consumer<WorkflowCandidate> listener) {
        candidateListeners.add(listener);
    }

    public void clear() {
        sessionizer.clear();
        lastResults.clear();
    }

    public WorkflowSessionizer getSessionizer() { return sessionizer; }
    public WorkflowScorer getScorer() { return scorer; }
    public List<WorkflowCandidate> getLastResults() { return lastResults; }
}

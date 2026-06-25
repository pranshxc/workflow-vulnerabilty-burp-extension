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
import java.util.concurrent.ConcurrentHashMap;
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

    // Live candidate metrics updated by BOTH preview and full-detect
    // paths. The status panel reads this; it should never be stale
    // simply because the user looked at the chain list before a full
    // analysis run.
    private volatile int liveCandidateCount = 0;
    private volatile int liveEdgeSupportedCount = 0;
    private volatile int liveSessionOnlyCount = 0;
    private volatile int liveAnalysisReadyCount = 0;
    private volatile int liveDisplayOnlyCount = 0;
    // The "confirmed" and "probable" counters reflect the strict /
    // loose proof counts on the most recent validation run. They are
    // updated by the validation engine via
    // {@link #setLiveValidationCounts(int, int)}.
    private volatile int liveConfirmedCount = 0;
    private volatile int liveProbableCount = 0;

    // De-duplication: when the same candidate is observed across multiple
    // detection runs, listeners should not be invoked again. The fingerprint
    // covers step order (via ChainVerdict.generateFingerprint), the
    // detected workflow type, and the score (rounded to a stable bucket
    // so a small score drift does not produce a fresh event).
    private final Set<String> publishedCandidateFingerprints = ConcurrentHashMap.newKeySet();

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
     * Edge-aware read-only preview of candidates.
     * <p>
     * Runs the same pipeline as the analysis path — workflow-relevant filter,
     * session segmentation, strong-edge cross-candidate merge, supporting-edge
     * attachment, and scoring — but does NOT update lastResults and does NOT
     * fire candidate listeners. This guarantees UI parity: the candidate list
     * shown in the graph panel is the same shape and score as the list that
     * the analysis engine would produce, without any double-counting or
     * duplicate listener events.
     * <p>
     * Safe to call from the UI refresh thread.
     *
     * @param allNodes all graph nodes
     * @return edge-aware, scored, prioritized candidates
     */
    public List<WorkflowCandidate> previewCandidates(List<RequestNode> allNodes) {
        if (allNodes == null || allNodes.isEmpty()) {
            updateLiveMetrics(List.of());
            return List.of();
        }
        List<WorkflowCandidate> result;
        if (graph == null || relationshipDetector == null) {
            // Fall back to session-only if graph context has not been wired
            result = detectSessionOnlyInternal(allNodes, false, false);
        } else {
            result = detectInternal(allNodes, graph, relationshipDetector, true, false, false);
        }
        updateLiveMetrics(result);
        return result;
    }

    /**
     * Backwards-compatible preview overload. With the new edge-aware preview
     * above, the `score` flag is always honoured as part of the pipeline; the
     * parameter is kept only for source-compat.
     *
     * @deprecated prefer {@link #previewCandidates(List)}; the new method is
     *             always edge-aware and always scored.
     */
    @Deprecated
    public List<WorkflowCandidate> previewCandidates(List<RequestNode> allNodes, boolean score) {
        return previewCandidates(allNodes);
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
     * Preferred over {@link #detectSessionOnly(List)} as it uses graph structure
     * (PARAM_REUSE, REDIRECT, REFERRER, RESPONSE_CORRELATION edges) to
     * strengthen candidate evidence and scoring.
     * Falls back to the session-only mode if graph context is not set.
     *
     * @param allNodes all graph nodes
     * @return sorted list of workflow candidates (highest score first)
     */
    public List<WorkflowCandidate> detect(List<RequestNode> allNodes) {
        List<WorkflowCandidate> result;
        if (graph != null && relationshipDetector != null) {
            result = detectInternal(allNodes, graph, relationshipDetector,
                    true, true, true);
        } else {
            // Fallback: session-only detection without edge attachment
            result = detectSessionOnlyInternal(allNodes, true, true);
        }
        updateLiveMetrics(result);
        return result;
    }

    /**
     * Detect workflow candidates with explicit graph references. Equivalent
     * to {@link #detect(List)} but does not depend on the graph context
     * having been wired via {@link #setGraphContext(RequestGraph, RelationshipDetector)}.
     */
    public List<WorkflowCandidate> detect(List<RequestNode> allNodes,
                                           RequestGraph graph,
                                           RelationshipDetector detector) {
        if (allNodes == null || allNodes.isEmpty()) return List.of();
        return detectInternal(allNodes, graph, detector, true, true, true);
    }

    /**
     * Shared detection pipeline used by both the analysis path and the UI
     * preview. The flag trio lets callers control which side effects fire:
     *
     * <ul>
     *   <li><b>edgeAware</b> — run strong-edge candidate merge and supporting
     *       edge attachment. When false the pipeline is session-only.</li>
     *   <li><b>publish</b> — invoke registered candidate listeners for
     *       display-worthy candidates (after de-duplication).</li>
     *   <li><b>updateLastResults</b> — overwrite the detector's lastResults
     *       field with the produced list. The UI preview passes false so
     *       analysis status indicators stay in sync with the last full run.</li>
     * </ul>
     */
    private List<WorkflowCandidate> detectInternal(List<RequestNode> allNodes,
                                                    RequestGraph graph,
                                                    RelationshipDetector detector,
                                                    boolean edgeAware,
                                                    boolean publish,
                                                    boolean updateLastResults) {
        if (allNodes == null || allNodes.isEmpty()) return List.of();

        if (!edgeAware) {
            return detectSessionOnlyInternal(allNodes, publish, updateLastResults);
        }

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

        // 8. Build derived workflow-sequence edges between consecutive
        // steps in each candidate. This gives the graph a usable
        // structure even when RelationshipDetector found no explicit
        // relationship edges. The edges are tagged
        // EdgeType.WORKFLOW_SEQUENCE so the status panel and the
        // scorer can separate them from "real" relationship edges.
        for (WorkflowCandidate candidate : prioritized) {
            buildWorkflowSequenceEdges(candidate, graph);
        }

        logger.log(LogCategory.GRAPH, LogLevel.INFO, "WorkflowDetector",
                "Edge-aware detection: " + prioritized.size()
                        + " candidates (merged from " + segmented.size()
                        + " session candidates) with supporting edges.");

        if (publish) publishCandidates(prioritized);
        if (updateLastResults) lastResults = prioritized;
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

        // Find strong cross-candidate edges of relevant types.
        // Direction must flow forward: A (earlier) -> B (later). The
        // directional helper makes that explicit; USER_DEFINED edges
        // are an exception and still get a chance via
        // edgeDirectionValidForWorkflow.
        for (RequestNode sourceNode : a.getSteps()) {
            for (RequestNode targetNode : b.getSteps()) {
                // Step 1: forward flow-implying edges (PARAM_REUSE, REDIRECT,
                // RESPONSE_CORRELATION) come from the directional helper.
                for (RequestEdge edge : findForwardEdges(graph, sourceNode, targetNode)) {
                    if (!edgeDirectionValidForWorkflow(edge, sourceNode, targetNode)) continue;
                    EdgeStrength strength = detector.getEdgeStrength(edge, sourceNode, targetNode);
                    if (strength == EdgeStrength.STRONG) {
                        EdgeType type = edge.getType();
                        if (type == EdgeType.PARAM_REUSE
                                || type == EdgeType.REDIRECT
                                || type == EdgeType.RESPONSE_CORRELATION) {
                            return true;
                        }
                    }
                }
                // Step 2: USER_DEFINED edges are undirected; check the
                // full bidirectional set and let edgeDirectionValidForWorkflow
                // accept either direction.
                for (RequestEdge edge : findEdgesBetween(graph, sourceNode, targetNode)) {
                    if (edge.getType() != EdgeType.USER_DEFINED) continue;
                    if (!edgeDirectionValidForWorkflow(edge, sourceNode, targetNode)) continue;
                    EdgeStrength strength = detector.getEdgeStrength(edge, sourceNode, targetNode);
                    if (strength == EdgeStrength.STRONG) return true;
                }
            }
        }

        return false;
    }

    /**
     * Check that an edge's source -> target direction matches the workflow's
     * earlier -> later flow. USER_DEFINED edges are allowed undirected because
     * the user manually grouped them. All flow-implying edge types must be
     * forward-only: PARAM_REUSE, REDIRECT, RESPONSE_CORRELATION, REFERRER.
     */
    private boolean edgeDirectionValidForWorkflow(RequestEdge edge,
                                                  RequestNode earlier,
                                                  RequestNode later) {
        if (edge == null || earlier == null || later == null) return false;
        EdgeType type = edge.getType();
        // USER_DEFINED edges are user-grouped; direction is irrelevant.
        if (type == EdgeType.USER_DEFINED) return true;
        // For all other flow-implying types, the source must be the earlier
        // node and the target must be the later node.
        return edge.getSourceNodeId().equals(earlier.getId())
                && edge.getTargetNodeId().equals(later.getId());
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

                // Step 1: forward flow-implying edges via the directional
                // helper. Direction intent is explicit at the call site.
                for (RequestEdge edge : findForwardEdges(graph, source, target)) {
                    if (edge.getType() == EdgeType.USER_DEFINED) continue;
                    String edgeKey = edge.getSourceNodeId() + "->" + edge.getTargetNodeId() + ":" + edge.getType();
                    if (!addedEdgeKeys.add(edgeKey)) continue;
                    EdgeStrength strength = detector.getEdgeStrength(edge, source, target);
                    if (strength == EdgeStrength.STRONG || strength == EdgeStrength.MEDIUM) {
                        candidate.addEdge(edge);
                        if (candidate.getEvidence() != null) {
                            candidate.getEvidence().addContinuationSignal(
                                    "edge:" + edge.getType() + ":" + strength
                                            + " " + truncate(edge.getEvidence(), 80));
                        }
                    }
                }
                // Step 2: USER_DEFINED edges are undirected; pick up either
                // direction so user-grouped steps still receive evidence.
                for (RequestEdge edge : findEdgesBetween(graph, source, target)) {
                    if (edge.getType() != EdgeType.USER_DEFINED) continue;
                    String edgeKey = edge.getSourceNodeId() + "->" + edge.getTargetNodeId() + ":" + edge.getType();
                    if (!addedEdgeKeys.add(edgeKey)) continue;
                    EdgeStrength strength = detector.getEdgeStrength(edge, source, target);
                    if (strength == EdgeStrength.STRONG || strength == EdgeStrength.MEDIUM) {
                        candidate.addEdge(edge);
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
     * Kept for callers that genuinely want bidirectional lookup; the merge
     * and supporting-edge code prefer {@link #findForwardEdges} to make
     * the direction intent explicit.
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

    /**
     * Find edges from {@code source} to {@code target} (forward only).
     * This is the directional helper used by the workflow merge and
     * supporting-edge logic. Using it instead of
     * {@link #findEdgesBetween} makes the direction intent explicit in
     * the call site and removes the need for a post-filter pass.
     */
    private List<RequestEdge> findForwardEdges(RequestGraph graph,
                                                RequestNode source,
                                                RequestNode target) {
        if (source == null || target == null) return List.of();
        List<RequestEdge> result = new ArrayList<>();
        for (RequestEdge edge : graph.getEdgesForNode(source.getId())) {
            if (edge.getTargetNodeId().equals(target.getId())) {
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
     * This method publishes candidate events via listeners and updates
     * lastResults. For a read-only preview with no side effects, use
     * {@link #previewCandidates(List)}.
     */
    public List<WorkflowCandidate> detectSessionOnly(List<RequestNode> allNodes) {
        if (allNodes == null || allNodes.isEmpty()) {
            updateLiveMetrics(List.of());
            return List.of();
        }
        List<WorkflowCandidate> result = detectSessionOnlyInternal(allNodes, true, true);
        updateLiveMetrics(result);
        return result;
    }

    /**
     * Internal session-only pipeline. Flag-controlled like {@link #detectInternal}.
     */
    private List<WorkflowCandidate> detectSessionOnlyInternal(List<RequestNode> allNodes,
                                                                boolean publish,
                                                                boolean updateLastResults) {
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

        // 4a. Build derived workflow-sequence edges between
        // consecutive steps in each candidate. The same code path
        // is used by the edge-aware detector so the graph shows
        // useful structure for session-only candidates too.
        if (graph != null) {
            for (WorkflowCandidate candidate : prioritized) {
                buildWorkflowSequenceEdges(candidate, graph);
            }
        }

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

        if (publish) publishCandidates(prioritized);
        if (updateLastResults) lastResults = prioritized;
        return prioritized;
    }

    /**
     * Build derived {@code WORKFLOW_SEQUENCE} edges between
     * consecutive steps in a workflow candidate and add them to
     * the graph. The edges are tagged separately from
     * RelationshipDetector's output so the status panel and
     * scorer can keep "real" relationships and "structural"
     * workflow sequence edges distinct.
     *
     * <p>Confidence is derived from the candidate's score
     * (capped at 0.55-0.75) — these are derived edges, not
     * strong object-flow evidence. We do not boost the candidate
     * score for them (see {@code WorkflowScorer.scoreObjectFlows}).
     *
     * <p>Duplicates are dropped via {@link RequestGraph#hasEdge}
     * so re-running the detector (preview or full) does not
     * produce duplicate sequence edges.
     */
    private void buildWorkflowSequenceEdges(WorkflowCandidate candidate,
                                            RequestGraph graph) {
        if (candidate == null || graph == null) return;
        List<RequestNode> steps = candidate.getSteps();
        if (steps == null || steps.size() < 2) return;

        // Confidence from candidate score, clamped to a derived-edge
        // range. We never go below 0.55 (so a low-score candidate
        // still has a meaningful chain) and never above 0.75 (so
        // derived edges never masquerade as strong object-flow).
        double score = candidate.getWorkflowScore();
        double confidence = Math.min(0.75, Math.max(0.55, score / 100.0));
        String evidencePrefix = "Consecutive workflow candidate steps: candidate="
                + candidate.getId() + ", type=" + candidate.getWorkflowType()
                + ", score=" + String.format("%.1f", score);

        int added = 0;
        for (int i = 0; i < steps.size() - 1; i++) {
            RequestNode a = steps.get(i);
            RequestNode b = steps.get(i + 1);
            if (a == null || b == null) continue;
            String sourceId = a.getId();
            String targetId = b.getId();
            if (sourceId == null || targetId == null) continue;
            // Skip self-loops (should not happen, but defensive).
            if (sourceId.equals(targetId)) continue;
            // Dedup: don't add a sequence edge if we already have one.
            if (graph.hasEdge(sourceId, targetId, EdgeType.WORKFLOW_SEQUENCE)) {
                continue;
            }
            RequestEdge edge = new RequestEdge(
                    sourceId, targetId,
                    EdgeType.WORKFLOW_SEQUENCE, confidence,
                    evidencePrefix);
            graph.addEdge(edge);
            added++;
        }
        if (added > 0) {
            logger.log(LogCategory.GRAPH, LogLevel.DEBUG, "WorkflowDetector",
                    "Built " + added + " WORKFLOW_SEQUENCE edges for candidate "
                            + candidate.getId() + " (score=" + String.format("%.1f", score)
                            + ")");
        }
    }

    /**
     * Publish display-worthy candidates to all registered listeners.
     * Shared by both edge-aware and session-only detection paths so that
     * listener behavior is consistent regardless of which detector is used.
     * <p>
     * Candidates are de-duplicated by a stable fingerprint covering step
     * order, workflow type, and score bucket. Without this, repeated full
     * detection runs (e.g. on every graph update with auto-analysis enabled)
     * would re-fire the same listener events for candidates that have not
     * actually changed. The fingerprint set is reset on {@link #clear()}.
     */
    private void publishCandidates(List<WorkflowCandidate> candidates) {
        if (candidates == null || candidates.isEmpty()) return;
        double displayThreshold = config.getWorkflowCandidateThreshold();
        for (WorkflowCandidate candidate : candidates) {
            if (candidate.getWorkflowScore() < displayThreshold) continue;
            String fp = candidateFingerprint(candidate);
            if (!publishedCandidateFingerprints.add(fp)) continue;
            for (Consumer<WorkflowCandidate> listener : candidateListeners) {
                try { listener.accept(candidate); } catch (Exception ignored) {}
            }
        }
    }

    /**
     * Build a stable fingerprint for a candidate based on its step order,
     * detected workflow type, and a rounded score bucket. Step order is the
     * primary signal: the same steps in the same order with the same type
     * produce the same fingerprint even if internal IDs change.
     */
    private String candidateFingerprint(WorkflowCandidate candidate) {
        StringBuilder sb = new StringBuilder();
        for (RequestNode step : candidate.getSteps()) {
            sb.append(step.getMethod() != null ? step.getMethod() : "?")
                    .append(':')
                    .append(step.getPath() != null ? step.getPath() : "?")
                    .append('@')
                    .append(step.getTimestamp())
                    .append('|');
        }
        sb.append("type=").append(candidate.getWorkflowType());
        sb.append("|score=").append(Math.round(candidate.getWorkflowScore()));
        return sb.toString();
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

    /**
     * Count of candidates with at least one supporting edge. A candidate
     * is "edge supported" when {@code attachSupportingEdges} ran and
     * found at least one edge connecting two of its steps. This is the
     * strong-evidence subset — these candidates have concrete graph
     * evidence that the steps are related, not just session co-occurrence.
     */
    public int getEdgeSupportedCandidateCount() {
        int count = 0;
        for (WorkflowCandidate c : lastResults) {
            if (c.getSupportingEdges() != null && !c.getSupportingEdges().isEmpty()) {
                count++;
            }
        }
        return count;
    }

    /**
     * Count of candidates with no supporting edges. These are produced
     * solely from session/boundary/method-path heuristic. They are
     * still valid candidates, but the lack of edges is worth knowing
     * about — it is the precise reason a candidate can exist when
     * {@code graph_edges == 0}.
     */
    public int getSessionOnlyCandidateCount() {
        int count = 0;
        for (WorkflowCandidate c : lastResults) {
            if (c.getSupportingEdges() == null || c.getSupportingEdges().isEmpty()) {
                count++;
            }
        }
        return count;
    }

    /**
     * Live candidate count, updated by BOTH {@link #previewCandidates}
     * and {@link #detect}. Use this in the status panel so the
     * "edges=0 but candidates>0" diagnostic remains accurate when
     * the user is looking at the chain list (preview path) rather
     * than waiting for a full analysis run.
     */
    public int getLiveCandidateCount() { return liveCandidateCount; }

    /**
     * Live edge-supported candidate count, updated alongside
     * {@link #getLiveCandidateCount()}.
     */
    public int getLiveEdgeSupportedCount() { return liveEdgeSupportedCount; }

    /**
     * Live session-only candidate count, updated alongside
     * {@link #getLiveCandidateCount()}.
     */
    public int getLiveSessionOnlyCount() { return liveSessionOnlyCount; }

    /**
     * Live analysis-ready candidate count (score &gt;= analysis
     * threshold), updated alongside {@link #getLiveCandidateCount()}.
     */
    public int getLiveAnalysisReadyCount() { return liveAnalysisReadyCount; }

    /**
     * Live display-only candidate count (display threshold &lt;= score
     * &lt; analysis threshold), updated alongside
     * {@link #getLiveCandidateCount()}.
     */
    public int getLiveDisplayOnlyCount() { return liveDisplayOnlyCount; }

    /**
     * Live count of strictly-confirmed validation results across the
     * most recent validation run. Updated by the validation engine
     * via {@link #setLiveValidationCounts(int, int)}.
     */
    public int getLiveConfirmedCount() { return liveConfirmedCount; }

    /**
     * Live count of probable validation results (strict proof not
     * observed). Updated by the validation engine.
     */
    public int getLiveProbableCount() { return liveProbableCount; }

    /**
     * Set the latest confirmed / probable validation counts. Called
     * by the validation engine after each run so the status panel
     * can show how many findings are strict vs needing review.
     */
    public void setLiveValidationCounts(int confirmed, int probable) {
        this.liveConfirmedCount = Math.max(0, confirmed);
        this.liveProbableCount = Math.max(0, probable);
    }

    /**
     * Recompute and cache the live counters from a candidate list.
     * Called by both preview and full-detect paths.
     */
    private void updateLiveMetrics(List<WorkflowCandidate> candidates) {
        int total = candidates.size();
        int edge = 0;
        int ready = 0;
        double analysisThreshold = config.getWorkflowScoreThreshold();
        for (WorkflowCandidate c : candidates) {
            if (c.getSupportingEdges() != null && !c.getSupportingEdges().isEmpty()) {
                edge++;
            }
            if (c.getWorkflowScore() >= analysisThreshold) {
                ready++;
            }
        }
        this.liveCandidateCount = total;
        this.liveEdgeSupportedCount = edge;
        this.liveSessionOnlyCount = total - edge;
        this.liveAnalysisReadyCount = ready;
        this.liveDisplayOnlyCount = total - ready;
    }

    public void addCandidateListener(Consumer<WorkflowCandidate> listener) {
        candidateListeners.add(listener);
    }

    public void clear() {
        sessionizer.clear();
        lastResults.clear();
        publishedCandidateFingerprints.clear();
        liveCandidateCount = 0;
        liveEdgeSupportedCount = 0;
        liveSessionOnlyCount = 0;
        liveAnalysisReadyCount = 0;
        liveDisplayOnlyCount = 0;
        liveConfirmedCount = 0;
        liveProbableCount = 0;
    }

    public WorkflowSessionizer getSessionizer() { return sessionizer; }
    public WorkflowScorer getScorer() { return scorer; }
    public List<WorkflowCandidate> getLastResults() { return lastResults; }
}

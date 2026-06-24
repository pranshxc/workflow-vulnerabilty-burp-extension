package com.workflowscanner.workflow;

import com.workflowscanner.classification.RequestClassification;
import com.workflowscanner.graph.RequestNode;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.function.Consumer;

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
    private final ExtensionLogger logger;
    private final List<Consumer<WorkflowCandidate>> candidateListeners = new ArrayList<>();
    private List<WorkflowCandidate> lastResults = new ArrayList<>();

    public WorkflowDetector(ExtensionLogger logger) {
        this.sessionizer = new WorkflowSessionizer(logger);
        this.scorer = new WorkflowScorer();
        this.logger = logger;
    }

    /**
     * Detect workflow candidates from a list of graph nodes.
     */
    public List<WorkflowCandidate> detect(List<RequestNode> allNodes) {
        if (allNodes == null || allNodes.isEmpty()) return List.of();

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

        // 2. Segment by session into candidates
        List<WorkflowCandidate> candidates = sessionizer.segment(relevantNodes);

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
                .filter(c -> c.getWorkflowScore() >= WorkflowScorer.ANALYSIS_THRESHOLD)
                .count();
        long displayOnly = prioritized.stream()
                .filter(c -> c.getWorkflowScore() >= WorkflowScorer.DISPLAY_THRESHOLD
                        && c.getWorkflowScore() < WorkflowScorer.ANALYSIS_THRESHOLD)
                .count();

        logger.log(LogCategory.GRAPH, LogLevel.INFO, "WorkflowDetector",
                "Detected " + prioritized.size() + " candidates: "
                        + aboveThreshold + " ready for LLM, "
                        + displayOnly + " display-only, "
                        + (prioritized.size() - aboveThreshold - displayOnly) + " low-score");

        // 6. Notify listeners for each new candidate
        for (WorkflowCandidate candidate : prioritized) {
            if (candidate.getWorkflowScore() >= WorkflowScorer.DISPLAY_THRESHOLD) {
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
        return lastResults.stream()
                .filter(c -> c.getWorkflowScore() >= WorkflowScorer.ANALYSIS_THRESHOLD)
                .toList();
    }

    /**
     * Get only candidates that score above the display threshold but below analysis.
     */
    public List<WorkflowCandidate> getDisplayOnlyCandidates() {
        return lastResults.stream()
                .filter(c -> c.getWorkflowScore() >= WorkflowScorer.DISPLAY_THRESHOLD
                        && c.getWorkflowScore() < WorkflowScorer.ANALYSIS_THRESHOLD)
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

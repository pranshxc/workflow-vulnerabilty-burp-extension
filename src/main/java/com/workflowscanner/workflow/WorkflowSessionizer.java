package com.workflowscanner.workflow;

import com.workflowscanner.graph.RequestNode;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Groups workflow-relevant request nodes by session key, detecting boundaries
 * and emitting completed WorkflowCandidates.
 *
 * Reads chronological nodes (filtered by RequestClassifier), groups by SessionKey,
 * and emits candidates when boundary end signals or idle timeout triggers.
 */
public class WorkflowSessionizer {

    private final WorkflowBoundaryDetector boundaryDetector;
    private final ExtensionLogger logger;
    private final Map<SessionKey, WorkflowCandidate> activeWorkflows;
    private final List<WorkflowCandidate> emittedCandidates;
    private long lastActivityTime = System.currentTimeMillis();

    // Maximum idle time before closing an inactive candidate
    private static final long MAX_IDLE_MS = 30_000;

    public WorkflowSessionizer(ExtensionLogger logger) {
        this.boundaryDetector = new WorkflowBoundaryDetector();
        this.logger = logger;
        this.activeWorkflows = new ConcurrentHashMap<>();
        this.emittedCandidates = new ArrayList<>();
    }

    /**
     * Segment a list of chronological nodes into workflow candidates.
     * Should be called with nodes already filtered for workflow relevance.
     */
    public List<WorkflowCandidate> segment(List<RequestNode> nodes) {
        List<WorkflowCandidate> newCandidates = new ArrayList<>();

        // Sort by timestamp
        nodes.sort(Comparator.comparingLong(RequestNode::getTimestamp));

        for (RequestNode node : nodes) {
            SessionKey key = buildSessionKey(node);
            lastActivityTime = System.currentTimeMillis();

            WorkflowCandidate active = activeWorkflows.get(key);

            // Check for boundary reset or new workflow start
            if (active == null || boundaryDetector.isBoundaryReset(
                    active.getLastStep(), node)) {

                // Close existing workflow if present
                if (active != null) {
                    closeCandidate(active);
                    newCandidates.add(active);
                }

                // Start new workflow
                active = new WorkflowCandidate(key);
                active.setStartReason(boundaryDetector.startsWorkflow(node)
                        ? "Start signal: " + node.getMethod() + " " + node.getPath()
                        : "New session/context");
                active.addStep(node);
                activeWorkflows.put(key, active);

                logger.log(LogCategory.GRAPH, LogLevel.DEBUG, "WorkflowSessionizer",
                        "New workflow started: " + key + " [" + node.getMethod() + " " + node.getPath() + "]");
            } else {
                // Continue existing workflow
                if (boundaryDetector.continuesWorkflow(active.getLastStep(), node)) {
                    active.addStep(node);

                    // Check for end signal
                    if (boundaryDetector.endsWorkflow(node)) {
                        active.setEndReason("End signal: " + node.getMethod() + " " + node.getPath());
                        closeCandidate(active);
                        newCandidates.add(active);
                        activeWorkflows.remove(key);
                    }
                } else {
                    // Can't connect to active workflow — could start new one
                    // But check if it belongs to a different context first
                    // For now, add as step (boundary detector was already lenient)
                    active.addStep(node);
                }
            }
        }

        // Emit any remaining active workflows that have been idle too long
        long now = System.currentTimeMillis();
        List<SessionKey> staleKeys = new ArrayList<>();
        for (Map.Entry<SessionKey, WorkflowCandidate> entry : activeWorkflows.entrySet()) {
            WorkflowCandidate candidate = entry.getValue();
            if (candidate.size() >= 2 && (now - candidate.getEndTime() > MAX_IDLE_MS)) {
                candidate.setEndReason("Idle timeout");
                closeCandidate(candidate);
                newCandidates.add(candidate);
                staleKeys.add(entry.getKey());
            }
        }
        staleKeys.forEach(activeWorkflows::remove);

        emittedCandidates.addAll(newCandidates);
        return newCandidates;
    }

    /**
     * Build a SessionKey from a request node.
     */
    private SessionKey buildSessionKey(RequestNode node) {
        String host = node.getHost() != null ? node.getHost() : "";
        // Use groupId as session distinguisher if available (context menu groups)
        String authHash = node.getGroupId() != null ? node.getGroupId() : "";
        // Use the request's referrer as additional segmentation
        String referrerPath = "";
        if (node.getRequest() != null && node.getRequest().getReferrer() != null) {
            referrerPath = node.getRequest().getReferrer();
        }
        return new SessionKey(host, authHash, referrerPath);
    }

    private void closeCandidate(WorkflowCandidate candidate) {
        if (candidate.size() < 2) return; // Don't emit single-node candidates

        // Detect workflow type
        candidate.setWorkflowType(WorkflowType.detect(candidate.getSteps()));

        logger.log(LogCategory.GRAPH, LogLevel.INFO, "WorkflowSessionizer",
                "Workflow candidate: " + candidate.size() + " steps, type="
                        + candidate.getWorkflowType() + ", " + candidate.getStartReason()
                        + ", " + candidate.getEndReason());
    }

    public List<WorkflowCandidate> getEmittedCandidates() {
        return new ArrayList<>(emittedCandidates);
    }

    public int getActiveCount() {
        return activeWorkflows.size();
    }

    public void clear() {
        activeWorkflows.clear();
        emittedCandidates.clear();
    }
}

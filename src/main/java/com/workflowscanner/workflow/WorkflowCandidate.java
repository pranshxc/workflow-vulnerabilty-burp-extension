package com.workflowscanner.workflow;

import com.workflowscanner.graph.RequestEdge;
import com.workflowscanner.graph.RequestNode;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * A detected workflow candidate — a sequence of related request nodes
 * that together represent a business workflow (e.g., checkout, login, registration).
 *
 * Produced by WorkflowDetector, scored by WorkflowScorer.
 * Only candidates with score >= threshold are sent to the LLM for analysis.
 */
public class WorkflowCandidate {
    private final String id;
    private SessionKey sessionKey;
    private WorkflowType workflowType;
    private final List<RequestNode> steps;            // Chronological request nodes
    private final List<RequestEdge> supportingEdges;  // Edges connecting steps
    private double workflowScore;
    private String startReason;
    private String endReason;
    private WorkflowEvidence evidence;

    public WorkflowCandidate() {
        this.id = UUID.randomUUID().toString().substring(0, 12);
        this.steps = new ArrayList<>();
        this.supportingEdges = new ArrayList<>();
        this.evidence = new WorkflowEvidence();
        this.workflowType = WorkflowType.UNKNOWN_BUSINESS_FLOW;
    }

    public WorkflowCandidate(SessionKey sessionKey) {
        this();
        this.sessionKey = sessionKey;
    }

    public void addStep(RequestNode node) {
        steps.add(node);
    }

    public void addEdge(RequestEdge edge) {
        supportingEdges.add(edge);
    }

    public RequestNode getLastStep() {
        return steps.isEmpty() ? null : steps.get(steps.size() - 1);
    }

    public long getStartTime() {
        return steps.isEmpty() ? 0 : steps.get(0).getTimestamp();
    }

    public long getEndTime() {
        return steps.isEmpty() ? 0 : steps.get(steps.size() - 1).getTimestamp();
    }

    public long getDurationMs() {
        return getEndTime() - getStartTime();
    }

    // --- Getters and Setters ---

    public String getId() { return id; }
    public SessionKey getSessionKey() { return sessionKey; }
    public void setSessionKey(SessionKey sessionKey) { this.sessionKey = sessionKey; }

    public WorkflowType getWorkflowType() { return workflowType; }
    public void setWorkflowType(WorkflowType workflowType) { this.workflowType = workflowType; }

    public List<RequestNode> getSteps() { return steps; }
    public List<RequestEdge> getSupportingEdges() { return supportingEdges; }

    public double getWorkflowScore() { return workflowScore; }
    public void setWorkflowScore(double workflowScore) { this.workflowScore = workflowScore; }

    public String getStartReason() { return startReason; }
    public void setStartReason(String startReason) { this.startReason = startReason; }

    public String getEndReason() { return endReason; }
    public void setEndReason(String endReason) { this.endReason = endReason; }

    public WorkflowEvidence getEvidence() { return evidence; }
    public void setEvidence(WorkflowEvidence evidence) { this.evidence = evidence; }

    public int size() { return steps.size(); }

    @Override
    public String toString() {
        return String.format("Workflow[%s] %s score=%.1f steps=%d type=%s %s",
                id, sessionKey, workflowScore, steps.size(), workflowType, startReason);
    }
}

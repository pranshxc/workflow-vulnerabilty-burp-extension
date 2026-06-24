package com.workflowscanner.workflow;

import java.util.ArrayList;
import java.util.List;

/**
 * Explains why a workflow candidate exists — the signals that triggered
 * its detection, the object flows found, and any noise that was suppressed.
 * Used for debugging and UI display.
 */
public class WorkflowEvidence {
    private final List<String> startSignals;
    private final List<String> continuationSignals;
    private final List<String> endSignals;
    private final List<String> objectFlows;
    private final List<String> suppressedNoise;
    private double confidence;

    public WorkflowEvidence() {
        this.startSignals = new ArrayList<>();
        this.continuationSignals = new ArrayList<>();
        this.endSignals = new ArrayList<>();
        this.objectFlows = new ArrayList<>();
        this.suppressedNoise = new ArrayList<>();
        this.confidence = 0.0;
    }

    public void addStartSignal(String signal) { startSignals.add(signal); }
    public void addContinuationSignal(String signal) { continuationSignals.add(signal); }
    public void addEndSignal(String signal) { endSignals.add(signal); }
    public void addObjectFlow(String flow) { objectFlows.add(flow); }
    public void addSuppressedNoise(String noise) { suppressedNoise.add(noise); }
    public void setConfidence(double confidence) { this.confidence = confidence; }

    public List<String> getStartSignals() { return startSignals; }
    public List<String> getContinuationSignals() { return continuationSignals; }
    public List<String> getEndSignals() { return endSignals; }
    public List<String> getObjectFlows() { return objectFlows; }
    public List<String> getSuppressedNoise() { return suppressedNoise; }
    public double getConfidence() { return confidence; }

    public String summarize() {
        StringBuilder sb = new StringBuilder();
        if (!startSignals.isEmpty()) sb.append("Start: ").append(String.join(", ", startSignals)).append("\n");
        if (!continuationSignals.isEmpty()) sb.append("Continuation: ").append(String.join(", ", continuationSignals)).append("\n");
        if (!endSignals.isEmpty()) sb.append("End: ").append(String.join(", ", endSignals)).append("\n");
        if (!objectFlows.isEmpty()) sb.append("Object flows: ").append(String.join(", ", objectFlows)).append("\n");
        if (!suppressedNoise.isEmpty()) sb.append("Suppressed: ").append(suppressedNoise.size()).append(" items");
        return sb.toString().trim();
    }

    @Override
    public String toString() {
        return summarize();
    }
}

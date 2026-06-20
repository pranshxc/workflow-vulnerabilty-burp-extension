package com.workflowscanner.graph;

/**
 * An edge in the request graph representing a relationship between two requests.
 * Each edge has a type, confidence score, and human-readable evidence string.
 */
public class RequestEdge {

    private String sourceNodeId;
    private String targetNodeId;
    private EdgeType type;
    private double confidence;
    private String evidence;

    public RequestEdge(String sourceNodeId, String targetNodeId, EdgeType type,
                       double confidence, String evidence) {
        this.sourceNodeId = sourceNodeId;
        this.targetNodeId = targetNodeId;
        this.type = type;
        this.confidence = confidence;
        this.evidence = evidence;
    }

    /** Constructor for deserialization. */
    public RequestEdge() {}

    public String getSourceNodeId() { return sourceNodeId; }
    public void setSourceNodeId(String sourceNodeId) { this.sourceNodeId = sourceNodeId; }

    public String getTargetNodeId() { return targetNodeId; }
    public void setTargetNodeId(String targetNodeId) { this.targetNodeId = targetNodeId; }

    public EdgeType getType() { return type; }
    public void setType(EdgeType type) { this.type = type; }

    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = confidence; }

    public String getEvidence() { return evidence; }
    public void setEvidence(String evidence) { this.evidence = evidence; }

    @Override
    public String toString() {
        return String.format("%s -[%s %.2f]-> %s", sourceNodeId, type, confidence, targetNodeId);
    }
}

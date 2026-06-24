package com.workflowscanner.graph;

import com.workflowscanner.classification.ValueKind;

/**
 * An edge in the request graph representing a relationship between two requests.
 * Each edge has a type, confidence score, and human-readable evidence string.
 * Optionally carries value semantics (kind, parameter name, value hash) for
 * business value flow analysis.
 */
public class RequestEdge {

    private String sourceNodeId;
    private String targetNodeId;
    private EdgeType type;
    private double confidence;
    private String evidence;

    // Value-flow semantics (optional, populated by RelationshipDetector)
    private ValueKind valueKind;
    private String paramName;
    private String valueHash;

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

    public ValueKind getValueKind() { return valueKind; }
    public void setValueKind(ValueKind valueKind) { this.valueKind = valueKind; }

    public String getParamName() { return paramName; }
    public void setParamName(String paramName) { this.paramName = paramName; }

    public String getValueHash() { return valueHash; }
    public void setValueHash(String valueHash) { this.valueHash = valueHash; }

    /**
     * Returns true if this edge represents a business value flow — i.e.,
     * a parameter value reused from one request to another with semantic meaning.
     * <p>
     * Covers three edge types:
     * <ul>
     *   <li>PARAM_REUSE — explicit parameter value carried across requests</li>
     *   <li>USER_DEFINED — manually grouped via context menu</li>
     *   <li>RESPONSE_CORRELATION — workflow-state cookies (cart_id,
     *       checkout_session, payment_intent, etc.) whose value carries
     *       workflow meaning rather than session identity</li>
     * </ul>
     * The actual session cookies (JSESSIONID, access_token, etc.) are excluded
     * by ValueKind.classify returning SESSION_TOKEN.
     */
    public boolean isBusinessValueFlow() {
        if (type != EdgeType.PARAM_REUSE
                && type != EdgeType.USER_DEFINED
                && type != EdgeType.RESPONSE_CORRELATION) {
            return false;
        }
        if (valueKind == null) return true; // legacy — assume business value
        return valueKind.isBusinessValue();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%s -[%s %.2f]-> %s", sourceNodeId, type, confidence, targetNodeId));
        if (valueKind != null) {
            sb.append(" [").append(valueKind).append("]");
            if (paramName != null) sb.append(" ").append(paramName);
        }
        return sb.toString();
    }
}

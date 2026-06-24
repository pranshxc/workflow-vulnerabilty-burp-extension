package com.workflowscanner.classification;

/**
 * Result of classifying a captured request.
 * Determines whether the request should become a graph node, be dropped,
 * or be downweighted for workflow detection.
 */
public class RequestClassification {

    private final RequestIntent intent;
    private final double businessScore;
    private final double noiseScore;
    private final boolean workflowRelevant;
    private final boolean background;
    private final String reason;
    private final EndpointKey endpointKey;

    public RequestClassification(RequestIntent intent, double businessScore, double noiseScore,
                                 boolean workflowRelevant, boolean background, String reason,
                                 EndpointKey endpointKey) {
        this.intent = intent;
        this.businessScore = businessScore;
        this.noiseScore = noiseScore;
        this.workflowRelevant = workflowRelevant;
        this.background = background;
        this.reason = reason;
        this.endpointKey = endpointKey;
    }

    /**
     * Create a classification for noise requests that should be dropped.
     */
    public static RequestClassification noise(RequestIntent intent, String reason) {
        return new RequestClassification(intent, 0, 1.0, false, false, reason, null);
    }

    /**
     * Create a classification for background requests (logged but not chained).
     */
    public static RequestClassification background(RequestIntent intent, String reason) {
        return new RequestClassification(intent, 0, 0.5, false, true, reason, null);
    }

    /**
     * Create a classification for business-relevant requests.
     */
    public static RequestClassification relevant(RequestIntent intent, double businessScore,
                                                  String reason, EndpointKey endpointKey) {
        return new RequestClassification(intent, businessScore, 0, true, false, reason, endpointKey);
    }

    /**
     * Create a classification for unknown requests that may still be interesting.
     */
    public static RequestClassification unknown(String reason, EndpointKey endpointKey) {
        return new RequestClassification(RequestIntent.UNKNOWN, 0.5, 0, true, false, reason, endpointKey);
    }

    // --- Getters ---

    public RequestIntent getIntent() { return intent; }
    public double getBusinessScore() { return businessScore; }
    public double getNoiseScore() { return noiseScore; }
    public boolean isWorkflowRelevant() { return workflowRelevant; }
    public boolean isBackground() { return background; }
    public String getReason() { return reason; }
    public EndpointKey getEndpointKey() { return endpointKey; }

    public boolean isNoise() {
        return noiseScore >= 1.0 || (!workflowRelevant && !background);
    }

    @Override
    public String toString() {
        return intent + (workflowRelevant ? " [relevant]" : " [suppressed]") + ": " + reason;
    }
}

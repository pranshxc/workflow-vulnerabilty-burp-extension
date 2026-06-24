package com.workflowscanner.graph;

import com.workflowscanner.classification.EndpointKey;
import com.workflowscanner.classification.RequestClassification;
import com.workflowscanner.data.CapturedRequest;

import java.util.HashMap;
import java.util.Map;

/**
 * A node in the request graph representing a single HTTP request/response.
 * Contains extracted parameters, response data, intent classification,
 * and endpoint normalization for relationship detection.
 */
public class RequestNode {

    private String id;
    private transient CapturedRequest request; // transient: not serialized to JSON
    private String method;
    private String host;
    private String path;
    private String url;
    private int statusCode;
    private Map<String, Object> extractedParams;  // All params from request
    private Map<String, Object> responseData;     // Extracted response values
    private long timestamp;
    private int nodeIndex;
    private String groupId;  // For user-defined chains via context menu

    // Classification fields (added in workflow rework)
    private RequestClassification classification;
    private EndpointKey endpointKey;

    public RequestNode(CapturedRequest request, int nodeIndex) {
        this.id = request.getId();
        this.request = request;
        this.method = request.getMethod();
        this.host = request.getHost();
        this.path = request.getPath();
        this.url = request.getUrl();
        this.statusCode = request.getStatusCode();
        this.timestamp = request.getTimestamp();
        this.nodeIndex = nodeIndex;
        this.groupId = request.getGroupId();
        this.extractedParams = new HashMap<>();
        this.responseData = new HashMap<>();
    }

    /** Constructor for deserialization. */
    public RequestNode() {
        this.extractedParams = new HashMap<>();
        this.responseData = new HashMap<>();
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public CapturedRequest getRequest() { return request; }
    public void setRequest(CapturedRequest request) { this.request = request; }

    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }

    public String getHost() { return host; }
    public void setHost(String host) { this.host = host; }

    public String getPath() { return path; }
    public void setPath(String path) { this.path = path; }

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public int getStatusCode() { return statusCode; }
    public void setStatusCode(int statusCode) { this.statusCode = statusCode; }

    public Map<String, Object> getExtractedParams() { return extractedParams; }
    public void setExtractedParams(Map<String, Object> extractedParams) { this.extractedParams = extractedParams; }

    public Map<String, Object> getResponseData() { return responseData; }
    public void setResponseData(Map<String, Object> responseData) { this.responseData = responseData; }

    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }

    public int getNodeIndex() { return nodeIndex; }
    public void setNodeIndex(int nodeIndex) { this.nodeIndex = nodeIndex; }

    public String getGroupId() { return groupId; }
    public void setGroupId(String groupId) { this.groupId = groupId; }

    // --- Classification (added in workflow rework) ---

    public RequestClassification getClassification() { return classification; }
    public void setClassification(RequestClassification classification) { this.classification = classification; }

    public EndpointKey getEndpointKey() { return endpointKey; }
    public void setEndpointKey(EndpointKey endpointKey) { this.endpointKey = endpointKey; }

    /**
     * Check if this is a redirect response (3xx).
     */
    public boolean isRedirect() {
        return statusCode >= 300 && statusCode < 400;
    }

    /**
     * Get the Location header value from response data (for redirect detection).
     */
    public String getRedirectLocation() {
        Object loc = responseData.get("Location");
        return loc != null ? loc.toString() : null;
    }

    @Override
    public String toString() {
        return String.format("Node#%d [%s %s -> %d]", nodeIndex, method, path, statusCode);
    }
}

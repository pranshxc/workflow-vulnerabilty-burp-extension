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

    // Lightweight metadata copied off the raw request at construction
    // time so referrer edge detection, content-type checks, and mime
    // routing still work after the raw payload has been evicted from
    // the hot graph (and reloaded from RequestStore on demand).
    private String referrer;
    private String contentType;
    private String mimeType;
    private String source;  // CapturedRequest.Source.name() at the time of capture

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
        this.referrer = request.getReferrer();
        this.contentType = request.getContentType();
        this.mimeType = request.getMimeType();
        if (request.getSource() != null) this.source = request.getSource().name();
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

    // --- Lightweight metadata (survives raw eviction) ---

    public String getReferrer() { return referrer; }
    public void setReferrer(String referrer) { this.referrer = referrer; }

    public String getContentType() { return contentType; }
    public void setContentType(String contentType) { this.contentType = contentType; }

    public String getMimeType() { return mimeType; }
    public void setMimeType(String mimeType) { this.mimeType = mimeType; }

    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }

    // --- Safe accessors for payload (request is transient; may be null
    //     after deserialization from disk until RequestHydrator re-loads it).

    public String getRequestBody() {
        return request != null ? request.getRequestBody() : null;
    }

    public String getResponseBody() {
        return request != null ? request.getResponseBody() : null;
    }

    public java.util.Map<String, java.util.List<String>> getRequestHeaders() {
        return request != null ? request.getRequestHeaders() : null;
    }

    public void setRequestHeaders(java.util.Map<String, java.util.List<String>> headers) {
        if (request == null) {
            // Lazily allocate a CapturedRequest so the headers can be set
            // even when the node was deserialized without a payload.
            request = new CapturedRequest();
        }
        request.setRequestHeaders(headers);
    }

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

package com.workflowscanner.data;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Unified internal representation of a captured HTTP request/response pair.
 * Used across all data sources: live proxy, backfill, and context menu.
 * No redaction — raw request/response bodies preserved.
 */
public class CapturedRequest {

    public enum Source {
        PROXY, BACKFILL, CONTEXT_MENU
    }

    private String id;
    private long timestamp;
    private String method;
    private String url;
    private String host;
    private String path;
    private Map<String, String> queryParams;
    private Map<String, List<String>> requestHeaders;
    private String requestBody;
    private int statusCode;
    private Map<String, List<String>> responseHeaders;
    private String responseBody;
    private String mimeType;
    private Source source;
    private List<String> cookies;
    private String referrer;
    private String contentType;
    private boolean inScope;
    private String groupId;  // For context menu grouped requests

    public CapturedRequest() {
        this.id = UUID.randomUUID().toString();
        this.timestamp = System.currentTimeMillis();
        this.queryParams = new HashMap<>();
        this.requestHeaders = new HashMap<>();
        this.responseHeaders = new HashMap<>();
        this.cookies = new ArrayList<>();
    }

    /**
     * Generate a deduplication key based on method + URL + timestamp.
     * Used to prevent re-ingesting the same request during backfill.
     */
    public String getDeduplicationKey() {
        return (method != null ? method : "") + "|" + (url != null ? url : "") + "|" + timestamp;
    }

    /**
     * Generate a fingerprint based on method + host + path (ignoring timestamp).
     * Used for identifying similar requests across different captures.
     */
    public String getFingerprint() {
        return (method != null ? method : "") + "|" + (host != null ? host : "") + "|" + (path != null ? path : "");
    }

    // --- Getters and Setters ---

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }

    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public String getHost() { return host; }
    public void setHost(String host) { this.host = host; }

    public String getPath() { return path; }
    public void setPath(String path) { this.path = path; }

    public Map<String, String> getQueryParams() { return queryParams; }
    public void setQueryParams(Map<String, String> queryParams) { this.queryParams = queryParams; }

    public Map<String, List<String>> getRequestHeaders() { return requestHeaders; }
    public void setRequestHeaders(Map<String, List<String>> requestHeaders) { this.requestHeaders = requestHeaders; }

    public String getRequestBody() { return requestBody; }
    public void setRequestBody(String requestBody) { this.requestBody = requestBody; }

    public int getStatusCode() { return statusCode; }
    public void setStatusCode(int statusCode) { this.statusCode = statusCode; }

    public Map<String, List<String>> getResponseHeaders() { return responseHeaders; }
    public void setResponseHeaders(Map<String, List<String>> responseHeaders) { this.responseHeaders = responseHeaders; }

    public String getResponseBody() { return responseBody; }
    public void setResponseBody(String responseBody) { this.responseBody = responseBody; }

    public String getMimeType() { return mimeType; }
    public void setMimeType(String mimeType) { this.mimeType = mimeType; }

    public Source getSource() { return source; }
    public void setSource(Source source) { this.source = source; }

    public List<String> getCookies() { return cookies; }
    public void setCookies(List<String> cookies) { this.cookies = cookies; }

    public String getReferrer() { return referrer; }
    public void setReferrer(String referrer) { this.referrer = referrer; }

    public String getContentType() { return contentType; }
    public void setContentType(String contentType) { this.contentType = contentType; }

    public boolean isInScope() { return inScope; }
    public void setInScope(boolean inScope) { this.inScope = inScope; }

    public String getGroupId() { return groupId; }
    public void setGroupId(String groupId) { this.groupId = groupId; }

    @Override
    public String toString() {
        return String.format("[%s] %s %s -> %d", source, method, url, statusCode);
    }
}

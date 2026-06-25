package com.workflowscanner.store;

/**
 * Compact in-memory representation of a single backfilled request.
 *
 * <p>Designed to be cheap to keep around: no headers, no bodies, no
 * cookies — just the fields the workflow detector, edge builder,
 * and UI need for matching, scoring, and display. Full data lives
 * in {@link RawHttp} on disk.
 *
 * <p>Intentionally a record-style class (not a Java record) so the
 * on-disk serializer can stay stable while the in-memory shape
 * evolves. Backed by simple fields and explicit getters.
 */
public final class RequestSummary {

    private final String id;
    private final long timestamp;
    private final String method;
    private final String host;
    private final String path;
    private final int statusCode;
    private final boolean workflowRelevant;
    private final boolean hasRawHttp;
    private final String endpointKey;        // may be null
    private final String sessionKey;        // may be null
    private final String intent;             // may be null
    private final long sizeBytes;            // approx size of raw body, 0 if none

    public RequestSummary(String id, long timestamp, String method, String host,
                          String path, int statusCode, boolean workflowRelevant,
                          boolean hasRawHttp, String endpointKey, String sessionKey,
                          String intent, long sizeBytes) {
        this.id = id;
        this.timestamp = timestamp;
        this.method = method;
        this.host = host;
        this.path = path;
        this.statusCode = statusCode;
        this.workflowRelevant = workflowRelevant;
        this.hasRawHttp = hasRawHttp;
        this.endpointKey = endpointKey;
        this.sessionKey = sessionKey;
        this.intent = intent;
        this.sizeBytes = sizeBytes;
    }

    public String getId() { return id; }
    public long getTimestamp() { return timestamp; }
    public String getMethod() { return method; }
    public String getHost() { return host; }
    public String getPath() { return path; }
    public int getStatusCode() { return statusCode; }
    public boolean isWorkflowRelevant() { return workflowRelevant; }
    public boolean isHasRawHttp() { return hasRawHttp; }
    public String getEndpointKey() { return endpointKey; }
    public String getSessionKey() { return sessionKey; }
    public String getIntent() { return intent; }
    public long getSizeBytes() { return sizeBytes; }

    @Override
    public String toString() {
        return "Summary[" + method + " " + host + path
                + " status=" + statusCode
                + (workflowRelevant ? " relevant" : "")
                + (hasRawHttp ? " raw" : "")
                + "]";
    }
}

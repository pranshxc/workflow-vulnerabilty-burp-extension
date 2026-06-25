package com.workflowscanner.store;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Full raw HTTP payload for a single request, persisted to disk by
 * {@link RequestStore}.
 *
 * <p>This is the data we keep off-heap. Headers, bodies, and cookies
 * can be large, especially response bodies for HTML/JSON endpoints.
 * For 1.6M requests the in-heap cost would be many gigabytes; on
 * disk the same data is far cheaper and survives restarts.
 *
 * <p>Implementations of {@link RequestStore} are free to compress
 * the request/response bodies before writing. Compression is
 * strongly recommended for response bodies &gt; 1KB.
 */
public final class RawHttp {

    private final Map<String, List<String>> requestHeaders;
    private final String requestBody;
    private final Map<String, List<String>> responseHeaders;
    private final String responseBody;
    private final String mimeType;
    private final String cookies;
    private final String queryParams;
    private final String referrer;

    public RawHttp(Map<String, List<String>> requestHeaders, String requestBody,
                   Map<String, List<String>> responseHeaders, String responseBody,
                   String mimeType, String cookies, String queryParams, String referrer) {
        this.requestHeaders = requestHeaders != null
                ? Collections.unmodifiableMap(new LinkedHashMap<>(requestHeaders))
                : Collections.emptyMap();
        this.requestBody = requestBody;
        this.responseHeaders = responseHeaders != null
                ? Collections.unmodifiableMap(new LinkedHashMap<>(responseHeaders))
                : Collections.emptyMap();
        this.responseBody = responseBody;
        this.mimeType = mimeType;
        this.cookies = cookies;
        this.queryParams = queryParams;
        this.referrer = referrer;
    }

    public Map<String, List<String>> getRequestHeaders() { return requestHeaders; }
    public String getRequestBody() { return requestBody; }
    public Map<String, List<String>> getResponseHeaders() { return responseHeaders; }
    public String getResponseBody() { return responseBody; }
    public String getMimeType() { return mimeType; }
    public String getCookies() { return cookies; }
    public String getQueryParams() { return queryParams; }
    public String getReferrer() { return referrer; }

    /**
     * Approximate size of this raw payload in bytes. Implementations
     * may use this for accounting and budgeting.
     */
    public long sizeBytes() {
        long n = 0;
        if (requestBody != null) n += requestBody.length();
        if (responseBody != null) n += responseBody.length();
        if (requestHeaders != null) {
            for (Map.Entry<String, List<String>> e : requestHeaders.entrySet()) {
                n += e.getKey().length();
                for (String v : e.getValue()) n += v.length();
            }
        }
        if (responseHeaders != null) {
            for (Map.Entry<String, List<String>> e : responseHeaders.entrySet()) {
                n += e.getKey().length();
                for (String v : e.getValue()) n += v.length();
            }
        }
        return n;
    }
}

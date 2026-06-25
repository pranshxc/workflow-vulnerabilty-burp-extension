package com.workflowscanner.store;

import com.workflowscanner.classification.EndpointKey;
import com.workflowscanner.classification.RequestClassification;
import com.workflowscanner.classification.RequestIntent;
import com.workflowscanner.data.CapturedRequest;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Bridges the in-process {@link CapturedRequest} pipeline model to the
 * on-disk {@link RequestStore} model.
 *
 * <p>The store needs a compact {@link RequestSummary} and (optionally)
 * the full {@link RawHttp}. This helper builds both from a single
 * {@code CapturedRequest} plus its classification, without keeping
 * the heavy data on the heap any longer than needed.
 *
 * <p>Used by {@code GraphBuilder.processRequest} for every request,
 * including suppressed ones: the store is the canonical record; the
 * hot in-memory graph is a working view.
 */
public final class RequestStoreConversion {

    private RequestStoreConversion() {}

    /**
     * Build a {@link RequestSummary} from a captured request and its
     * classification. The id is taken from the captured request; the
     * timestamp, method, host, path, status, and workflow-relevance
     * flag are copied directly. The intent, endpoint key, and
     * session key are taken from the classification when present.
     */
    public static RequestSummary summaryOf(CapturedRequest request,
                                           RequestClassification classification) {
        long ts = request.getTimestamp();
        String method = request.getMethod();
        String host = request.getHost();
        String path = request.getPath();
        int status = request.getStatusCode();
        boolean relevant = classification != null && classification.isWorkflowRelevant();
        boolean hasRaw = request.getRequestBody() != null
                || request.getResponseBody() != null
                || !request.getRequestHeaders().isEmpty()
                || !request.getResponseHeaders().isEmpty();
        String endpointKeyStr = null;
        if (classification != null && classification.getEndpointKey() != null) {
            endpointKeyStr = endpointKeyToString(classification.getEndpointKey());
        }
        String intentStr = null;
        if (classification != null && classification.getIntent() != null) {
            intentStr = classification.getIntent().name();
        }
        long size = approxSize(request);
        return new RequestSummary(
                request.getId(),
                ts,
                method,
                host,
                path,
                status,
                relevant,
                hasRaw,
                endpointKeyStr,
                null,                       // session key is filled in by the sessionizer, not here
                intentStr,
                size);
    }

    /**
     * Build a {@link RawHttp} from a captured request. Returns null
     * if the captured request has neither headers nor bodies — the
     * caller is free to pass null in that case.
     */
    public static RawHttp rawOf(CapturedRequest request) {
        if (request == null) return null;
        if (!hasAnyPayload(request)) return null;
        return new RawHttp(
                request.getRequestHeaders(),
                request.getRequestBody(),
                request.getResponseHeaders(),
                request.getResponseBody(),
                request.getMimeType(),
                joinList(request.getCookies(), "; "),
                joinQueryParams(request.getQueryParams()),
                request.getReferrer());
    }

    private static boolean hasAnyPayload(CapturedRequest r) {
        return (r.getRequestHeaders() != null && !r.getRequestHeaders().isEmpty())
                || (r.getResponseHeaders() != null && !r.getResponseHeaders().isEmpty())
                || notEmpty(r.getRequestBody())
                || notEmpty(r.getResponseBody())
                || notEmpty(r.getReferrer())
                || (r.getCookies() != null && !r.getCookies().isEmpty())
                || (r.getQueryParams() != null && !r.getQueryParams().isEmpty());
    }

    private static boolean notEmpty(String s) { return s != null && !s.isEmpty(); }

    private static long approxSize(CapturedRequest r) {
        long n = 0;
        if (r.getRequestBody() != null) n += r.getRequestBody().length();
        if (r.getResponseBody() != null) n += r.getResponseBody().length();
        if (r.getRequestHeaders() != null) {
            for (Map.Entry<String, List<String>> e : r.getRequestHeaders().entrySet()) {
                n += e.getKey().length();
                for (String v : e.getValue()) n += v.length();
            }
        }
        if (r.getResponseHeaders() != null) {
            for (Map.Entry<String, List<String>> e : r.getResponseHeaders().entrySet()) {
                n += e.getKey().length();
                for (String v : e.getValue()) n += v.length();
            }
        }
        return n;
    }

    private static String joinList(List<String> list, String sep) {
        if (list == null || list.isEmpty()) return null;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) sb.append(sep);
            sb.append(list.get(i));
        }
        return sb.toString();
    }

    private static String joinQueryParams(Map<String, String> q) {
        if (q == null || q.isEmpty()) return null;
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (Map.Entry<String, String> e : q.entrySet()) {
            if (!first) sb.append('&');
            first = false;
            sb.append(e.getKey());
            if (e.getValue() != null) {
                sb.append('=');
                sb.append(e.getValue());
            }
        }
        return sb.toString();
    }

    /**
     * Render an {@link EndpointKey} as a compact stable string. We use
     * the same shape the classification layer already produces
     * ({@code METHOD host/path}) so the store does not need its own
     * schema for the endpoint identity.
     */
    private static String endpointKeyToString(EndpointKey ek) {
        if (ek == null) return null;
        return ek.getMethod() + " " + ek.getHost() + ek.getNormalizedPath();
    }
}

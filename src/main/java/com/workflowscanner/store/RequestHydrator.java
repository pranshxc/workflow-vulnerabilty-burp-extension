package com.workflowscanner.store;

import com.workflowscanner.data.CapturedRequest;
import com.workflowscanner.graph.RequestNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Re-hydrates a {@link com.workflowscanner.graph.RequestNode}'s
 * raw HTTP payload from the disk-backed {@link RequestStore}.
 *
 * <p>The hot in-memory graph only retains raw HTTP payloads for
 * recently seen or selected nodes (see
 * {@code GraphBuilder.HOT_RAW_RETENTION}). For older, evicted, or
 * backfill-only nodes, {@code node.getRequest()} is {@code null}.
 * Consumers that need the raw data (LLM prompt building, request
 * replay, View Request/Response, Send to Repeater, advisory
 * evidence creation) must call {@link #ensureHydrated(RequestNode, RequestStore)}
 * before reading {@code getRequest()}.
 */
public final class RequestHydrator {

    private RequestHydrator() {}

    /**
     * Ensure the node has its raw payload attached. If the node
     * already has raw data, this is a no-op. Otherwise the store
     * is consulted and the raw payload is rebuilt from the stored
     * {@link RawHttp} plus the node's lightweight metadata. The
     * rebuilt {@link CapturedRequest} is attached to the node in
     * place so subsequent calls to {@code node.getRequest()} work.
     *
     * @return the (possibly newly-attached) {@code CapturedRequest},
     *         or null if neither the node nor the store can supply
     *         raw data.
     */
    public static CapturedRequest ensureHydrated(RequestNode node, RequestStore store) {
        if (node == null) return null;
        CapturedRequest existing = node.getRequest();
        if (existing != null) return existing;
        if (store == null) return null;
        Optional<RawHttp> rawOpt = store.getRaw(node.getId());
        if (rawOpt.isEmpty()) return null;
        CapturedRequest rebuilt = hydrate(buildSeedFromNode(node), rawOpt.get());
        node.setRequest(rebuilt);
        return rebuilt;
    }

    /**
     * Build a {@link CapturedRequest} from already-loaded
     * {@link RawHttp} plus the metadata the caller already has.
     */
    public static CapturedRequest hydrate(CapturedRequest seed, RawHttp raw) {
        if (raw == null) return seed;
        CapturedRequest out = seed != null ? seed : new CapturedRequest();
        Map<String, List<String>> reqH = raw.getRequestHeaders();
        if (reqH != null && !reqH.isEmpty()) {
            Map<String, List<String>> copy = new LinkedHashMap<>(reqH.size());
            for (Map.Entry<String, List<String>> e : reqH.entrySet()) {
                copy.put(e.getKey(), new ArrayList<>(e.getValue()));
            }
            out.setRequestHeaders(copy);
        }
        out.setRequestBody(raw.getRequestBody());
        Map<String, List<String>> resH = raw.getResponseHeaders();
        if (resH != null && !resH.isEmpty()) {
            Map<String, List<String>> copy = new LinkedHashMap<>(resH.size());
            for (Map.Entry<String, List<String>> e : resH.entrySet()) {
                copy.put(e.getKey(), new ArrayList<>(e.getValue()));
            }
            out.setResponseHeaders(copy);
        }
        out.setResponseBody(raw.getResponseBody());
        out.setMimeType(raw.getMimeType());
        out.setReferrer(raw.getReferrer());
        if (raw.getCookies() != null && !raw.getCookies().isEmpty()) {
            out.setCookies(splitList(raw.getCookies(), ";"));
        }
        if (raw.getQueryParams() != null && !raw.getQueryParams().isEmpty()) {
            out.setQueryParams(splitQuery(raw.getQueryParams()));
        }
        return out;
    }

    /**
     * Build a {@link CapturedRequest} from a {@link RequestNode}'s
     * lightweight metadata fields. Used as a seed for hydration
     * when the node does not already hold a raw request.
     */
    private static CapturedRequest buildSeedFromNode(RequestNode node) {
        CapturedRequest seed = new CapturedRequest();
        if (node.getId() != null) seed.setId(node.getId());
        seed.setTimestamp(node.getTimestamp());
        seed.setMethod(node.getMethod());
        seed.setHost(node.getHost());
        seed.setPath(node.getPath());
        seed.setUrl(node.getUrl());
        seed.setStatusCode(node.getStatusCode());
        seed.setGroupId(node.getGroupId());
        seed.setReferrer(node.getReferrer());
        seed.setContentType(node.getContentType());
        seed.setMimeType(node.getMimeType());
        return seed;
    }

    /**
     * Quick check used by call sites to decide whether they need to
     * hydrate. Returns true if hydration is required (raw is null
     * but the store likely has the data). Returns false if the node
     * already has raw or the store is null.
     */
    public static boolean needsHydration(CapturedRequest current, RequestStore store) {
        return current == null && store != null;
    }

    private static List<String> splitList(String joined, String sep) {
        List<String> out = new ArrayList<>();
        if (joined == null) return out;
        for (String s : joined.split(java.util.regex.Pattern.quote(sep), -1)) {
            String t = s.trim();
            if (!t.isEmpty()) out.add(t);
        }
        return out;
    }

    private static Map<String, String> splitQuery(String joined) {
        Map<String, String> out = new LinkedHashMap<>();
        if (joined == null) return out;
        for (String pair : joined.split("&", -1)) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            if (eq < 0) {
                out.put(pair, "");
            } else {
                out.put(pair.substring(0, eq), pair.substring(eq + 1));
            }
        }
        return out;
    }
}

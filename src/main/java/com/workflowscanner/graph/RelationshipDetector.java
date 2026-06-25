package com.workflowscanner.graph;

import com.workflowscanner.classification.EdgeStrength;
import com.workflowscanner.classification.RequestClassification;
import com.workflowscanner.classification.RequestIntent;
import com.workflowscanner.classification.ValueKind;
import com.workflowscanner.data.RequestConverter;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Detects relationships between request nodes using five heuristics.
 *
 * Edge strength tiers (used downstream by WorkflowDetector):
 * - STRONG: redirect, user-defined, business-token value flow
 * - MEDIUM: referrer to business endpoint, object-ID reuse
 * - WEAK: same-host time proximity, referrer to static/telemetry
 * - CONTEXT_ONLY: session cookie propagation, telemetry dependency
 *
 * Key changes from the original design:
 * - TIME_WINDOW no longer creates graph edges (context-only)
 * - REFERRER confidence varies by target intent
 * - RESPONSE_CORRELATION filters out session cookies
 * - PARAM_REUSE uses ValueKind classification to filter noise
 *
 * <p>All detection paths are O(1)-ish in the number of indexed
 * candidates, not O(N) over the full hot graph. We use bounded
 * indexes (last-N node IDs per key) for url, groupId, cookie value,
 * and response value lookups. The hot graph can have hundreds of
 * thousands of nodes without exploding detection cost.
 */
public class RelationshipDetector {

    private final RequestGraph graph;
    private final ExtensionLogger logger;

    // Bounded index: value -> last N producer node IDs.
    // Used by detectParameterReuse / detectResponseCorrelation to
    // look up value producers in O(N-bounded) instead of O(graph).
    private final Map<String, Deque<String>> responseValueIndex = new ConcurrentHashMap<>();

    // Bounded index: normalized URL -> last N node IDs. Used by
    // detectReferrerLinks and detectRedirectChains to find the
    // few recent nodes that share a URL.
    private final Map<String, Deque<String>> urlIndex = new ConcurrentHashMap<>();

    // Bounded index: groupId -> last N node IDs. Used by
    // detectUserDefinedGroups.
    private final Map<String, Deque<String>> groupIndex = new ConcurrentHashMap<>();

    // Bounded index: cookie name -> last N Set-Cookie values.
    // For each value, the deque stores
    // (value, nodeId) pairs so we can resolve the producer
    // quickly. detectResponseCorrelation uses this.
    private final Map<String, Deque<CookieProducer>> cookieSetIndex = new ConcurrentHashMap<>();

    // Per-key cap. Bounded so the index cannot grow unboundedly
    // with the request count.
    private final int indexMaxPerKey;

    // ========================================================================
    // Edge-miss diagnostics
    //
    // These counters are updated by the detection paths and
    // surfaced via {@link #getEdgeMissDiagnostics()} so the
    // status panel and the health check can explain *why* explicit
    // edges stay at zero. The common pattern in modern apps is
    // "edges = 0 but candidates > 0" because the referrer points
    // to a static/SPA page that is not captured, response bodies
    // are encrypted or have no extractable IDs, and the only
    // repeated cookie is a session token. Without these counters
    // it is impossible to tell which heuristic is failing.
    // ========================================================================
    private final AtomicLong diagReferrerPresent = new AtomicLong(0);
    private final AtomicLong diagReferrerMatched = new AtomicLong(0);
    private final AtomicLong diagRedirectSeen = new AtomicLong(0);
    private final AtomicLong diagRedirectMatched = new AtomicLong(0);
    private final AtomicLong diagParamValuesChecked = new AtomicLong(0);
    private final AtomicLong diagParamValuesReused = new AtomicLong(0);
    private final AtomicLong diagNonSessionCookiesChecked = new AtomicLong(0);
    private final AtomicLong diagNonSessionCookiesCorrelated = new AtomicLong(0);
    private final AtomicLong diagResponseValuesIndexed = new AtomicLong(0);
    private final AtomicLong diagNodesProcessed = new AtomicLong(0);

    // Session cookie names that should never create workflow edges
    private static final Set<String> SESSION_COOKIE_NAMES = Set.of(
            "jsessionid", "phpsessid", "connect.sid", "session", "_auth",
            "access_token", "refresh_token", "sid", "token", "auth_",
            "awsalb", "lb", "sessionid", "__cfduid", "cfid", "cftoken",
            "rememberme", "remember_me", "xsrf-token", "x-csrf-token");

    public RelationshipDetector(RequestGraph graph, ExtensionLogger logger) {
        this(graph, logger, 50);
    }

    public RelationshipDetector(RequestGraph graph, ExtensionLogger logger,
                                int indexMaxPerKey) {
        this.graph = graph;
        this.logger = logger;
        this.indexMaxPerKey = Math.max(1, indexMaxPerKey);
    }

    /**
     * Compute all edges for a newly added node against existing nodes.
     * Also indexes the new node into the bounded indexes for future
     * lookups.
     */
    public List<RequestEdge> detectRelationships(RequestNode newNode) {
        List<RequestEdge> newEdges = new ArrayList<>();
        diagNodesProcessed.incrementAndGet();

        newEdges.addAll(detectRedirectChains(newNode));
        newEdges.addAll(detectReferrerLinks(newNode));
        // TIME_WINDOW is intentionally omitted — context-only, no edges created
        newEdges.addAll(detectParameterReuse(newNode));
        newEdges.addAll(detectResponseCorrelation(newNode));
        newEdges.addAll(detectUserDefinedGroups(newNode));

        // Index this node for future lookups.
        indexResponseValues(newNode);
        indexUrl(newNode);
        indexGroup(newNode);
        indexSetCookies(newNode);

        return newEdges;
    }

    /**
     * Get the edge strength for a given edge and its nodes.
     * Used by WorkflowDetector to decide which edges form workflow chains.
     */
    public EdgeStrength getEdgeStrength(RequestEdge edge, RequestNode source, RequestNode target) {
        switch (edge.getType()) {
            case REDIRECT:
                return EdgeStrength.STRONG;
            case USER_DEFINED:
                return EdgeStrength.STRONG;
            case PARAM_REUSE:
                // Business ID and security token reuse = STRONG
                if (isBusinessValueFlow(edge)) return EdgeStrength.STRONG;
                return EdgeStrength.MEDIUM;
            case REFERRER:
                // Referrer to business endpoint = MEDIUM, to static/telemetry = WEAK
                if (target != null && isBusinessRelevant(target)) return EdgeStrength.MEDIUM;
                return EdgeStrength.WEAK;
            case RESPONSE_CORRELATION:
                // Strength is determined by the cookie's semantic value, not the
                // presence of the literal "Set-Cookie" string in the evidence
                // (which was always present and so always downgraded).
                if (edge.getValueKind() == ValueKind.SESSION_TOKEN) {
                    return EdgeStrength.CONTEXT_ONLY;
                }
                if (edge.isBusinessValueFlow()) {
                    return EdgeStrength.MEDIUM;
                }
                // Workflow-state cookies (cart_id, checkout_session, etc.)
                // with UNKNOWN or other non-session value kinds still represent
                // a meaningful relationship — keep them at MEDIUM.
                return EdgeStrength.MEDIUM;
            case TIME_WINDOW:
                return EdgeStrength.WEAK;
            case WORKFLOW_SEQUENCE:
                // Derived structural edge — WorkflowDetector produced
                // it from a candidate's step order, not from an
                // observable HTTP signal. WEAK means it does not
                // contribute to candidate merging on its own. The
                // candidate's score drives the edge confidence
                // (already encoded on the edge itself).
                return EdgeStrength.WEAK;
            default:
                return EdgeStrength.WEAK;
        }
    }

    private boolean isBusinessValueFlow(RequestEdge edge) {
        // Use the edge's own ValueKind-based check rather than raw confidence
        return edge != null && edge.isBusinessValueFlow();
    }

    private boolean isBusinessRelevant(RequestNode node) {
        RequestClassification cls = node.getClassification();
        if (cls == null) return true; // Conservative: assume relevant
        RequestIntent intent = cls.getIntent();
        return intent == RequestIntent.BUSINESS_ACTION
                || intent == RequestIntent.BUSINESS_READ
                || intent == RequestIntent.AUTHENTICATION
                || intent == RequestIntent.WORKFLOW_STATE
                || intent == RequestIntent.UNKNOWN;
    }

    // ========================================================================
    // 1. Redirect Chain Detection
    // ========================================================================

    private List<RequestEdge> detectRedirectChains(RequestNode newNode) {
        List<RequestEdge> edges = new ArrayList<>();
        boolean sawRedirect = newNode.isRedirect();
        boolean matchedRedirect = false;

        // Walk the existing index for redirect producers whose
        // Location header matches this new URL, and redirect
        // consumers (existing nodes) whose URL matches a Location
        // header on this new node. Bounded by indexMaxPerKey per
        // URL key, not by the full graph size.
        if (newNode.isRedirect()) {
            String location = newNode.getRedirectLocation();
            if (location != null) {
                Deque<String> existingIds = urlIndex.get(normalizeUrl(location));
                if (existingIds != null) {
                    for (String existingId : existingIds) {
                        if (existingId.equals(newNode.getId())) continue;
                        RequestNode existing = graph.getNode(existingId);
                        if (existing == null) continue;
                        edges.add(new RequestEdge(
                                newNode.getId(), existing.getId(),
                                EdgeType.REDIRECT, 1.0,
                                newNode.getStatusCode() + " Location: " + location
                                        + " -> " + existing.getMethod() + " " + existing.getUrl()));
                        matchedRedirect = true;
                    }
                }
            }
        }
        // For the other direction, find existing redirect nodes
        // that point at this new URL. Since the response data
        // already lives on the new node (responseData) and the
        // existing producer's Location has been recorded against
        // the producer's index entry, we just walk the URL index
        // for this new URL looking for earlier nodes that were
        // redirects.
        Deque<String> recent = urlIndex.get(normalizeUrl(newNode.getUrl()));
        if (recent != null) {
            for (String existingId : recent) {
                if (existingId.equals(newNode.getId())) continue;
                RequestNode existing = graph.getNode(existingId);
                if (existing == null) continue;
                if (!existing.isRedirect()) continue;
                sawRedirect = true;
                String location = existing.getRedirectLocation();
                if (location != null && urlMatches(location, newNode.getUrl())) {
                    edges.add(new RequestEdge(
                            existing.getId(), newNode.getId(),
                            EdgeType.REDIRECT, 1.0,
                            existing.getStatusCode() + " Location: " + location
                                    + " -> " + newNode.getMethod() + " " + newNode.getUrl()));
                    matchedRedirect = true;
                }
            }
        }
        if (sawRedirect) diagRedirectSeen.incrementAndGet();
        if (matchedRedirect) diagRedirectMatched.incrementAndGet();
        return edges;
    }

    // ========================================================================
    // 2. Referrer Header Analysis (tiered confidence based on target intent)
    //
    // Reads referrer off the lightweight node field (set at
    // construction from CapturedRequest) so this still works after
    // the raw payload has been dropped.
    // ========================================================================

    private List<RequestEdge> detectReferrerLinks(RequestNode newNode) {
        List<RequestEdge> edges = new ArrayList<>();
        String referrer = newNode.getReferrer();
        boolean hasReferrer = referrer != null && !referrer.isEmpty();
        boolean matched = false;

        if (hasReferrer) {
            diagReferrerPresent.incrementAndGet();

            // Find existing node whose URL matches the referrer.
            Deque<String> existingIds = urlIndex.get(normalizeUrl(referrer));
            if (existingIds != null) {
                for (String existingId : existingIds) {
                    if (existingId.equals(newNode.getId())) continue;
                    RequestNode existing = graph.getNode(existingId);
                    if (existing == null) continue;
                    if (!urlMatches(referrer, existing.getUrl())) continue;
                    double confidence = isBusinessRelevant(newNode) ? 0.85 : 0.5;
                    edges.add(new RequestEdge(
                            existing.getId(), newNode.getId(),
                            EdgeType.REFERRER, confidence,
                            "Referer header: " + referrer + " matches " + existing.getUrl()));
                    matched = true;
                    break;   // first match wins
                }
            }
        }

        // Reverse direction: find existing nodes whose referrer
        // matches this new URL. Walk the bounded URL index for the
        // new URL and check the corresponding node's lightweight
        // referrer field. This is the more common case in modern
        // apps: the request that *fired first* had no referrer in
        // the captured set, but a later request's URL matches an
        // earlier request's Referer. We still credit that.
        if (newNode.getUrl() != null) {
            Deque<String> candidates = urlIndex.get(normalizeUrl(newNode.getUrl()));
            if (candidates != null) {
                for (String existingId : candidates) {
                    if (existingId.equals(newNode.getId())) continue;
                    RequestNode existing = graph.getNode(existingId);
                    if (existing == null) continue;
                    String existingReferrer = existing.getReferrer();
                    if (existingReferrer != null
                            && urlMatches(existingReferrer, newNode.getUrl())) {
                        diagReferrerPresent.incrementAndGet();
                        double confidence = isBusinessRelevant(existing) ? 0.85 : 0.5;
                        edges.add(new RequestEdge(
                                newNode.getId(), existing.getId(),
                                EdgeType.REFERRER, confidence,
                                "Referer header: " + existingReferrer
                                        + " matches " + newNode.getUrl()));
                        matched = true;
                    }
                }
            }
        }
        if (matched) diagReferrerMatched.incrementAndGet();
        return edges;
    }

    // ========================================================================
    // 3. Parameter Reuse Detection (filtered by ValueKind)
    // ========================================================================

    private List<RequestEdge> detectParameterReuse(RequestNode newNode) {
        List<RequestEdge> edges = new ArrayList<>();
        Map<String, Object> newParams = newNode.getExtractedParams();
        if (newParams == null) return edges;

        for (Map.Entry<String, Object> entry : newParams.entrySet()) {
            String paramName = entry.getKey();
            String paramValue = entry.getValue() != null ? entry.getValue().toString() : null;
            if (paramValue == null || paramValue.length() < 4) continue;

            // Filter through ValueKind — only correlation-relevant values create edges
            if (!ParameterExtractor.isInterestingCorrelationValue(paramName, paramValue)) continue;

            diagParamValuesChecked.incrementAndGet();
            Deque<String> sourceNodeIds = responseValueIndex.get(paramValue);
            if (sourceNodeIds == null) continue;

            for (String sourceNodeId : sourceNodeIds) {
                if (sourceNodeId.equals(newNode.getId())) continue;
                RequestNode sourceNode = graph.getNode(sourceNodeId);
                if (sourceNode == null || sourceNode.getTimestamp() >= newNode.getTimestamp()) continue;

                String responseName = findParamName(sourceNode.getResponseData(), paramValue);
                RequestEdge edge = new RequestEdge(
                        sourceNodeId, newNode.getId(),
                        EdgeType.PARAM_REUSE, 0.8,
                        "Value '" + truncate(paramValue, 40) + "' from response "
                                + (responseName != null ? "(" + responseName + ")" : "")
                                + " of Node#" + sourceNode.getNodeIndex()
                                + " reused in request (" + paramName + ")"
                                + " of Node#" + newNode.getNodeIndex());
                edge.setValueKind(ValueKind.classify(paramName, paramValue));
                edge.setParamName(paramName);
                edge.setValueHash(sha256(paramValue));
                edges.add(edge);
                diagParamValuesReused.incrementAndGet();
            }
        }
        return edges;
    }

    // ========================================================================
    // 4. Response-to-Request Correlation (session cookies excluded)
    // ========================================================================

    private List<RequestEdge> detectResponseCorrelation(RequestNode newNode) {
        List<RequestEdge> edges = new ArrayList<>();
        Map<String, Object> newParams = newNode.getExtractedParams();
        if (newParams == null) return edges;

        for (Map.Entry<String, Object> entry : newParams.entrySet()) {
            if (!entry.getKey().startsWith("cookie.")) continue;
            String cookieName = entry.getKey().substring(7).toLowerCase();

            // Skip session cookies — they don't indicate workflow relationships
            if (SESSION_COOKIE_NAMES.contains(cookieName)) continue;

            diagNonSessionCookiesChecked.incrementAndGet();
            String cookieValue = entry.getValue().toString();

            // Look up bounded producer list for this cookie name.
            Deque<CookieProducer> producers = cookieSetIndex.get(cookieName);
            if (producers == null) continue;
            for (CookieProducer p : producers) {
                if (p.nodeId.equals(newNode.getId())) continue;
                if (p.timestamp >= newNode.getTimestamp()) continue;
                if (!p.value.equals(cookieValue)) continue;
                RequestNode existing = graph.getNode(p.nodeId);
                if (existing == null) continue;
                RequestEdge edge = new RequestEdge(
                        p.nodeId, newNode.getId(),
                        EdgeType.RESPONSE_CORRELATION, 0.85,
                        "Set-Cookie '" + cookieName + "' from Node#"
                                + existing.getNodeIndex()
                                + " used as Cookie in Node#" + newNode.getNodeIndex());
                edge.setParamName(cookieName);
                edge.setValueHash(sha256(cookieValue));
                edge.setValueKind(ValueKind.classify(cookieName, cookieValue));
                edges.add(edge);
                diagNonSessionCookiesCorrelated.incrementAndGet();
            }
        }
        return edges;
    }

    // ========================================================================
    // 5. User-Defined Groups (Context Menu)
    // ========================================================================

    private List<RequestEdge> detectUserDefinedGroups(RequestNode newNode) {
        List<RequestEdge> edges = new ArrayList<>();
        if (newNode.getGroupId() == null) return edges;

        Deque<String> members = groupIndex.get(newNode.getGroupId());
        if (members == null) return edges;
        for (String existingId : members) {
            if (existingId.equals(newNode.getId())) continue;
            RequestNode existing = graph.getNode(existingId);
            if (existing == null) continue;
            String sourceId = existing.getTimestamp() < newNode.getTimestamp()
                    ? existing.getId() : newNode.getId();
            String targetId = sourceId.equals(existing.getId())
                    ? newNode.getId() : existing.getId();
            edges.add(new RequestEdge(
                    sourceId, targetId,
                    EdgeType.USER_DEFINED, 1.0,
                    "User-grouped via context menu (group: " + newNode.getGroupId() + ")"));
        }
        return edges;
    }

    // ========================================================================
    // Inverted Index Management (all bounded)
    // ========================================================================

    private void indexResponseValues(RequestNode node) {
        Set<String> values = ParameterExtractor.getInterestingValues(node.getResponseData());
        for (String value : values) {
            pushBounded(responseValueIndex, value, node.getId());
            diagResponseValuesIndexed.incrementAndGet();
        }
    }

    private void indexUrl(RequestNode node) {
        if (node.getUrl() != null) {
            pushBounded(urlIndex, normalizeUrl(node.getUrl()), node.getId());
        }
    }

    private void indexGroup(RequestNode node) {
        if (node.getGroupId() != null) {
            pushBounded(groupIndex, node.getGroupId(), node.getId());
        }
    }

    private void indexSetCookies(RequestNode node) {
        Map<String, Object> responseData = node.getResponseData();
        if (responseData == null) return;
        for (Map.Entry<String, Object> e : responseData.entrySet()) {
            if (!e.getKey().startsWith("set-cookie.")) continue;
            String cookieName = e.getKey().substring("set-cookie.".length()).toLowerCase();
            String value = e.getValue() != null ? e.getValue().toString() : null;
            if (value == null) continue;
            pushBounded(cookieSetIndex, cookieName,
                    new CookieProducer(node.getId(), value, node.getTimestamp()));
        }
    }

    private <V> void pushBounded(Map<String, Deque<V>> index, String key, V value) {
        Deque<V> deque = index.computeIfAbsent(key, k -> new ArrayDeque<>(indexMaxPerKey));
        synchronized (deque) {
            // Evict from the front until we have room, then add.
            while (deque.size() >= indexMaxPerKey) {
                deque.pollFirst();
            }
            deque.addLast(value);
        }
    }

    public void rebuildIndex() {
        responseValueIndex.clear();
        urlIndex.clear();
        groupIndex.clear();
        cookieSetIndex.clear();
        for (RequestNode node : graph.getNodes().values()) {
            indexResponseValues(node);
            indexUrl(node);
            indexGroup(node);
            indexSetCookies(node);
        }
        logger.log(LogCategory.GRAPH, LogLevel.INFO, "RelationshipDetector",
                "Indexes rebuilt. responseValueIndex=" + responseValueIndex.size()
                        + " urlIndex=" + urlIndex.size()
                        + " groupIndex=" + groupIndex.size()
                        + " cookieSetIndex=" + cookieSetIndex.size());
    }

    public int getIndexSize() { return responseValueIndex.size(); }
    public int getUrlIndexSize() { return urlIndex.size(); }
    public int getGroupIndexSize() { return groupIndex.size(); }
    public int getCookieSetIndexSize() { return cookieSetIndex.size(); }

    /**
     * Edge-miss diagnostic counters. The status panel and
     * HealthCheck read this map to explain *why* the explicit
     * edge count is zero (e.g. "0 referrers matched" vs "50
     * referrers present but none matched" tells the user
     * whether the referrer target is uncaptured, vs whether
     * the Referer header is not even being sent by the app).
     *
     * <p>Keys are stable so the UI can read them by name and
     * absent keys read as 0.
     */
    public Map<String, Long> getEdgeMissDiagnostics() {
        Map<String, Long> out = new LinkedHashMap<>();
        out.put("nodes_processed", diagNodesProcessed.get());
        out.put("referrer_present", diagReferrerPresent.get());
        out.put("referrer_matched", diagReferrerMatched.get());
        out.put("redirect_seen", diagRedirectSeen.get());
        out.put("redirect_matched", diagRedirectMatched.get());
        out.put("param_values_checked", diagParamValuesChecked.get());
        out.put("param_values_reused", diagParamValuesReused.get());
        out.put("non_session_cookies_checked", diagNonSessionCookiesChecked.get());
        out.put("non_session_cookies_correlated", diagNonSessionCookiesCorrelated.get());
        out.put("response_values_indexed", diagResponseValuesIndexed.get());
        return out;
    }

    /**
     * Simple value-object for cookie producers stored in the bounded
     * index. Pairs the producer node id with the cookie value and
     * the producer's timestamp (so we can compare against the new
     * node's timestamp when correlating).
     */
    private static final class CookieProducer {
        final String nodeId;
        final String value;
        final long timestamp;
        CookieProducer(String nodeId, String value, long timestamp) {
            this.nodeId = nodeId;
            this.value = value;
            this.timestamp = timestamp;
        }
    }

    // ========================================================================
    // Utility Methods
    // ========================================================================

    private boolean urlMatches(String url1, String url2) {
        if (url1 == null || url2 == null) return false;
        String n1 = normalizeUrl(url1);
        String n2 = normalizeUrl(url2);
        if (n1.equals(n2)) return true;
        if (url1.startsWith("/")) {
            String path2 = RequestConverter.extractPath(url2);
            return url1.equals(path2);
        }
        return false;
    }

    private String normalizeUrl(String url) {
        if (url == null) return "";
        String normalized = url.toLowerCase();
        int hashIdx = normalized.indexOf('#');
        if (hashIdx >= 0) normalized = normalized.substring(0, hashIdx);
        if (normalized.endsWith("/") && normalized.length() > 1) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private String findParamName(Map<String, Object> params, String value) {
        if (params == null) return null;
        for (Map.Entry<String, Object> entry : params.entrySet()) {
            if (entry.getValue() != null && entry.getValue().toString().equals(value)) {
                return entry.getKey();
            }
        }
        return null;
    }

    private String truncate(String s, int maxLen) {
        if (s == null) return "";
        return s.length() <= maxLen ? s : s.substring(0, maxLen) + "...";
    }

    /**
     * SHA-256 hash a string.
     */
    private static String sha256(String input) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (java.security.NoSuchAlgorithmException e) {
            return Integer.toHexString(input.hashCode());
        }
    }
}

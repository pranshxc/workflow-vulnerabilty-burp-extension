package com.workflowscanner.graph;

import com.workflowscanner.data.CapturedRequest;
import com.workflowscanner.data.RequestConverter;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Detects relationships between request nodes using five heuristics:
 * 1. Redirect chains (3xx Location header)
 * 2. Referrer header analysis
 * 3. Time window correlation
 * 4. Parameter reuse detection (via inverted index)
 * 5. Response-to-request correlation (Set-Cookie, JSON values)
 *
 * Uses an inverted value index for O(1) parameter reuse lookups.
 * Edge computation is incremental: only new nodes are checked against existing nodes.
 */
public class RelationshipDetector {

    /** Default time window for temporal correlation (milliseconds). */
    private static final long DEFAULT_TIME_WINDOW_MS = 5000;

    private final RequestGraph graph;
    private final ExtensionLogger logger;

    /**
     * Inverted index: value -> set of node IDs whose RESPONSE contains that value.
     * Used for fast parameter reuse detection.
     */
    private final Map<String, Set<String>> responseValueIndex = new ConcurrentHashMap<>();

    public RelationshipDetector(RequestGraph graph, ExtensionLogger logger) {
        this.graph = graph;
        this.logger = logger;
    }

    /**
     * Compute all edges for a newly added node against existing nodes.
     * This is the main entry point called by GraphBuilder for each new node.
     * Returns the list of new edges created.
     */
    public List<RequestEdge> detectRelationships(RequestNode newNode) {
        List<RequestEdge> newEdges = new ArrayList<>();

        // Run all five heuristics
        newEdges.addAll(detectRedirectChains(newNode));
        newEdges.addAll(detectReferrerLinks(newNode));
        newEdges.addAll(detectTimeWindowCorrelation(newNode));
        newEdges.addAll(detectParameterReuse(newNode));
        newEdges.addAll(detectResponseCorrelation(newNode));
        newEdges.addAll(detectUserDefinedGroups(newNode));

        // Index this node's response values for future lookups
        indexResponseValues(newNode);

        return newEdges;
    }

    // ========================================================================
    // 1. Redirect Chain Detection
    // ========================================================================

    private List<RequestEdge> detectRedirectChains(RequestNode newNode) {
        List<RequestEdge> edges = new ArrayList<>();

        // Check if any existing node's redirect Location matches this node's URL
        for (RequestNode existing : graph.getNodes().values()) {
            if (existing.getId().equals(newNode.getId())) continue;

            // Existing node redirects TO new node?
            if (existing.isRedirect()) {
                String location = existing.getRedirectLocation();
                if (location != null && urlMatches(location, newNode.getUrl())) {
                    RequestEdge edge = new RequestEdge(
                            existing.getId(), newNode.getId(),
                            EdgeType.REDIRECT, 1.0,
                            existing.getStatusCode() + " Location: " + location
                                    + " -> " + newNode.getMethod() + " " + newNode.getUrl());
                    edges.add(edge);
                }
            }

            // New node redirects TO existing node?
            if (newNode.isRedirect()) {
                String location = newNode.getRedirectLocation();
                if (location != null && urlMatches(location, existing.getUrl())) {
                    RequestEdge edge = new RequestEdge(
                            newNode.getId(), existing.getId(),
                            EdgeType.REDIRECT, 1.0,
                            newNode.getStatusCode() + " Location: " + location
                                    + " -> " + existing.getMethod() + " " + existing.getUrl());
                    edges.add(edge);
                }
            }
        }
        return edges;
    }

    // ========================================================================
    // 2. Referrer Header Analysis
    // ========================================================================

    private List<RequestEdge> detectReferrerLinks(RequestNode newNode) {
        List<RequestEdge> edges = new ArrayList<>();
        CapturedRequest newReq = newNode.getRequest();
        if (newReq == null) return edges;

        String referrer = newReq.getReferrer();

        // New node has a Referer pointing to an existing node?
        if (referrer != null && !referrer.isEmpty()) {
            for (RequestNode existing : graph.getNodes().values()) {
                if (existing.getId().equals(newNode.getId())) continue;
                if (urlMatches(referrer, existing.getUrl())) {
                    RequestEdge edge = new RequestEdge(
                            existing.getId(), newNode.getId(),
                            EdgeType.REFERRER, 0.9,
                            "Referer header: " + referrer + " matches " + existing.getUrl());
                    edges.add(edge);
                    break; // One referrer match is enough
                }
            }
        }

        // Any existing node has a Referer pointing to the new node?
        for (RequestNode existing : graph.getNodes().values()) {
            if (existing.getId().equals(newNode.getId())) continue;
            CapturedRequest existingReq = existing.getRequest();
            if (existingReq == null) continue;

            String existingReferrer = existingReq.getReferrer();
            if (existingReferrer != null && urlMatches(existingReferrer, newNode.getUrl())) {
                RequestEdge edge = new RequestEdge(
                        newNode.getId(), existing.getId(),
                        EdgeType.REFERRER, 0.9,
                        "Referer header: " + existingReferrer + " matches " + newNode.getUrl());
                edges.add(edge);
            }
        }

        return edges;
    }

    // ========================================================================
    // 3. Time Window Correlation
    // ========================================================================

    private List<RequestEdge> detectTimeWindowCorrelation(RequestNode newNode) {
        List<RequestEdge> edges = new ArrayList<>();

        for (RequestNode existing : graph.getNodes().values()) {
            if (existing.getId().equals(newNode.getId())) continue;

            // Same host only
            if (!sameHost(newNode, existing)) continue;

            long timeDiff = Math.abs(newNode.getTimestamp() - existing.getTimestamp());
            if (timeDiff > 0 && timeDiff <= DEFAULT_TIME_WINDOW_MS) {
                // Don't create time window edges if a stronger relationship already exists
                if (hasStrongerEdge(newNode.getId(), existing.getId())) continue;

                // Confidence scales with proximity (closer = higher)
                double confidence = 0.3 + (0.2 * (1.0 - (double) timeDiff / DEFAULT_TIME_WINDOW_MS));

                // Determine direction by timestamp
                String sourceId = existing.getTimestamp() < newNode.getTimestamp()
                        ? existing.getId() : newNode.getId();
                String targetId = sourceId.equals(existing.getId())
                        ? newNode.getId() : existing.getId();

                RequestEdge edge = new RequestEdge(
                        sourceId, targetId,
                        EdgeType.TIME_WINDOW, confidence,
                        "Same host, " + timeDiff + "ms apart");
                edges.add(edge);
            }
        }
        return edges;
    }

    // ========================================================================
    // 4. Parameter Reuse Detection (via Inverted Index)
    // ========================================================================

    private List<RequestEdge> detectParameterReuse(RequestNode newNode) {
        List<RequestEdge> edges = new ArrayList<>();

        // Get all parameter values from the new node's REQUEST
        Set<String> requestValues = ParameterExtractor.getInterestingValues(
                newNode.getExtractedParams());

        // Check if any of these values exist in a previous node's RESPONSE
        for (String value : requestValues) {
            Set<String> sourceNodeIds = responseValueIndex.get(value);
            if (sourceNodeIds == null) continue;

            for (String sourceNodeId : sourceNodeIds) {
                if (sourceNodeId.equals(newNode.getId())) continue;

                RequestNode sourceNode = graph.getNode(sourceNodeId);
                if (sourceNode == null) continue;

                // Only link if source is older than target
                if (sourceNode.getTimestamp() >= newNode.getTimestamp()) continue;

                // Find which param name contains this value
                String paramName = findParamName(newNode.getExtractedParams(), value);
                String responseName = findParamName(sourceNode.getResponseData(), value);

                RequestEdge edge = new RequestEdge(
                        sourceNodeId, newNode.getId(),
                        EdgeType.PARAM_REUSE, 0.8,
                        "Value '" + truncate(value, 40) + "' from response "
                                + (responseName != null ? "(" + responseName + ")" : "")
                                + " of Node#" + sourceNode.getNodeIndex()
                                + " reused in request "
                                + (paramName != null ? "(" + paramName + ")" : "")
                                + " of Node#" + newNode.getNodeIndex());
                edges.add(edge);
            }
        }

        return edges;
    }

    // ========================================================================
    // 5. Response-to-Request Correlation
    // ========================================================================

    private List<RequestEdge> detectResponseCorrelation(RequestNode newNode) {
        List<RequestEdge> edges = new ArrayList<>();

        // Check Set-Cookie -> Cookie chains
        Map<String, Object> newParams = newNode.getExtractedParams();
        for (Map.Entry<String, Object> entry : newParams.entrySet()) {
            if (!entry.getKey().startsWith("cookie.")) continue;
            String cookieName = entry.getKey().substring(7);
            String cookieValue = entry.getValue().toString();

            // Look for a Set-Cookie with the same name in previous responses
            for (RequestNode existing : graph.getNodes().values()) {
                if (existing.getId().equals(newNode.getId())) continue;
                if (existing.getTimestamp() >= newNode.getTimestamp()) continue;

                Object setCookieValue = existing.getResponseData().get("set-cookie." + cookieName);
                if (setCookieValue != null && setCookieValue.toString().equals(cookieValue)) {
                    RequestEdge edge = new RequestEdge(
                            existing.getId(), newNode.getId(),
                            EdgeType.RESPONSE_CORRELATION, 0.85,
                            "Set-Cookie '" + cookieName + "' from Node#" + existing.getNodeIndex()
                                    + " used as Cookie in Node#" + newNode.getNodeIndex());
                    edges.add(edge);
                }
            }
        }

        return edges;
    }

    // ========================================================================
    // 6. User-Defined Groups (Context Menu)
    // ========================================================================

    private List<RequestEdge> detectUserDefinedGroups(RequestNode newNode) {
        List<RequestEdge> edges = new ArrayList<>();
        if (newNode.getGroupId() == null) return edges;

        // Link to other nodes in the same group
        for (RequestNode existing : graph.getNodes().values()) {
            if (existing.getId().equals(newNode.getId())) continue;
            if (newNode.getGroupId().equals(existing.getGroupId())) {
                // Direction by timestamp
                String sourceId = existing.getTimestamp() < newNode.getTimestamp()
                        ? existing.getId() : newNode.getId();
                String targetId = sourceId.equals(existing.getId())
                        ? newNode.getId() : existing.getId();

                RequestEdge edge = new RequestEdge(
                        sourceId, targetId,
                        EdgeType.USER_DEFINED, 1.0,
                        "User-grouped via context menu (group: " + newNode.getGroupId() + ")");
                edges.add(edge);
            }
        }
        return edges;
    }

    // ========================================================================
    // Inverted Index Management
    // ========================================================================

    /**
     * Index all interesting values from a node's response data.
     */
    private void indexResponseValues(RequestNode node) {
        Set<String> values = ParameterExtractor.getInterestingValues(node.getResponseData());
        for (String value : values) {
            responseValueIndex.computeIfAbsent(value, k -> ConcurrentHashMap.newKeySet())
                    .add(node.getId());
        }
    }

    /**
     * Rebuild the entire inverted index (e.g., after loading from disk).
     */
    public void rebuildIndex() {
        responseValueIndex.clear();
        for (RequestNode node : graph.getNodes().values()) {
            indexResponseValues(node);
        }
        logger.log(LogCategory.GRAPH, LogLevel.INFO, "RelationshipDetector",
                "Inverted index rebuilt. Indexed values: " + responseValueIndex.size());
    }

    public int getIndexSize() {
        return responseValueIndex.size();
    }

    // ========================================================================
    // Utility Methods
    // ========================================================================

    /**
     * Check if two URLs match (with normalization).
     */
    private boolean urlMatches(String url1, String url2) {
        if (url1 == null || url2 == null) return false;
        // Normalize: strip trailing slash, fragments, lowercase
        String n1 = normalizeUrl(url1);
        String n2 = normalizeUrl(url2);
        if (n1.equals(n2)) return true;

        // Also check if url1 is a relative path matching url2's path
        if (url1.startsWith("/")) {
            String path2 = RequestConverter.extractPath(url2);
            return url1.equals(path2);
        }
        return false;
    }

    private String normalizeUrl(String url) {
        if (url == null) return "";
        String normalized = url.toLowerCase();
        // Strip fragment
        int hashIdx = normalized.indexOf('#');
        if (hashIdx >= 0) normalized = normalized.substring(0, hashIdx);
        // Strip trailing slash
        if (normalized.endsWith("/") && normalized.length() > 1) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private boolean sameHost(RequestNode a, RequestNode b) {
        if (a.getHost() == null || b.getHost() == null) return false;
        return a.getHost().equalsIgnoreCase(b.getHost());
    }

    /**
     * Check if a stronger edge already exists between two nodes.
     */
    private boolean hasStrongerEdge(String nodeId1, String nodeId2) {
        for (RequestEdge edge : graph.getEdges()) {
            if ((edge.getSourceNodeId().equals(nodeId1) && edge.getTargetNodeId().equals(nodeId2))
                    || (edge.getSourceNodeId().equals(nodeId2) && edge.getTargetNodeId().equals(nodeId1))) {
                if (edge.getType() != EdgeType.TIME_WINDOW) {
                    return true;
                }
            }
        }
        return false;
    }

    private String findParamName(Map<String, Object> params, String value) {
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
}

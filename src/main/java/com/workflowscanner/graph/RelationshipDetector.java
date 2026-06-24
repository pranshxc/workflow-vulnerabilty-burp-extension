package com.workflowscanner.graph;

import com.workflowscanner.classification.EdgeStrength;
import com.workflowscanner.classification.RequestClassification;
import com.workflowscanner.classification.RequestIntent;
import com.workflowscanner.classification.ValueKind;
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
 */
public class RelationshipDetector {

    private final RequestGraph graph;
    private final ExtensionLogger logger;

    // Inverted index: value -> set of node IDs whose RESPONSE contains that value
    private final Map<String, Set<String>> responseValueIndex = new ConcurrentHashMap<>();

    // Session cookie names that should never create workflow edges
    private static final Set<String> SESSION_COOKIE_NAMES = Set.of(
            "jsessionid", "phpsessid", "connect.sid", "session", "_auth",
            "access_token", "refresh_token", "sid", "token", "auth_",
            "awsalb", "lb", "sessionid", "__cfduid", "cfid", "cftoken",
            "rememberme", "remember_me", "xsrf-token", "x-csrf-token");

    public RelationshipDetector(RequestGraph graph, ExtensionLogger logger) {
        this.graph = graph;
        this.logger = logger;
    }

    /**
     * Compute all edges for a newly added node against existing nodes.
     */
    public List<RequestEdge> detectRelationships(RequestNode newNode) {
        List<RequestEdge> newEdges = new ArrayList<>();

        newEdges.addAll(detectRedirectChains(newNode));
        newEdges.addAll(detectReferrerLinks(newNode));
        // TIME_WINDOW is intentionally omitted — context-only, no edges created
        newEdges.addAll(detectParameterReuse(newNode));
        newEdges.addAll(detectResponseCorrelation(newNode));
        newEdges.addAll(detectUserDefinedGroups(newNode));

        // Index this node's response values for future lookups
        indexResponseValues(newNode);

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
                // Business token correlation = MEDIUM, cookie correlation = CONTEXT_ONLY
                if (edge.getEvidence() != null && edge.getEvidence().contains("Set-Cookie")) {
                    return EdgeStrength.CONTEXT_ONLY;
                }
                return EdgeStrength.MEDIUM;
            case TIME_WINDOW:
                return EdgeStrength.WEAK;
            default:
                return EdgeStrength.WEAK;
        }
    }

    private boolean isBusinessValueFlow(RequestEdge edge) {
        // PARAM_REUSE edges containing business IDs or tokens are strong
        // This is a heuristic based on evidence text — could be improved
        return edge.getConfidence() >= 0.8;
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

        for (RequestNode existing : graph.getNodes().values()) {
            if (existing.getId().equals(newNode.getId())) continue;

            if (existing.isRedirect()) {
                String location = existing.getRedirectLocation();
                if (location != null && urlMatches(location, newNode.getUrl())) {
                    edges.add(new RequestEdge(
                            existing.getId(), newNode.getId(),
                            EdgeType.REDIRECT, 1.0,
                            existing.getStatusCode() + " Location: " + location
                                    + " -> " + newNode.getMethod() + " " + newNode.getUrl()));
                }
            }

            if (newNode.isRedirect()) {
                String location = newNode.getRedirectLocation();
                if (location != null && urlMatches(location, existing.getUrl())) {
                    edges.add(new RequestEdge(
                            newNode.getId(), existing.getId(),
                            EdgeType.REDIRECT, 1.0,
                            newNode.getStatusCode() + " Location: " + location
                                    + " -> " + existing.getMethod() + " " + existing.getUrl()));
                }
            }
        }
        return edges;
    }

    // ========================================================================
    // 2. Referrer Header Analysis (tiered confidence based on target intent)
    // ========================================================================

    private List<RequestEdge> detectReferrerLinks(RequestNode newNode) {
        List<RequestEdge> edges = new ArrayList<>();
        CapturedRequest newReq = newNode.getRequest();
        if (newReq == null) return edges;

        String referrer = newReq.getReferrer();

        if (referrer != null && !referrer.isEmpty()) {
            for (RequestNode existing : graph.getNodes().values()) {
                if (existing.getId().equals(newNode.getId())) continue;
                if (urlMatches(referrer, existing.getUrl())) {
                    double confidence = isBusinessRelevant(newNode) ? 0.85 : 0.5;
                    edges.add(new RequestEdge(
                            existing.getId(), newNode.getId(),
                            EdgeType.REFERRER, confidence,
                            "Referer header: " + referrer + " matches " + existing.getUrl()));
                    break;
                }
            }
        }

        for (RequestNode existing : graph.getNodes().values()) {
            if (existing.getId().equals(newNode.getId())) continue;
            CapturedRequest existingReq = existing.getRequest();
            if (existingReq == null) continue;

            String existingReferrer = existingReq.getReferrer();
            if (existingReferrer != null && urlMatches(existingReferrer, newNode.getUrl())) {
                double confidence = isBusinessRelevant(existing) ? 0.85 : 0.5;
                edges.add(new RequestEdge(
                        newNode.getId(), existing.getId(),
                        EdgeType.REFERRER, confidence,
                        "Referer header: " + existingReferrer + " matches " + newNode.getUrl()));
            }
        }
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

            Set<String> sourceNodeIds = responseValueIndex.get(paramValue);
            if (sourceNodeIds == null) continue;

            for (String sourceNodeId : sourceNodeIds) {
                if (sourceNodeId.equals(newNode.getId())) continue;
                RequestNode sourceNode = graph.getNode(sourceNodeId);
                if (sourceNode == null || sourceNode.getTimestamp() >= newNode.getTimestamp()) continue;

                String responseName = findParamName(sourceNode.getResponseData(), paramValue);
                edges.add(new RequestEdge(
                        sourceNodeId, newNode.getId(),
                        EdgeType.PARAM_REUSE, 0.8,
                        "Value '" + truncate(paramValue, 40) + "' from response "
                                + (responseName != null ? "(" + responseName + ")" : "")
                                + " of Node#" + sourceNode.getNodeIndex()
                                + " reused in request (" + paramName + ")"
                                + " of Node#" + newNode.getNodeIndex()));
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

            String cookieValue = entry.getValue().toString();

            for (RequestNode existing : graph.getNodes().values()) {
                if (existing.getId().equals(newNode.getId())) continue;
                if (existing.getTimestamp() >= newNode.getTimestamp()) continue;

                Object setCookieValue = existing.getResponseData().get("set-cookie." + cookieName);
                if (setCookieValue != null && setCookieValue.toString().equals(cookieValue)) {
                    edges.add(new RequestEdge(
                            existing.getId(), newNode.getId(),
                            EdgeType.RESPONSE_CORRELATION, 0.85,
                            "Set-Cookie '" + cookieName + "' from Node#" + existing.getNodeIndex()
                                    + " used as Cookie in Node#" + newNode.getNodeIndex()));
                }
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

        for (RequestNode existing : graph.getNodes().values()) {
            if (existing.getId().equals(newNode.getId())) continue;
            if (newNode.getGroupId().equals(existing.getGroupId())) {
                String sourceId = existing.getTimestamp() < newNode.getTimestamp()
                        ? existing.getId() : newNode.getId();
                String targetId = sourceId.equals(existing.getId())
                        ? newNode.getId() : existing.getId();
                edges.add(new RequestEdge(
                        sourceId, targetId,
                        EdgeType.USER_DEFINED, 1.0,
                        "User-grouped via context menu (group: " + newNode.getGroupId() + ")"));
            }
        }
        return edges;
    }

    // ========================================================================
    // Inverted Index Management
    // ========================================================================

    private void indexResponseValues(RequestNode node) {
        Set<String> values = ParameterExtractor.getInterestingValues(node.getResponseData());
        for (String value : values) {
            responseValueIndex.computeIfAbsent(value, k -> ConcurrentHashMap.newKeySet())
                    .add(node.getId());
        }
    }

    public void rebuildIndex() {
        responseValueIndex.clear();
        for (RequestNode node : graph.getNodes().values()) {
            indexResponseValues(node);
        }
        logger.log(LogCategory.GRAPH, LogLevel.INFO, "RelationshipDetector",
                "Inverted index rebuilt. Indexed values: " + responseValueIndex.size());
    }

    public int getIndexSize() { return responseValueIndex.size(); }

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
}

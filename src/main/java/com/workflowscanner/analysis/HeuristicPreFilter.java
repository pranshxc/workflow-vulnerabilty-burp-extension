package com.workflowscanner.analysis;

import com.workflowscanner.graph.RequestNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Fast heuristic pre-filtering before LLM analysis.
 * Identifies signals that boost chain priority and provide additional context.
 * These checks run in <100ms per chain.
 */
public class HeuristicPreFilter {

    private static final Set<String> STATE_CHANGING = Set.of("POST", "PUT", "DELETE", "PATCH");

    private static final Set<String> CSRF_TOKEN_NAMES = Set.of(
            "csrf", "csrf_token", "csrftoken", "_csrf", "xsrf", "xsrf_token",
            "_token", "authenticity_token", "__requestverificationtoken");

    private static final Set<String> TAMPERABLE_PARAM_NAMES = Set.of(
            "price", "amount", "total", "quantity", "qty", "cost",
            "role", "admin", "is_admin", "isadmin", "privilege",
            "discount", "coupon", "credit", "balance");

    /**
     * Run all heuristic checks on a chain.
     * Returns a list of signals found.
     */
    public List<HeuristicSignal> analyze(List<RequestNode> chain) {
        List<HeuristicSignal> signals = new ArrayList<>();

        for (RequestNode node : chain) {
            signals.addAll(checkMissingCsrf(node));
            signals.addAll(checkTamperableParams(node));
            signals.addAll(checkSessionFixation(node, chain));
            signals.addAll(checkMissingRateLimit(node));
        }

        return signals;
    }

    /**
     * Detect state-changing requests without CSRF tokens.
     */
    private List<HeuristicSignal> checkMissingCsrf(RequestNode node) {
        List<HeuristicSignal> signals = new ArrayList<>();
        String method = node.getMethod() != null ? node.getMethod().toUpperCase() : "GET";

        if (!STATE_CHANGING.contains(method)) return signals;

        // Check if any parameter looks like a CSRF token
        Map<String, Object> params = node.getExtractedParams();
        if (params != null) {
            for (String paramName : params.keySet()) {
                String lower = paramName.toLowerCase();
                for (String csrfName : CSRF_TOKEN_NAMES) {
                    if (lower.contains(csrfName)) return signals; // Has CSRF token
                }
            }
        }

        signals.add(new HeuristicSignal(
                HeuristicSignal.Type.MISSING_CSRF,
                "Node#" + node.getNodeIndex() + " (" + method + " " + node.getPath()
                        + ") is state-changing but has no CSRF token parameter",
                node.getNodeIndex()));
        return signals;
    }

    /**
     * Detect parameters that look like they could be tampered with.
     */
    private List<HeuristicSignal> checkTamperableParams(RequestNode node) {
        List<HeuristicSignal> signals = new ArrayList<>();
        Map<String, Object> params = node.getExtractedParams();
        if (params == null) return signals;

        for (Map.Entry<String, Object> entry : params.entrySet()) {
            String lower = entry.getKey().toLowerCase();
            for (String tamperName : TAMPERABLE_PARAM_NAMES) {
                if (lower.contains(tamperName)) {
                    signals.add(new HeuristicSignal(
                            HeuristicSignal.Type.TAMPERABLE_PARAM,
                            "Node#" + node.getNodeIndex() + " has potentially tamperable parameter: "
                                    + entry.getKey() + "=" + entry.getValue(),
                            node.getNodeIndex()));
                    break;
                }
            }
        }
        return signals;
    }

    /**
     * Detect session tokens that don't rotate after authentication.
     */
    private List<HeuristicSignal> checkSessionFixation(RequestNode node, List<RequestNode> chain) {
        List<HeuristicSignal> signals = new ArrayList<>();

        // Look for auth-related endpoints
        String path = node.getPath() != null ? node.getPath().toLowerCase() : "";
        boolean isAuthEndpoint = path.contains("login") || path.contains("signin")
                || path.contains("auth") || path.contains("token");

        if (!isAuthEndpoint) return signals;

        // Check if Set-Cookie is present in response (session should rotate)
        Map<String, Object> responseData = node.getResponseData();
        if (responseData != null) {
            boolean hasSetCookie = responseData.keySet().stream()
                    .anyMatch(k -> k.startsWith("set-cookie."));
            if (!hasSetCookie && node.getStatusCode() >= 200 && node.getStatusCode() < 400) {
                signals.add(new HeuristicSignal(
                        HeuristicSignal.Type.SESSION_FIXATION,
                        "Node#" + node.getNodeIndex() + " (" + path
                                + ") is an auth endpoint but doesn't set new session cookies",
                        node.getNodeIndex()));
            }
        }
        return signals;
    }

    /**
     * Detect endpoints that don't have rate-limiting headers.
     */
    private List<HeuristicSignal> checkMissingRateLimit(RequestNode node) {
        List<HeuristicSignal> signals = new ArrayList<>();
        String method = node.getMethod() != null ? node.getMethod().toUpperCase() : "GET";
        if (!STATE_CHANGING.contains(method)) return signals;

        // Check for rate-limit response headers
        if (node.getRequest() != null && node.getRequest().getResponseHeaders() != null) {
            boolean hasRateLimit = node.getRequest().getResponseHeaders().keySet().stream()
                    .anyMatch(h -> h.toLowerCase().contains("rate-limit")
                            || h.toLowerCase().contains("ratelimit")
                            || h.toLowerCase().contains("x-rate"));
            if (!hasRateLimit) {
                signals.add(new HeuristicSignal(
                        HeuristicSignal.Type.MISSING_RATE_LIMIT,
                        "Node#" + node.getNodeIndex() + " (" + method + " " + node.getPath()
                                + ") has no rate-limiting response headers",
                        node.getNodeIndex()));
            }
        }
        return signals;
    }

    /**
     * A heuristic signal detected during pre-filtering.
     */
    public static class HeuristicSignal {
        public enum Type {
            MISSING_CSRF,
            TAMPERABLE_PARAM,
            SESSION_FIXATION,
            MISSING_RATE_LIMIT
        }

        public final Type type;
        public final String description;
        public final int nodeIndex;

        public HeuristicSignal(Type type, String description, int nodeIndex) {
            this.type = type;
            this.description = description;
            this.nodeIndex = nodeIndex;
        }

        @Override
        public String toString() {
            return "[" + type + "] " + description;
        }
    }
}

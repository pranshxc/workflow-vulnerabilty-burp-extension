package com.workflowscanner.workflow;

import com.workflowscanner.classification.BusinessKeywordRules;
import com.workflowscanner.classification.RequestIntent;
import com.workflowscanner.classification.RequestClassification;
import com.workflowscanner.config.ExtensionConfig;
import com.workflowscanner.graph.RequestNode;

/**
 * Detects workflow boundaries: where a workflow starts, continues, ends, or resets.
 * Uses deterministic rules on path patterns, method transitions, response codes, and time gaps.
 */
public class WorkflowBoundaryDetector {

    private final long idleTimeoutMs;

    public WorkflowBoundaryDetector(ExtensionConfig config) {
        this.idleTimeoutMs = config.getWorkflowSessionWindowMs();
    }

    /**
     * Check if a node signals the start of a new workflow.
     */
    public boolean startsWorkflow(RequestNode node) {
        if (node == null) return false;
        String path = node.getPath() != null ? node.getPath().toLowerCase() : "";
        String method = node.getMethod() != null ? node.getMethod().toUpperCase() : "GET";

        // GET to a form/page that starts a workflow
        if ("GET".equals(method)) {
            if (path.contains("login") || path.contains("signin") || path.contains("sign-up"))
                return true;
            if (path.contains("register") || path.contains("signup") || path.contains("sign-up"))
                return true;
            if (path.contains("cart") || path.contains("checkout")) return true;
            if (path.contains("reset") && path.contains("password")) return true;
            if (path.contains("settings") || path.contains("profile")) return true;
            if ((path.contains("create") || path.contains("new"))
                    && !path.contains("notification"))
                return true;
            if (path.endsWith("/new") || path.contains("/new/")) return true;
        }

        // POST to start/begin/create endpoints
        if (BusinessKeywordRules.isStateChanging(method)) {
            if (path.contains("/start") || path.contains("/begin")) return true;
            if (path.contains("/create") && path.contains("/api/")) return true;
            if (path.contains("/init") || path.contains("/initialize")) return true;
        }

        // 201 Created — use as signal, not hard boundary
        // Only treat as start if the path suggests a creation workflow
        if (node.getStatusCode() == 201) {
            if (path.contains("/start") || path.contains("/begin")
                    || path.contains("/init") || path.contains("/initialize")) {
                return true;
            }
            // POST to a new-resource path typically opens a workflow, not ends one
            if (BusinessKeywordRules.isStateChanging(method)
                    && (path.matches(".*/api/.*") || path.contains("create"))) {
                return false; // Let continuesWorkflow/evidence handle it
            }
            // By default, don't treat 201 as a hard start
            return false;
        }

        return false;
    }

    /**
     * Check if a node continues an existing workflow.
     */
    public boolean continuesWorkflow(RequestNode previous, RequestNode current) {
        if (previous == null || current == null) return false;

        // Same host check
        if (!sameHost(previous, current)) return false;

        // Referrer chain: current request's referrer points to previous request
        String currentUrl = current.getUrl();
        String referrer = getReferrer(current);
        String prevUrl = previous.getUrl();

        if (referrer != null && prevUrl != null && urlsMatch(referrer, prevUrl)) return true;

        // Method transition pattern (GET->POST is typical workflow)
        String prevMethod = previous.getMethod() != null ? previous.getMethod().toUpperCase() : "GET";
        String currMethod = current.getMethod() != null ? current.getMethod().toUpperCase() : "GET";
        if ("GET".equals(prevMethod) && BusinessKeywordRules.isStateChanging(currMethod)) return true;

        // Same path family (e.g., /checkout/shipping -> /checkout/payment)
        String prevPath = previous.getPath() != null ? previous.getPath().toLowerCase() : "";
        String currPath = current.getPath() != null ? current.getPath().toLowerCase() : "";
        if (samePathFamily(prevPath, currPath)) return true;

        // Redirect chain
        if (previous.isRedirect() && previous.getRedirectLocation() != null
                && current.getUrl() != null
                && previous.getRedirectLocation().equals(current.getUrl())) return true;

        // Same session cookie hash (within same user session)
        if (previous.getGroupId() != null && current.getGroupId() != null
                && previous.getGroupId().equals(current.getGroupId())) return true;

        return false;
    }

    /**
     * Check if a node signals the end of a workflow.
     */
    public boolean endsWorkflow(RequestNode node) {
        if (node == null) return false;
        String path = node.getPath() != null ? node.getPath().toLowerCase() : "";
        String method = node.getMethod() != null ? node.getMethod().toUpperCase() : "GET";

        // Confirmation/success pages
        if (path.contains("/confirmation") || path.contains("/confirm")
                || path.contains("/success") || path.contains("/complete")
                || path.contains("/done")) return true;

        // 201 Created — use as signal, not hard end boundary
        // Only treat as end if the path suggests a terminal action
        if (node.getStatusCode() == 201) {
            // POST to a completion endpoint = workflow end
            if (path.contains("/complete") || path.contains("/finish")
                    || path.contains("/confirm") || path.contains("/success")) {
                return true;
            }
            // Otherwise, 201 is mid-workflow (e.g., adding items to cart)
            return false;
        }

        // 303 redirect to a result page
        if (node.getStatusCode() == 303) return true;

        // POST to submit/finish endpoints
        if ("POST".equals(method) && (path.contains("/submit") || path.contains("/finish")
                || path.contains("/complete") || path.contains("/confirm"))) return true;

        // Terminal paths: order/{id}, dashboard (after completing an action)
        if (path.matches(".*/orders?/\\d+.*") || path.matches(".*/orders?/[a-f0-9]+.*")) return true;

        // Logout ends the session's workflow
        if (path.contains("logout") || path.contains("signout") || path.contains("sign-out"))
            return true;

        return false;
    }

    /**
     * Check if there's a boundary reset between two nodes (new workflow should start).
     * Checks continuesWorkflow BEFORE startsWorkflow to avoid over-splitting
     * real workflows that happen to also match start patterns.
     */
    public boolean isBoundaryReset(RequestNode previous, RequestNode current) {
        if (previous == null || current == null) return true;

        // Different host = definitely a reset
        if (!sameHost(previous, current)) return true;

        // Large time gap (use configurable session window)
        long gap = current.getTimestamp() - previous.getTimestamp();
        if (gap > idleTimeoutMs) return true;

        // If current continues the previous workflow, it's NOT a reset
        // even if it also matches a start pattern
        if (continuesWorkflow(previous, current)) return false;

        // Logout before current request
        String prevPath = previous.getPath() != null ? previous.getPath().toLowerCase() : "";
        if (prevPath.contains("logout") || prevPath.contains("signout")) return true;

        // Start of a new, different workflow type (only if not continuing previous)
        if (startsWorkflow(current)) return true;

        // Classification changed from business action to static/background
        RequestClassification prevClass = previous.getClassification();
        RequestClassification currClass = current.getClassification();
        if (prevClass != null && currClass != null) {
            if (prevClass.isWorkflowRelevant() && currClass.isBackground()) return true;
        }

        return false;
    }

    // --- Helpers ---

    private boolean sameHost(RequestNode a, RequestNode b) {
        if (a.getHost() == null || b.getHost() == null) return false;
        return a.getHost().equalsIgnoreCase(b.getHost());
    }

    private boolean samePathFamily(String path1, String path2) {
        // Check if both paths share the same first 2-3 segments
        String[] segs1 = path1.split("/");
        String[] segs2 = path2.split("/");
        int minLen = Math.min(segs1.length, segs2.length);
        if (minLen < 2) return false;

        // First 2 segments should match (e.g., /checkout/shipping vs /checkout/payment)
        int checkLen = Math.min(minLen, 3);
        for (int i = 1; i < checkLen; i++) {
            if (segs1.length <= i || segs2.length <= i) return false;
            if (!segs1[i].equals(segs2[i]) && !segs1[i].equals("{int}") && !segs2[i].equals("{int}")
                    && !segs1[i].equals("{uuid}") && !segs2[i].equals("{uuid}")) {
                return false;
            }
        }
        return true;
    }

    private boolean urlsMatch(String url1, String url2) {
        if (url1 == null || url2 == null) return false;
        String n1 = url1.toLowerCase().replaceAll("#.*$", "").replaceAll("/$", "");
        String n2 = url2.toLowerCase().replaceAll("#.*$", "").replaceAll("/$", "");
        return n1.equals(n2);
    }

    private String getReferrer(RequestNode node) {
        if (node.getRequest() != null) {
            String ref = node.getRequest().getReferrer();
            if (ref != null && !ref.isEmpty()) return ref;
        }
        return null;
    }
}

package com.workflowscanner.workflow;

import com.workflowscanner.config.ExtensionConfig;
import com.workflowscanner.graph.RequestNode;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Groups workflow-relevant request nodes by session key, detecting boundaries
 * and emitting completed WorkflowCandidates.
 *
 * Reads chronological nodes (filtered by RequestClassifier), groups by SessionKey,
 * and emits candidates when boundary end signals or idle timeout triggers.
 */
public class WorkflowSessionizer {

    private final WorkflowBoundaryDetector boundaryDetector;
    private final ExtensionConfig config;
    private final ExtensionLogger logger;
    private final Map<SessionKey, WorkflowCandidate> activeWorkflows;
    private final List<WorkflowCandidate> emittedCandidates;

    // Known auth cookie names (lowercase)
    private static final Set<String> AUTH_COOKIE_NAMES = Set.of(
            "jsessionid", "phpsessid", "connect.sid", "session", "sid",
            "auth", "auth_token", "auth-token", "rememberme", "remember_me",
            "token", "access_token", "refresh_token", "identity");

    public WorkflowSessionizer(ExtensionConfig config, ExtensionLogger logger) {
        this.boundaryDetector = new WorkflowBoundaryDetector(config);
        this.config = config;
        this.logger = logger;
        this.activeWorkflows = new ConcurrentHashMap<>();
        this.emittedCandidates = new ArrayList<>();
    }

    /**
     * Segment a list of chronological nodes into workflow candidates.
     * Should be called with nodes already filtered for workflow relevance.
     */
    public List<WorkflowCandidate> segment(List<RequestNode> nodes) {
        List<WorkflowCandidate> newCandidates = new ArrayList<>();
        long idleTimeoutMs = config.getWorkflowSessionWindowMs();

        // Sort by timestamp
        nodes.sort(Comparator.comparingLong(RequestNode::getTimestamp));

        for (RequestNode node : nodes) {
            SessionKey key = buildSessionKey(node);

            WorkflowCandidate active = activeWorkflows.get(key);

            // Check for boundary reset or new workflow start
            if (active == null || boundaryDetector.isBoundaryReset(
                    active.getLastStep(), node)) {

                // Close existing workflow if present
                if (active != null) {
                    closeCandidate(active);
                    newCandidates.add(active);
                }

                // Start new workflow
                active = new WorkflowCandidate(key);
                active.setStartReason(boundaryDetector.startsWorkflow(node)
                        ? "Start signal: " + node.getMethod() + " " + node.getPath()
                        : "New session/context");
                // Populate evidence: start signal
                String startSignal = boundaryDetector.startsWorkflow(node)
                        ? "startsWorkflow: " + node.getMethod() + " " + node.getPath()
                        : "new session for " + key;
                active.getEvidence().addStartSignal(startSignal);
                active.addStep(node);
                activeWorkflows.put(key, active);

                logger.log(LogCategory.GRAPH, LogLevel.DEBUG, "WorkflowSessionizer",
                        "New workflow started: " + key + " [" + node.getMethod() + " " + node.getPath() + "]");
            } else {
                // Continue existing workflow
                if (boundaryDetector.continuesWorkflow(active.getLastStep(), node)) {
                    active.addStep(node);

                    // Populate evidence: continuation signal
                    active.getEvidence().addContinuationSignal(
                            "step added: " + node.getMethod() + " " + node.getPath());

                    // Check for end signal
                    if (boundaryDetector.endsWorkflow(node)) {
                        active.setEndReason("End signal: " + node.getMethod() + " " + node.getPath());
                        active.getEvidence().addEndSignal(
                                "endsWorkflow: " + node.getMethod() + " " + node.getPath());
                        closeCandidate(active);
                        newCandidates.add(active);
                        activeWorkflows.remove(key);
                    }
                } else {
                    // Can't connect to active workflow — could start new one
                    // But check if it belongs to a different context first
                    // For now, add as step (boundary detector was already lenient)
                    active.addStep(node);
                }
            }
        }

        // Emit any remaining active workflows that have been idle too long
        // Use request timestamps, not wall-clock, for full-graph segmentation
        List<SessionKey> staleKeys = new ArrayList<>();
        for (Map.Entry<SessionKey, WorkflowCandidate> entry : activeWorkflows.entrySet()) {
            WorkflowCandidate candidate = entry.getValue();
            if (candidate.size() >= 2) {
                // Find the last node in the steps list
                RequestNode lastStep = candidate.getLastStep();
                RequestNode firstStep = candidate.getSteps().get(0);
                long totalDuration = lastStep != null ? lastStep.getTimestamp() - firstStep.getTimestamp() : 0;
                if (totalDuration > idleTimeoutMs) {
                    candidate.setEndReason("Idle timeout (exceeded session window)");
                    candidate.getEvidence().addEndSignal(
                            "idle timeout after " + (totalDuration / 1000) + "s");
                    closeCandidate(candidate);
                    newCandidates.add(candidate);
                    staleKeys.add(entry.getKey());
                }
            }
        }
        staleKeys.forEach(activeWorkflows::remove);

        emittedCandidates.addAll(newCandidates);
        return newCandidates;
    }

    /**
     * Build a SessionKey from a request node using real auth identity.
     * Auth: JSESSIONID, session, connect.sid, PHPSESSID cookies + Bearer + X-Auth-Token headers
     * Fallback: source IP when no auth identity is found
     * Referrer: normalized to top-level path family (first 3 segments)
     */
    private SessionKey buildSessionKey(RequestNode node) {
        String host = node.getHost() != null ? node.getHost() : "";
        String authHash = extractAuthCookieHash(node);
        String referrerFamily = extractReferrerFamily(node);
        return new SessionKey(host, authHash, referrerFamily);
    }

    /**
     * Extract auth cookies/headers and return a SHA-256 hash.
     * If no auth is found, use source IP as fallback identity.
     */
    private String extractAuthCookieHash(RequestNode node) {
        if (node.getRequest() == null) return "";

        // Collect cookies from request
        Map<String, String> cookies = parseCookies(node.getRequest().getRequestHeaders());
        StringBuilder authValues = new StringBuilder();

        for (String cookieName : AUTH_COOKIE_NAMES) {
            String val = cookies.get(cookieName);
            if (val != null && !val.isEmpty()) {
                if (authValues.length() > 0) authValues.append("|");
                authValues.append(cookieName).append("=").append(val);
            }
        }

        // Authorization: Bearer header
        List<String> authHeaders = node.getRequest().getRequestHeaders().get("Authorization");
        if (authHeaders != null && !authHeaders.isEmpty()) {
            for (String header : authHeaders) {
                if (header.startsWith("Bearer ")) {
                    if (authValues.length() > 0) authValues.append("|");
                    authValues.append("Bearer=").append(header.substring(7));
                }
            }
        }

        // X-Auth-Token header
        List<String> xAuthHeaders = node.getRequest().getRequestHeaders().get("X-Auth-Token");
        if (xAuthHeaders != null && !xAuthHeaders.isEmpty()) {
            if (authValues.length() > 0) authValues.append("|");
            authValues.append("X-Auth-Token=").append(xAuthHeaders.get(0));
        }

        // No auth found — try source IP as fallback identity
        if (authValues.length() == 0) {
            List<String> xForwardedFor = node.getRequest().getRequestHeaders().get("X-Forwarded-For");
            if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
                authValues.append("src_ip=").append(xForwardedFor.get(0).split(",")[0].trim());
            } else {
                // Truly anonymous — return empty string
                return "";
            }
        }

        return sha256(authValues.toString());
    }

    /**
     * Normalize the referrer to its top-level path family (first 3 segments).
     * This prevents one workflow from being split just because the browser
     * navigated through different pages in the same path family.
     */
    private String extractReferrerFamily(RequestNode node) {
        if (node.getRequest() == null) return "";
        String referrer = node.getRequest().getReferrer();
        if (referrer == null || referrer.isEmpty()) return "";

        try {
            URI uri = new URI(referrer);
            String path = uri.getRawPath();
            if (path == null || path.isEmpty() || path.equals("/")) return "/";

            String[] segments = path.split("/");
            StringBuilder family = new StringBuilder();
            int count = 0;
            for (String seg : segments) {
                if (!seg.isEmpty()) {
                    family.append("/").append(seg.toLowerCase());
                    count++;
                    if (count >= 3) break;
                }
            }
            return family.toString();
        } catch (URISyntaxException e) {
            return referrer.length() > 40 ? referrer.substring(0, 40) : referrer;
        }
    }

    /**
     * Parse cookies from request headers into a name-value map.
     */
    private Map<String, String> parseCookies(Map<String, List<String>> headers) {
        Map<String, String> cookies = new java.util.LinkedHashMap<>();
        if (headers == null) return cookies;

        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if ("Cookie".equalsIgnoreCase(entry.getKey()) && entry.getValue() != null) {
                for (String cookieHeader : entry.getValue()) {
                    String[] parts = cookieHeader.split(";");
                    for (String part : parts) {
                        part = part.trim();
                        int eqIdx = part.indexOf('=');
                        if (eqIdx > 0) {
                            String name = part.substring(0, eqIdx).trim().toLowerCase();
                            String value = part.substring(eqIdx + 1).trim();
                            cookies.put(name, value);
                        }
                    }
                }
            }
        }
        return cookies;
    }

    /**
     * SHA-256 hash a string.
     */
    private String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            return Integer.toHexString(input.hashCode());
        }
    }

    private void closeCandidate(WorkflowCandidate candidate) {
        if (candidate.size() < config.getWorkflowMinSteps()) return; // Don't emit single-node candidates

        // Detect workflow type
        candidate.setWorkflowType(WorkflowType.detect(candidate.getSteps()));

        logger.log(LogCategory.GRAPH, LogLevel.INFO, "WorkflowSessionizer",
                "Workflow candidate: " + candidate.size() + " steps, type="
                        + candidate.getWorkflowType() + ", " + candidate.getStartReason()
                        + ", " + candidate.getEndReason());
    }

    public List<WorkflowCandidate> getEmittedCandidates() {
        return new ArrayList<>(emittedCandidates);
    }

    public int getActiveCount() {
        return activeWorkflows.size();
    }

    public void clear() {
        activeWorkflows.clear();
        emittedCandidates.clear();
    }
}

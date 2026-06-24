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
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Groups workflow-relevant request nodes by session key, detecting boundaries
 * and emitting completed WorkflowCandidates.
 *
 * Two API modes:
 * - {@link #segmentFullGraph(List, ExtensionConfig, ExtensionLogger)}: Stateless,
 *   safe for UI/analysis threads. Uses local maps only.
 * - {@link #segmentIncremental(RequestNode)}: Stateful, for live traffic only.
 *   Uses instance-level activeWorkflows/emittedCandidates.
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

    // ========================================================================
    // Stateless full-graph API (safe for UI/analysis threads)
    // ========================================================================

    /**
     * Stateless full-graph segmentation. Uses local maps — no mutation of
     * instance state. Safe to call from UI refresh, analysis pipeline,
     * or any thread without side effects.
     * <p>
     * Idle timeout uses adjacent request gap, not total candidate duration.
     *
     * @param nodes  chronologically sorted workflow-relevant nodes
     * @param config extension configuration
     * @param logger logger
     * @return list of completed workflow candidates
     */
    public static List<WorkflowCandidate> segmentFullGraph(
            List<RequestNode> nodes,
            ExtensionConfig config,
            ExtensionLogger logger) {

        if (nodes == null || nodes.isEmpty()) return List.of();

        WorkflowBoundaryDetector boundaryDetector = new WorkflowBoundaryDetector(config);
        long idleTimeoutMs = config.getWorkflowSessionWindowMs();
        long minSteps = config.getWorkflowMinSteps();

        // Local state — not shared
        Map<SessionKey, WorkflowCandidate> actives = new HashMap<>();
        List<WorkflowCandidate> completed = new ArrayList<>();

        // Sort by timestamp
        List<RequestNode> sorted = new ArrayList<>(nodes);
        sorted.sort(Comparator.comparingLong(RequestNode::getTimestamp));

        for (RequestNode node : sorted) {
            SessionKey key = buildSessionKey(node);
            WorkflowCandidate active = actives.get(key);

            // Check for boundary reset or new workflow start
            if (active == null || boundaryDetector.isBoundaryReset(
                    active.getLastStep(), node)) {

                // Close existing workflow
                if (active != null) {
                    closeAndEmit(active, completed, minSteps, logger);
                }

                // Start new workflow
                active = new WorkflowCandidate(key);
                active.setStartReason(boundaryDetector.startsWorkflow(node)
                        ? "Start signal: " + node.getMethod() + " " + node.getPath()
                        : "New session/context");
                String startSignal = boundaryDetector.startsWorkflow(node)
                        ? "startsWorkflow: " + node.getMethod() + " " + node.getPath()
                        : "new session for " + key;
                active.getEvidence().addStartSignal(startSignal);
                active.addStep(node);
                actives.put(key, active);
            } else {
                // Continue existing workflow
                if (boundaryDetector.continuesWorkflow(active.getLastStep(), node)) {
                    active.addStep(node);
                    active.getEvidence().addContinuationSignal(
                            "step added: " + node.getMethod() + " " + node.getPath());

                    if (boundaryDetector.endsWorkflow(node)) {
                        active.setEndReason("End signal: " + node.getMethod() + " " + node.getPath());
                        active.getEvidence().addEndSignal(
                                "endsWorkflow: " + node.getMethod() + " " + node.getPath());
                        closeAndEmit(active, completed, minSteps, logger);
                        actives.remove(key);
                    }
                } else {
                    // Can't connect — add as step anyway (boundary detector was lenient)
                    active.addStep(node);
                }
            }

            // Idle timeout is handled by WorkflowBoundaryDetector.isBoundaryReset(),
            // which checks the gap between adjacent nodes. This check is intentionally
            // absent here because active.getLastStep() is the node just added, so
            // gap would always be 0.
        }

        // Close any remaining active candidates (no idle check needed for full-graph)
        for (Map.Entry<SessionKey, WorkflowCandidate> entry : actives.entrySet()) {
            closeAndEmit(entry.getValue(), completed, minSteps, logger);
        }

        return completed;
    }

    /**
     * Stateless Segment a list of chronological nodes into workflow candidates.
     * Delegates to {@link #segmentFullGraph(List, ExtensionConfig, ExtensionLogger)}.
     * This is the preferred API for full-graph detection.
     */
    public static List<WorkflowCandidate> segment(List<RequestNode> nodes,
                                                     ExtensionConfig config,
                                                     ExtensionLogger logger) {
        return segmentFullGraph(nodes, config, logger);
    }

    // ========================================================================
    // Stateful incremental API (for live traffic only)
    // ========================================================================

    /**
     * Process a single new node incrementally. Mutates activeWorkflows and
     * emittedCandidates. NOT safe for UI/analysis threads.
     * <p>
     * Idle timeout uses adjacent request gap.
     *
     * @param node the new incoming request node
     * @return completed candidate if one was closed, empty otherwise
     */
    public Optional<WorkflowCandidate> segmentIncremental(RequestNode node) {
        long idleTimeoutMs = config.getWorkflowSessionWindowMs();
        SessionKey key = buildSessionKey(node);
        WorkflowCandidate active = activeWorkflows.get(key);

        if (active == null || boundaryDetector.isBoundaryReset(
                active.getLastStep(), node)) {
            // Close existing
            if (active != null) {
                closeCandidate(active);
                emittedCandidates.add(active);
                activeWorkflows.remove(key);
            }
            // Start new
            active = new WorkflowCandidate(key);
            active.setStartReason(boundaryDetector.startsWorkflow(node)
                    ? "Start signal: " + node.getMethod() + " " + node.getPath()
                    : "New session/context");
            active.getEvidence().addStartSignal(
                    boundaryDetector.startsWorkflow(node)
                            ? "startsWorkflow: " + node.getMethod() + " " + node.getPath()
                            : "new session for " + key);
            active.addStep(node);
            activeWorkflows.put(key, active);
            return Optional.empty();
        }

        // Continue existing
        if (boundaryDetector.continuesWorkflow(active.getLastStep(), node)) {
            // Idle timeout check using adjacent gap
            long gap = node.getTimestamp() - active.getLastStep().getTimestamp();
            if (gap > idleTimeoutMs) {
                active.setEndReason("Idle timeout (gap=" + (gap / 1000) + "s)");
                active.getEvidence().addEndSignal("idle timeout after " + (gap / 1000) + "s gap");
                closeCandidate(active);
                emittedCandidates.add(active);
                activeWorkflows.remove(key);

                // Start new for this node
                WorkflowCandidate replacement = new WorkflowCandidate(key);
                replacement.setStartReason("New after idle gap");
                replacement.getEvidence().addStartSignal("new after idle gap of " + (gap / 1000) + "s");
                replacement.addStep(node);
                activeWorkflows.put(key, replacement);
                logger.log(LogCategory.GRAPH, LogLevel.DEBUG, "WorkflowSessionizer",
                        "Idle gap " + (gap / 1000) + "s, started new candidate for " + key);
                return Optional.of(active);
            }

            active.addStep(node);
            active.getEvidence().addContinuationSignal(
                    "step added: " + node.getMethod() + " " + node.getPath());

            if (boundaryDetector.endsWorkflow(node)) {
                active.setEndReason("End signal: " + node.getMethod() + " " + node.getPath());
                active.getEvidence().addEndSignal(
                        "endsWorkflow: " + node.getMethod() + " " + node.getPath());
                closeCandidate(active);
                emittedCandidates.add(active);
                activeWorkflows.remove(key);
                return Optional.of(active);
            }
        } else {
            active.addStep(node);
        }

        return Optional.empty();
    }

    /**
     * Segment nodes using the (deprecated) stateful approach.
     * Prefer {@link #segmentFullGraph(List, ExtensionConfig, ExtensionLogger)}.
     */
    @Deprecated
    public List<WorkflowCandidate> segment(List<RequestNode> nodes) {
        // For backward compat — delegates to instance logic but also
        // calls incremental for each node to maintain active state
        List<WorkflowCandidate> result = new ArrayList<>();
        for (RequestNode node : nodes) {
            segmentIncremental(node).ifPresent(result::add);
        }
        return result;
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    private static void closeAndEmit(WorkflowCandidate candidate,
                                      List<WorkflowCandidate> completed,
                                      long minSteps,
                                      ExtensionLogger logger) {
        if (candidate.size() < minSteps) return;
        candidate.setWorkflowType(WorkflowType.detect(candidate.getSteps()));
        completed.add(candidate);
        if (logger != null) {
            logger.log(LogCategory.GRAPH, LogLevel.INFO, "WorkflowSessionizer",
                    "Workflow candidate: " + candidate.size() + " steps, type="
                            + candidate.getWorkflowType() + ", "
                            + candidate.getStartReason()
                            + (candidate.getEndReason() != null ? ", " + candidate.getEndReason() : ""));
        }
    }

    /**
     * Build a SessionKey from a request node using real auth identity.
     * Auth: JSESSIONID, session, connect.sid, PHPSESSID cookies + Bearer + X-Auth-Token headers
     * Fallback: source IP when no auth identity is found
     * Referrer: normalized to top-level path family (first 3 segments)
     */
    static SessionKey buildSessionKey(RequestNode node) {
        String host = node.getHost() != null ? node.getHost() : "";
        String authHash = extractAuthCookieHash(node);
        String referrerFamily = extractReferrerFamily(node);
        return new SessionKey(host, authHash, referrerFamily);
    }

    /**
     * Extract auth cookies/headers and return a SHA-256 hash.
     * If no auth is found, use source IP as fallback identity.
     */
    private static String extractAuthCookieHash(RequestNode node) {
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
    private static String extractReferrerFamily(RequestNode node) {
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
    private static Map<String, String> parseCookies(Map<String, List<String>> headers) {
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
    private static String sha256(String input) {
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

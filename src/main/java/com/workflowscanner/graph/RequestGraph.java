package com.workflowscanner.graph;

import com.workflowscanner.config.ExtensionConfig;
import com.workflowscanner.workflow.WorkflowCandidate;
import com.workflowscanner.workflow.WorkflowDetector;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * The core request graph data structure.
 * Thread-safe for concurrent reads (UI, analysis) and writes (graph builder).
 * Supports chain detection, filtering, and statistics.
 *
 * <p><b>Workflow rework:</b> The old {@link #getWorkflowChains()} method (naive BFS)
 * is deprecated in favor of {@link #detectWorkflowCandidates(WorkflowDetector)},
 * which uses intent-aware workflow detection instead of connected components.</p>
 */
public class RequestGraph {

    private final Map<String, RequestNode> nodes = new ConcurrentHashMap<>();
    /**
     * Edges stored in a {@link ConcurrentLinkedQueue} so that backfill
     * (millions of {@code addEdge} calls) does not pay the per-write
     * array-copy cost of {@code CopyOnWriteArrayList}. Iteration is
     * still O(n) but cheap, and the queue is unbounded so it does not
     * reject writes.
     */
    private final Queue<RequestEdge> edges = new ConcurrentLinkedQueue<>();
    private volatile int nextNodeIndex = 0;

    // Monotonic version counter. Incremented on every structural mutation
    // (addNode / addEdge / clear / merge). Used by callers (notably the
    // GraphPanel preview cache) to short-circuit expensive recomputations
    // when the graph has not changed since the last refresh.
    private volatile long graphVersion = 0;

    // O(1) counters maintained by addNode / addEdge / clear / merge so
    // the status panel can read these without scanning the graph or
    // doing connected-component traversals on a 1.6M-node dataset.
    // These are the source of truth for live status; GraphStats is
    // populated from them.
    private final AtomicInteger workflowRelevantNodeCount = new AtomicInteger(0);
    private final ConcurrentHashMap<EdgeType, AtomicInteger> edgesByType =
            new ConcurrentHashMap<>();
    {
        for (EdgeType t : EdgeType.values()) {
            edgesByType.put(t, new AtomicInteger(0));
        }
    }

    // Adjacency lists for efficient traversal. Values are queues
    // (not lists) so backfill does not pay array-copy cost. The
    // BFS in getConnectedComponents() iterates the queue, which
    // is allowed.
    private final Map<String, Queue<String>> outgoing = new ConcurrentHashMap<>(); // nodeId -> targetIds
    private final Map<String, Queue<String>> incoming = new ConcurrentHashMap<>(); // nodeId -> sourceIds

    // Optional reference for enriching graph stats with candidate counts
    private volatile WorkflowDetector workflowDetector;
    private volatile ExtensionConfig config;

    // --- Node Operations ---

    public synchronized RequestNode addNode(RequestNode node) {
        boolean wasNew = !nodes.containsKey(node.getId());
        nodes.put(node.getId(), node);
        outgoing.putIfAbsent(node.getId(), new ConcurrentLinkedQueue<>());
        incoming.putIfAbsent(node.getId(), new ConcurrentLinkedQueue<>());
        if (wasNew) {
            // Maintain O(1) workflow-relevant counter. If the new
            // node replaces an existing one of the same id, do not
            // double-count; the old classification (if any) is
            // effectively overwritten and the new one is what matters.
            com.workflowscanner.classification.RequestClassification cls =
                    node.getClassification();
            if (cls != null && cls.isWorkflowRelevant()) {
                workflowRelevantNodeCount.incrementAndGet();
            }
        }
        graphVersion++;
        return node;
    }

    public void addEdge(RequestEdge edge) {
        edges.add(edge);
        AtomicInteger typeCounter = edgesByType.get(edge.getType());
        if (typeCounter != null) {
            typeCounter.incrementAndGet();
        }
        outgoing.computeIfAbsent(edge.getSourceNodeId(), k -> new ConcurrentLinkedQueue<>())
                .add(edge.getTargetNodeId());
        incoming.computeIfAbsent(edge.getTargetNodeId(), k -> new ConcurrentLinkedQueue<>())
                .add(edge.getSourceNodeId());
        graphVersion++;
    }

    public RequestNode getNode(String nodeId) {
        return nodes.get(nodeId);
    }

    public Map<String, RequestNode> getNodes() {
        return Collections.unmodifiableMap(nodes);
    }

    /**
     * Live edges. Backed by a {@link ConcurrentLinkedQueue} so
     * backfill does not pay array-copy cost. Returns a
     * {@code Collection} (not {@code List}) because the underlying
     * storage is a queue. Callers that need a stable list should
     * snapshot it themselves.
     */
    public java.util.Collection<RequestEdge> getEdges() {
        return edges;
    }

    // --- Filtering ---

    public List<RequestNode> getNodesByHost(String host) {
        List<RequestNode> result = new ArrayList<>();
        for (RequestNode node : nodes.values()) {
            if (host != null && host.equalsIgnoreCase(node.getHost())) {
                result.add(node);
            }
        }
        return result;
    }

    public List<RequestNode> getNodesByPath(String pathPattern) {
        Pattern pattern = Pattern.compile(pathPattern, Pattern.CASE_INSENSITIVE);
        List<RequestNode> result = new ArrayList<>();
        for (RequestNode node : nodes.values()) {
            if (node.getPath() != null && pattern.matcher(node.getPath()).find()) {
                result.add(node);
            }
        }
        return result;
    }

    /**
     * Get all edges connected to a specific node (incoming + outgoing).
     */
    public List<RequestEdge> getEdgesForNode(String nodeId) {
        List<RequestEdge> result = new ArrayList<>();
        for (RequestEdge edge : edges) {
            if (nodeId.equals(edge.getSourceNodeId()) || nodeId.equals(edge.getTargetNodeId())) {
                result.add(edge);
            }
        }
        return result;
    }

    // --- Chain Detection ---

    /**
     * Detect all connected components (subgraphs) via BFS.
     * This is the low-level graph traversal method, replacing the older
     * {@link #getWorkflowChains()} which made naive assumptions about workflow structure.
     *
     * Each component is a list of nodes sorted by timestamp.
     */
    public List<List<RequestNode>> getConnectedComponents() {
        Set<String> visited = new HashSet<>();
        List<List<RequestNode>> components = new ArrayList<>();

        for (String nodeId : nodes.keySet()) {
            if (visited.contains(nodeId)) continue;

            // BFS to find connected component
            List<RequestNode> component = new ArrayList<>();
            Queue<String> queue = new LinkedList<>();
            queue.add(nodeId);
            visited.add(nodeId);

            while (!queue.isEmpty()) {
                String current = queue.poll();
                RequestNode node = nodes.get(current);
                if (node != null) {
                    component.add(node);
                }

                // Follow outgoing edges
                Queue<String> targets = outgoing.get(current);
                if (targets != null) {
                    for (String target : targets) {
                        if (visited.add(target)) {
                            queue.add(target);
                        }
                    }
                }

                // Follow incoming edges
                Queue<String> sources = incoming.get(current);
                if (sources != null) {
                    for (String source : sources) {
                        if (visited.add(source)) {
                            queue.add(source);
                        }
                    }
                }
            }

            // Sort component by timestamp
            component.sort(Comparator.comparingLong(RequestNode::getTimestamp));

            if (component.size() > 1) { // Only include components with 2+ nodes
                components.add(component);
            }
        }

        // Sort components by size (largest first)
        components.sort((a, b) -> Integer.compare(b.size(), a.size()));
        return components;
    }

    /**
     * Detect workflow candidates using intent-aware workflow detection.
     * This is the replacement for {@link #getWorkflowChains()} and should be
     * preferred for all new analysis code.
     *
     * @param detector the WorkflowDetector instance
     * @return sorted list of workflow candidates (highest score first)
     */
    public List<WorkflowCandidate> detectWorkflowCandidates(WorkflowDetector detector) {
        // Use the edge-aware overload that requires graph + relationship detector access
        // The detector receives graph context through its internal graph reference
        List<WorkflowCandidate> candidates = detector.detect(
                new ArrayList<>(nodes.values()));
        // Sort by score descending
        candidates.sort((a, b) -> Double.compare(b.getWorkflowScore(), a.getWorkflowScore()));
        return candidates;
    }

    /**
     * Legacy method: detect all connected subgraphs.
     *
     * @deprecated Replaced by {@link #getConnectedComponents()} for raw traversal
     *             and {@link #detectWorkflowCandidates(WorkflowDetector)} for
     *             workflow-aware analysis. This method creates naive connected-component
     *             chains that do not respect workflow boundaries or intent.
     */
    @Deprecated
    public List<List<RequestNode>> getWorkflowChains() {
        return getConnectedComponents();
    }

    /**
     * Get the full chain containing a specific node (using connected components).
     */
    public List<RequestNode> getChainForNode(String nodeId) {
        for (List<RequestNode> chain : getConnectedComponents()) {
            for (RequestNode node : chain) {
                if (node.getId().equals(nodeId)) {
                    return chain;
                }
            }
        }
        return Collections.emptyList();
    }

    /**
     * Get all unique hosts in the graph.
     */
    public Set<String> getAllHosts() {
        Set<String> hosts = new HashSet<>();
        for (RequestNode node : nodes.values()) {
            if (node.getHost() != null && !node.getHost().isEmpty()) {
                hosts.add(node.getHost());
            }
        }
        return hosts;
    }

    // --- Merge ---

    /**
     * Merge another graph into this one (e.g., backfill data into live graph).
     */
    public void merge(RequestGraph other) {
        boolean changed = false;
        for (RequestNode node : other.nodes.values()) {
            if (!nodes.containsKey(node.getId())) {
                addNode(node);
                changed = true;
            }
        }
        for (RequestEdge edge : other.edges) {
            addEdge(edge);
            changed = true;
        }
        if (changed) graphVersion++;
    }

    // --- Statistics ---

    public int getNodeCount() { return nodes.size(); }
    public int getEdgeCount() { return edges.size(); }

    /**
     * O(1) count of nodes whose classification is workflow-relevant.
     * Workflow-relevant nodes are the ones the workflow detector
     * considers when building candidates. Nodes flagged as
     * background/static-asset/etc. are excluded.
     *
     * <p>The counter is maintained by {@link #addNode(RequestNode)} and
     * reset by {@link #clear()}, so this accessor is safe to call from
     * the status panel timer.
     */
    public int getWorkflowRelevantNodeCount() {
        return workflowRelevantNodeCount.get();
    }

    /**
     * O(1) count of edges of a given type. Maintained by
     * {@link #addEdge(RequestEdge)} and reset by {@link #clear()}.
     */
    public int getEdgeCountByType(EdgeType type) {
        AtomicInteger c = edgesByType.get(type);
        return c == null ? 0 : c.get();
    }

    /**
     * Snapshot of the per-type edge counts. Returns a fresh map so the
     * caller can hold it without worrying about concurrent mutation.
     */
    public java.util.Map<EdgeType, Integer> getEdgeCountsByType() {
        java.util.Map<EdgeType, Integer> snap = new java.util.EnumMap<>(EdgeType.class);
        for (java.util.Map.Entry<EdgeType, AtomicInteger> e : edgesByType.entrySet()) {
            snap.put(e.getKey(), e.getValue().get());
        }
        return snap;
    }

    /**
     * <b>DO NOT CALL FROM UI TIMERS OR BACKFILL.</b>
     *
     * <p>Returns the number of connected components by doing a full
     * BFS over the graph. This is O(n) on a 1.6M-node graph and can
     * freeze Burp. The status panel uses
     * {@link #getComponentCountOnDemand()} only when explicitly
     * requested by a user action.
     *
     * <p>This method is kept for back-compat with any caller that
     * genuinely needs the cheap-looking API. New code should use
     * the workflow detector's live counters for candidate counts,
     * and {@link #getComponentCountOnDemand()} when connected
     * components are actually needed.
     */
    public int getChainCount() {
        return getConnectedComponents().size();
    }

    public synchronized int getNextNodeIndex() {
        return nextNodeIndex++;
    }

    /**
     * Set a reference to the WorkflowDetector for enriching graph statistics
     * with workflow candidate counts.
     */
    public void setWorkflowDetector(WorkflowDetector detector, ExtensionConfig cfg) {
        this.workflowDetector = detector;
        this.config = cfg;
    }

    /**
     * Get the workflow detector wired into this graph, or null if none
     * has been set. Used by the status panel to surface edge-supported
     * vs session-only candidate counts without going through GraphBuilder.
     */
    public WorkflowDetector getWorkflowDetector() { return workflowDetector; }

    /**
     * Repair nextNodeIndex to be higher than any existing node index.
     * Should be called after loading nodes from serialized state.
     */
    public synchronized void recalculateNextNodeIndex() {
        int maxIndex = 0;
        for (RequestNode node : nodes.values()) {
            int nodeIndex = node.getNodeIndex();
            if (nodeIndex >= maxIndex) {
                maxIndex = nodeIndex + 1;
            }
        }
        if (maxIndex > nextNodeIndex) {
            nextNodeIndex = maxIndex;
        }
    }

    /**
     * Live stats. O(1) for the cheap fields. Caller must not depend
     * on connected-component / max-component-size / host-count fields
     * being current — those are populated lazily and may be stale
     * or {@code 0} on the hot path.
     */
    public GraphStats getStats() {
        GraphStats stats = new GraphStats(nodes.size(), edges.size(),
                0,            // componentCount: lazy, see getComponentCountOnDemand()
                0,            // maxComponentSize: lazy
                0);           // hostCount: lazy
        stats.workflowRelevantNodeCount = getWorkflowRelevantNodeCount();
        // Candidate counts come from the workflow detector's live
        // counters (updated by both preview and detect paths). The
        // "analysis-ready" split is computed against the live total.
        if (workflowDetector != null) {
            stats.workflowCandidateCount = workflowDetector.getLiveCandidateCount();
            stats.edgeSupportedCandidateCount = workflowDetector.getLiveEdgeSupportedCount();
            stats.sessionOnlyCandidateCount = workflowDetector.getLiveSessionOnlyCount();
            // For analysis-ready / display-only we still need the
            // list (to read scores). Only do this on-demand if the
            // caller actually wants the breakdown; status panels do
            // not need it.
            if (config != null) {
                double threshold = config.getWorkflowScoreThreshold();
                int ready = 0;
                for (WorkflowCandidate c : workflowDetector.getLastResults()) {
                    if (c.getWorkflowScore() >= threshold) ready++;
                }
                stats.analysisReadyCandidateCount = ready;
                stats.displayOnlyCandidateCount = stats.workflowCandidateCount - ready;
            }
        }
        return stats;
    }

    /**
     * Number of connected components (BFS over the graph). O(n) on a
     * 1.6M-node graph. Use only from explicit user actions like
     * "Show Components" — never from the status panel timer.
     */
    public int getComponentCountOnDemand() {
        return getConnectedComponents().size();
    }

    /**
     * Number of distinct hosts. O(n) on a 1.6M-node graph. Use only
     * from explicit user actions — never from the status panel timer.
     */
    public int getHostCountOnDemand() {
        return getAllHosts().size();
    }

    /**
     * Clear all graph data.
     */
    public synchronized void clear() {
        nodes.clear();
        edges.clear();
        outgoing.clear();
        incoming.clear();
        nextNodeIndex = 0;
        workflowRelevantNodeCount.set(0);
        for (AtomicInteger c : edgesByType.values()) {
            c.set(0);
        }
        graphVersion++;
    }

    /**
     * Monotonic graph version. Increments on every structural mutation
     * (addNode / addEdge / clear / merge). Callers can use this to
     * short-circuit expensive recomputations when the graph has not
     * changed since the last refresh.
     */
    public long getVersion() {
        return graphVersion;
    }

    // --- Stats Record ---

    /**
     * Lightweight stats snapshot.
     *
     * <p>All cheap fields are kept up to date by the graph itself
     * (nodeCount, edgeCount, workflowRelevantNodeCount, candidate
     * counts). The expensive fields — {@code componentCount},
     * {@code maxComponentSize}, {@code hostCount} — require a graph
     * traversal and may be {@code 0} on the hot path. To get accurate
     * values, call {@link #getComponentCountOnDemand()} or
     * {@link #getHostCountOnDemand()} explicitly.
     */
    public static class GraphStats {
        public final int nodeCount;
        public final int edgeCount;
        /** Lazy. 0 unless populated by an explicit on-demand call. */
        public final int componentCount;
        /** Lazy. 0 unless populated by an explicit on-demand call. */
        public final int maxComponentSize;
        /** Lazy. 0 unless populated by an explicit on-demand call. */
        public final int hostCount;

        // Subset of nodes whose classification is workflow-relevant.
        public int workflowRelevantNodeCount;

        // Candidate count placeholders; populated externally by WorkflowDetector
        public int workflowCandidateCount;
        public int analysisReadyCandidateCount;
        public int displayOnlyCandidateCount;
        // Edge-supported (>=1 supporting edge) vs session-only (no edges) split.
        public int edgeSupportedCandidateCount;
        public int sessionOnlyCandidateCount;

        public GraphStats(int nodeCount, int edgeCount, int componentCount,
                          int maxComponentSize, int hostCount) {
            this.nodeCount = nodeCount;
            this.edgeCount = edgeCount;
            this.componentCount = componentCount;
            this.maxComponentSize = maxComponentSize;
            this.hostCount = hostCount;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(String.format("Nodes: %d (relevant: %d), Edges: %d, Components: %d, Max component: %d, Hosts: %d",
                    nodeCount, workflowRelevantNodeCount, edgeCount, componentCount,
                    maxComponentSize, hostCount));
            if (workflowCandidateCount > 0) {
                sb.append(String.format(
                        ", Candidates: %d (edge-supported: %d, session-only: %d, analysis-ready: %d, display-only: %d)",
                        workflowCandidateCount, edgeSupportedCandidateCount,
                        sessionOnlyCandidateCount, analysisReadyCandidateCount,
                        displayOnlyCandidateCount));
            }
            return sb.toString();
        }
    }
}

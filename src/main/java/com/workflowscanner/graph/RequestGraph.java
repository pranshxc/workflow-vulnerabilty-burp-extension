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
import java.util.concurrent.CopyOnWriteArrayList;
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
    private final List<RequestEdge> edges = new CopyOnWriteArrayList<>();
    private volatile int nextNodeIndex = 0;

    // Adjacency lists for efficient traversal
    private final Map<String, List<String>> outgoing = new ConcurrentHashMap<>(); // nodeId -> [targetIds]
    private final Map<String, List<String>> incoming = new ConcurrentHashMap<>(); // nodeId -> [sourceIds]

    // Optional reference for enriching graph stats with candidate counts
    private volatile WorkflowDetector workflowDetector;
    private volatile ExtensionConfig config;

    // --- Node Operations ---

    public synchronized RequestNode addNode(RequestNode node) {
        nodes.put(node.getId(), node);
        outgoing.putIfAbsent(node.getId(), new CopyOnWriteArrayList<>());
        incoming.putIfAbsent(node.getId(), new CopyOnWriteArrayList<>());
        return node;
    }

    public void addEdge(RequestEdge edge) {
        edges.add(edge);
        outgoing.computeIfAbsent(edge.getSourceNodeId(), k -> new CopyOnWriteArrayList<>())
                .add(edge.getTargetNodeId());
        incoming.computeIfAbsent(edge.getTargetNodeId(), k -> new CopyOnWriteArrayList<>())
                .add(edge.getSourceNodeId());
    }

    public RequestNode getNode(String nodeId) {
        return nodes.get(nodeId);
    }

    public Map<String, RequestNode> getNodes() {
        return Collections.unmodifiableMap(nodes);
    }

    public List<RequestEdge> getEdges() {
        return Collections.unmodifiableList(edges);
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
                List<String> targets = outgoing.get(current);
                if (targets != null) {
                    for (String target : targets) {
                        if (visited.add(target)) {
                            queue.add(target);
                        }
                    }
                }

                // Follow incoming edges
                List<String> sources = incoming.get(current);
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
        for (RequestNode node : other.nodes.values()) {
            if (!nodes.containsKey(node.getId())) {
                addNode(node);
            }
        }
        for (RequestEdge edge : other.edges) {
            addEdge(edge);
        }
    }

    // --- Statistics ---

    public int getNodeCount() { return nodes.size(); }
    public int getEdgeCount() { return edges.size(); }

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

    public GraphStats getStats() {
        List<List<RequestNode>> components = getConnectedComponents();
        int maxComponentSize = components.isEmpty() ? 0 : components.get(0).size();
        GraphStats stats = new GraphStats(nodes.size(), edges.size(), components.size(),
                maxComponentSize, getAllHosts().size());
        // Populate candidate counts from workflow detector if set
        if (workflowDetector != null) {
            List<WorkflowCandidate> lastResults = workflowDetector.getLastResults();
            stats.workflowCandidateCount = lastResults.size();
            stats.analysisReadyCandidateCount = (int) lastResults.stream()
                    .filter(c -> c.getWorkflowScore() >= config.getWorkflowScoreThreshold())
                    .count();
            stats.displayOnlyCandidateCount = stats.workflowCandidateCount
                    - stats.analysisReadyCandidateCount;
        }
        return stats;
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
    }

    // --- Stats Record ---

    public static class GraphStats {
        public final int nodeCount;
        public final int edgeCount;
        public final int componentCount;
        public final int maxComponentSize;
        public final int hostCount;

        // Candidate count placeholders; populated externally by WorkflowDetector
        public int workflowCandidateCount;
        public int analysisReadyCandidateCount;
        public int displayOnlyCandidateCount;

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
            sb.append(String.format("Nodes: %d, Edges: %d, Components: %d, Max component: %d, Hosts: %d",
                    nodeCount, edgeCount, componentCount, maxComponentSize, hostCount));
            if (workflowCandidateCount > 0) {
                sb.append(String.format(", Candidates: %d (analysis-ready: %d, display-only: %d)",
                        workflowCandidateCount, analysisReadyCandidateCount, displayOnlyCandidateCount));
            }
            return sb.toString();
        }
    }
}

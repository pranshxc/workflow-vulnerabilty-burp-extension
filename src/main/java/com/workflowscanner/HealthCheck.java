package com.workflowscanner;

import com.workflowscanner.analysis.AnalysisEngine;
import com.workflowscanner.data.RequestPipeline;
import com.workflowscanner.graph.GraphBuilder;
import com.workflowscanner.graph.RequestGraph;
import com.workflowscanner.llm.LLMClient;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;
import com.workflowscanner.store.RequestStore;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Periodic health check for all subsystems.
 * Logs warnings for degraded subsystems and exposes status for UI.
 */
public class HealthCheck {

    private final ExtensionLogger logger;
    private final RequestPipeline pipeline;
    private final GraphBuilder graphBuilder;
    private final RequestGraph graph;
    private final LLMClient llmClient;
    private final AnalysisEngine analysisEngine;
    // Optional. Set when the disk-backed store is wired in (Commit 2).
    // When null, the stored-requests metric keys read 0.
    private volatile RequestStore requestStore;

    private ScheduledExecutorService scheduler;
    private volatile Map<String, SubsystemStatus> lastStatus = new LinkedHashMap<>();

    public HealthCheck(ExtensionLogger logger, RequestPipeline pipeline,
                       GraphBuilder graphBuilder, RequestGraph graph,
                       LLMClient llmClient, AnalysisEngine analysisEngine) {
        this.logger = logger;
        this.pipeline = pipeline;
        this.graphBuilder = graphBuilder;
        this.graph = graph;
        this.llmClient = llmClient;
        this.analysisEngine = analysisEngine;
    }

    /**
     * Set the disk-backed request store. Wired in by the application
     * bootstrap once the store is opened. When unset, the
     * {@code stored_*} metric keys read 0.
     */
    public void setRequestStore(RequestStore store) {
        this.requestStore = store;
    }

    /**
     * Start periodic health checks.
     */
    public void start(int intervalSeconds) {
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "WorkflowScanner-HealthCheck");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleAtFixedRate(this::runCheck, intervalSeconds, intervalSeconds, TimeUnit.SECONDS);
    }

    /**
     * Run a health check on all subsystems.
     */
    public void runCheck() {
        Map<String, SubsystemStatus> status = new LinkedHashMap<>();

        // Logging
        status.put("Logging", new SubsystemStatus(
                logger.isInitialized(),
                "Buffer: " + logger.getEntryCount() + "/" + logger.getCapacity()));

        // Pipeline
        status.put("Pipeline", new SubsystemStatus(
                pipeline != null && pipeline.isRunning(),
                pipeline != null ? "Queue: " + pipeline.size() + ", Submitted: " + pipeline.getTotalSubmitted() : "N/A"));

        // Graph Builder
        status.put("GraphBuilder", new SubsystemStatus(
                graphBuilder != null && graphBuilder.isRunning(),
                graphBuilder != null ? "Processed: " + graphBuilder.getNodesProcessed() : "N/A"));

        // Graph
        status.put("Graph", new SubsystemStatus(
                graph != null,
                graph != null ? "Nodes: " + graph.getNodeCount() + ", Edges: " + graph.getEdgeCount() : "N/A"));

        // LLM Client
        status.put("LLMClient", new SubsystemStatus(
                llmClient != null && llmClient.isConfigured(),
                llmClient != null ? "Requests: " + llmClient.getTotalRequests()
                        + ", Errors: " + llmClient.getTotalErrors() : "N/A"));

        // Analysis Engine
        status.put("Analysis", new SubsystemStatus(
                analysisEngine != null,
                analysisEngine != null ? analysisEngine.getProgressText() : "N/A"));

        this.lastStatus = status;

        // Log warnings for unhealthy subsystems
        for (Map.Entry<String, SubsystemStatus> entry : status.entrySet()) {
            if (!entry.getValue().healthy) {
                logger.log(LogCategory.EXTENSION, LogLevel.WARN, "HealthCheck",
                        entry.getKey() + " is not healthy: " + entry.getValue().detail);
            }
        }
    }

    /**
     * Get the last health check results.
     */
    public Map<String, SubsystemStatus> getLastStatus() {
        return lastStatus;
    }

    /**
     * Get a flat metrics map for the StatusBarPanel.
     *
     * <p><b>Stored vs in-memory distinction (status-clarity rework):</b>
     * <ul>
     *   <li>{@code graph_nodes} is now the in-heap node count
     *       (RequestGraph hot cache).</li>
     *   <li>{@code workflow_relevant_requests} is the subset of
     *       stored nodes that the workflow detector actually
     *       considers. This is the meaningful "requests we
     *       analyzed" number.</li>
     *   <li>{@code workflow_candidates} is the actual count from
     *       the workflow detector, not connected components.</li>
     *   <li>{@code graph_components} is the (lazy) connected-component
     *       count. 0 unless explicitly requested via
     *       {@link com.workflowscanner.graph.RequestGraph#getComponentCountOnDemand()}.</li>
     *   <li>{@code edge_supported_candidates} vs
     *       {@code session_only_candidates} breaks the
     *       {@code workflow_candidates} total down by source:
     *       edge-supported = at least one supporting edge;
     *       session-only = no edges (session/boundary heuristic only).</li>
     *   <li>{@code edges_by_type_*} per-EdgeType counts (cheap O(1)
     *       reads of the atomic counter map).</li>
     *   <li>{@code edges_no_candidate_warning} = "1" when there are
     *       zero edges and at least one candidate, so the UI can
     *       surface the "edges missing" diagnostic.</li>
     * </ul>
     */
    public Map<String, String> getMetrics() {
        Map<String, String> metrics = new LinkedHashMap<>();

        metrics.put("pipeline_depth", pipeline != null ? String.valueOf(pipeline.size()) : "?");
        metrics.put("pipeline_capacity", pipeline != null ? String.valueOf(pipeline.getTotalSubmitted()) : "?");

        int edgeCount = (graph != null) ? graph.getEdgeCount() : 0;
        int nodeCount = (graph != null) ? graph.getNodeCount() : 0;
        int relevantCount = (graph != null) ? graph.getWorkflowRelevantNodeCount() : 0;
        // Real candidate count from detector, not connected components.
        // Use the live counters (updated by BOTH preview and detect
        // paths) so the status bar reflects what the user is currently
        // looking at, not just the last full analysis run.
        int candidateCount = 0;
        int edgeSuppCount = 0;
        int sessionOnlyCount = 0;
        if (graph != null && graph.getWorkflowDetector() != null) {
            com.workflowscanner.workflow.WorkflowDetector det = graph.getWorkflowDetector();
            candidateCount = det.getLiveCandidateCount();
            edgeSuppCount = det.getLiveEdgeSupportedCount();
            sessionOnlyCount = det.getLiveSessionOnlyCount();
        }

        metrics.put("graph_nodes", String.valueOf(nodeCount));
        metrics.put("graph_edges", String.valueOf(edgeCount));
        metrics.put("graph_components", "0"); // lazy; populated by on-demand call
        metrics.put("workflow_relevant_requests", String.valueOf(relevantCount));
        metrics.put("workflow_candidates", String.valueOf(candidateCount));
        metrics.put("edge_supported_candidates", String.valueOf(edgeSuppCount));
        metrics.put("session_only_candidates", String.valueOf(sessionOnlyCount));

        // Per-edge-type counts (O(1) reads from the atomic map).
        if (graph != null) {
            java.util.Map<com.workflowscanner.graph.EdgeType, Integer> byType =
                    graph.getEdgeCountsByType();
            for (com.workflowscanner.graph.EdgeType t : com.workflowscanner.graph.EdgeType.values()) {
                metrics.put("edges_by_type_" + t.name(),
                        String.valueOf(byType.getOrDefault(t, 0)));
            }
        }

        // Stored-requests counters from the disk-backed RequestStore.
        // Until Commit 2 wires the H2 implementation, these read 0.
        if (requestStore != null) {
            metrics.put("stored_requests", String.valueOf(requestStore.countAll()));
            metrics.put("stored_workflow_relevant", String.valueOf(requestStore.countWorkflowRelevant()));
            metrics.put("stored_with_raw", String.valueOf(requestStore.countWithRaw()));
            metrics.put("stored_disk_bytes", String.valueOf(requestStore.diskBytes()));
        } else {
            metrics.put("stored_requests", "0");
            metrics.put("stored_workflow_relevant", "0");
            metrics.put("stored_with_raw", "0");
            metrics.put("stored_disk_bytes", "0");
        }

        // Diagnostic: zero edges with non-zero candidates usually means
        // edge building never ran (backfill-only project, edge index
        // rebuild required, etc.). Surface it as an explicit key.
        boolean edgeMissing = edgeCount == 0 && candidateCount > 0;
        metrics.put("edges_no_candidate_warning", edgeMissing ? "1" : "0");

        // Live validation counts from the workflow detector.
        int confirmedCount = 0;
        int probableCount = 0;
        if (graph != null && graph.getWorkflowDetector() != null) {
            com.workflowscanner.workflow.WorkflowDetector det = graph.getWorkflowDetector();
            confirmedCount = det.getLiveConfirmedCount();
            probableCount = det.getLiveProbableCount();
        }
        metrics.put("confirmed_count", String.valueOf(confirmedCount));
        metrics.put("probable_count", String.valueOf(probableCount));

        // Analysis-ready vs display-only candidate split (live).
        int analysisReady = 0;
        int displayOnly = 0;
        if (graph != null && graph.getWorkflowDetector() != null) {
            analysisReady = graph.getWorkflowDetector().getLiveAnalysisReadyCount();
            displayOnly = graph.getWorkflowDetector().getLiveDisplayOnlyCount();
        }
        metrics.put("analysis_ready_candidates", String.valueOf(analysisReady));
        metrics.put("display_only_candidates", String.valueOf(displayOnly));

        metrics.put("analyzed_chains", analysisEngine != null ? String.valueOf(analysisEngine.getCompletedCandidates()) : "?");
        metrics.put("findings_count", analysisEngine != null ? String.valueOf(analysisEngine.getTotalFindings()) : "?");
        metrics.put("suppressed_total", graphBuilder != null ? String.valueOf(graphBuilder.getSuppressedCount()) : "?");
        metrics.put("llm_errors", llmClient != null ? String.valueOf(llmClient.getTotalErrors()) : "?");
        metrics.put("replay_errors", "0"); // Replay errors tracked internally

        return metrics;
    }

    /**
     * Check if all subsystems are healthy.
     */
    public boolean isAllHealthy() {
        for (SubsystemStatus status : lastStatus.values()) {
            if (!status.healthy) return false;
        }
        return !lastStatus.isEmpty();
    }

    public void stop() {
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
    }

    /**
     * Status of a single subsystem.
     */
    public static class SubsystemStatus {
        public final boolean healthy;
        public final String detail;

        public SubsystemStatus(boolean healthy, String detail) {
            this.healthy = healthy;
            this.detail = detail;
        }

        @Override
        public String toString() {
            return (healthy ? "OK" : "DEGRADED") + " - " + detail;
        }
    }
}

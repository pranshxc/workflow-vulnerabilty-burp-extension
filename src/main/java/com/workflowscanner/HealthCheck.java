package com.workflowscanner;

import com.workflowscanner.analysis.AnalysisEngine;
import com.workflowscanner.data.RequestPipeline;
import com.workflowscanner.graph.GraphBuilder;
import com.workflowscanner.graph.RequestGraph;
import com.workflowscanner.llm.LLMClient;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;

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

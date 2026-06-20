package com.workflowscanner.graph;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import com.workflowscanner.config.ExtensionConfig;
import com.workflowscanner.data.CapturedRequest;
import com.workflowscanner.data.RequestPipeline;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Builds and maintains the request graph by:
 * 1. Consuming requests from the RequestPipeline
 * 2. Creating RequestNodes with extracted parameters
 * 3. Computing edges via RelationshipDetector
 * 4. Persisting graph data to disk
 *
 * Runs a background consumer thread and an auto-save scheduler.
 */
public class GraphBuilder {

    private static final String NODES_FILE = "graph-nodes.json";
    private static final String EDGES_FILE = "graph-edges.json";
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    private final RequestGraph graph;
    private final RelationshipDetector detector;
    private final ExtensionLogger logger;

    private volatile RequestPipeline pipeline;
    private volatile ExtensionConfig config;
    private Thread consumerThread;
    private ScheduledExecutorService autoSaveScheduler;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicLong nodesProcessed = new AtomicLong(0);
    private final AtomicLong edgesCreated = new AtomicLong(0);

    public GraphBuilder(RequestGraph graph, ExtensionLogger logger) {
        this.graph = graph;
        this.detector = new RelationshipDetector(graph, logger);
        this.logger = logger;
    }

    /**
     * Start the background consumer thread that reads from the pipeline
     * and builds the graph incrementally.
     */
    public void start(RequestPipeline pipeline, ExtensionConfig config) {
        this.pipeline = pipeline;
        this.config = config;

        if (running.get()) {
            logger.log(LogCategory.GRAPH, LogLevel.WARN, "GraphBuilder",
                    "Graph builder already running.");
            return;
        }

        running.set(true);

        // Start consumer thread
        consumerThread = new Thread(this::consumeLoop, "WorkflowScanner-GraphBuilder");
        consumerThread.setDaemon(true);
        consumerThread.start();

        // Start auto-save scheduler
        int saveInterval = config.getGraphAutoSaveIntervalSeconds();
        if (saveInterval > 0 && config.getGraphDataDirectory() != null
                && !config.getGraphDataDirectory().isEmpty()) {
            autoSaveScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "WorkflowScanner-AutoSave");
                t.setDaemon(true);
                return t;
            });
            autoSaveScheduler.scheduleAtFixedRate(
                    () -> {
                        try {
                            saveToDirectory(config.getGraphDataDirectory());
                        } catch (Exception e) {
                            logger.log(LogCategory.ERROR, LogLevel.ERROR, "GraphBuilder",
                                    "Auto-save failed.", e);
                        }
                    },
                    saveInterval, saveInterval, TimeUnit.SECONDS);
            logger.log(LogCategory.GRAPH, LogLevel.INFO, "GraphBuilder",
                    "Auto-save enabled every " + saveInterval + "s.");
        }

        logger.log(LogCategory.GRAPH, LogLevel.INFO, "GraphBuilder",
                "Graph builder started.");
    }

    /**
     * Main consumer loop: reads from pipeline, creates nodes, detects edges.
     */
    private void consumeLoop() {
        while (running.get()) {
            try {
                CapturedRequest request = pipeline.take(500);
                if (request == null) continue;

                processRequest(request);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                logger.log(LogCategory.ERROR, LogLevel.ERROR, "GraphBuilder",
                        "Error in consumer loop.", e);
            }
        }
    }

    /**
     * Process a single request: create node, extract params, detect edges.
     */
    public void processRequest(CapturedRequest request) {
        try {
            // Create node
            int index = graph.getNextNodeIndex();
            RequestNode node = new RequestNode(request, index);

            // Extract parameters from request
            Map<String, Object> params = ParameterExtractor.extractRequestParams(request);
            node.setExtractedParams(params);

            // Extract response data
            Map<String, Object> responseData = ParameterExtractor.extractResponseData(request);
            node.setResponseData(responseData);

            // Add node to graph
            graph.addNode(node);
            nodesProcessed.incrementAndGet();

            // Detect relationships with existing nodes (incremental)
            List<RequestEdge> newEdges = detector.detectRelationships(node);
            for (RequestEdge edge : newEdges) {
                graph.addEdge(edge);
                edgesCreated.incrementAndGet();

                logger.log(LogCategory.GRAPH, LogLevel.DEBUG, "GraphBuilder",
                        "Edge created: " + edge.getType() + " (" + edge.getConfidence() + ") "
                                + edge.getEvidence());
            }

            logger.log(LogCategory.GRAPH, LogLevel.DEBUG, "GraphBuilder",
                    "Node#" + index + " added: " + request.getMethod() + " " + request.getPath()
                            + " | Params: " + params.size()
                            + " | Response values: " + responseData.size()
                            + " | New edges: " + newEdges.size());

            // Log chain detection periodically
            if (nodesProcessed.get() % 50 == 0) {
                RequestGraph.GraphStats stats = graph.getStats();
                logger.log(LogCategory.GRAPH, LogLevel.INFO, "GraphBuilder",
                        "Graph stats: " + stats);
            }

        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "GraphBuilder",
                    "Error processing request: " + request, e);
        }
    }

    // ========================================================================
    // Persistence
    // ========================================================================

    /**
     * Save graph data to a directory as JSON files.
     */
    public void saveToDirectory(String directoryPath) {
        if (directoryPath == null || directoryPath.isEmpty()) return;

        try {
            File dir = new File(directoryPath);
            if (!dir.exists()) dir.mkdirs();

            // Save nodes (without transient CapturedRequest)
            List<NodeData> nodeDataList = new ArrayList<>();
            for (RequestNode node : graph.getNodes().values()) {
                NodeData nd = new NodeData();
                nd.id = node.getId();
                nd.method = node.getMethod();
                nd.host = node.getHost();
                nd.path = node.getPath();
                nd.url = node.getUrl();
                nd.statusCode = node.getStatusCode();
                nd.timestamp = node.getTimestamp();
                nd.nodeIndex = node.getNodeIndex();
                nd.groupId = node.getGroupId();
                nd.extractedParams = node.getExtractedParams();
                nd.responseData = node.getResponseData();
                nodeDataList.add(nd);
            }

            Path nodesPath = Paths.get(directoryPath, NODES_FILE);
            Files.writeString(nodesPath, GSON.toJson(nodeDataList), StandardCharsets.UTF_8);

            // Save edges
            Path edgesPath = Paths.get(directoryPath, EDGES_FILE);
            Files.writeString(edgesPath, GSON.toJson(graph.getEdges()), StandardCharsets.UTF_8);

            logger.log(LogCategory.GRAPH, LogLevel.INFO, "GraphBuilder",
                    "Graph saved: " + nodeDataList.size() + " nodes, "
                            + graph.getEdgeCount() + " edges to " + directoryPath);

        } catch (IOException e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "GraphBuilder",
                    "Failed to save graph.", e);
        }
    }

    /**
     * Load graph data from a directory.
     */
    public void loadFromDirectory(String directoryPath) {
        if (directoryPath == null || directoryPath.isEmpty()) return;

        Path nodesPath = Paths.get(directoryPath, NODES_FILE);
        Path edgesPath = Paths.get(directoryPath, EDGES_FILE);

        if (!Files.exists(nodesPath) || !Files.exists(edgesPath)) {
            logger.log(LogCategory.GRAPH, LogLevel.INFO, "GraphBuilder",
                    "No saved graph data found at: " + directoryPath);
            return;
        }

        try {
            // Load nodes
            String nodesJson = Files.readString(nodesPath, StandardCharsets.UTF_8);
            Type nodeListType = new TypeToken<List<NodeData>>() {}.getType();
            List<NodeData> nodeDataList = GSON.fromJson(nodesJson, nodeListType);

            if (nodeDataList != null) {
                for (NodeData nd : nodeDataList) {
                    RequestNode node = new RequestNode();
                    node.setId(nd.id);
                    node.setMethod(nd.method);
                    node.setHost(nd.host);
                    node.setPath(nd.path);
                    node.setUrl(nd.url);
                    node.setStatusCode(nd.statusCode);
                    node.setTimestamp(nd.timestamp);
                    node.setNodeIndex(nd.nodeIndex);
                    node.setGroupId(nd.groupId);
                    if (nd.extractedParams != null) node.setExtractedParams(nd.extractedParams);
                    if (nd.responseData != null) node.setResponseData(nd.responseData);
                    graph.addNode(node);
                }
            }

            // Load edges
            String edgesJson = Files.readString(edgesPath, StandardCharsets.UTF_8);
            Type edgeListType = new TypeToken<List<RequestEdge>>() {}.getType();
            List<RequestEdge> edgeList = GSON.fromJson(edgesJson, edgeListType);

            if (edgeList != null) {
                for (RequestEdge edge : edgeList) {
                    graph.addEdge(edge);
                }
            }

            // Rebuild inverted index
            detector.rebuildIndex();

            logger.log(LogCategory.GRAPH, LogLevel.INFO, "GraphBuilder",
                    "Graph loaded: " + graph.getNodeCount() + " nodes, "
                            + graph.getEdgeCount() + " edges from " + directoryPath);

        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "GraphBuilder",
                    "Failed to load graph.", e);
        }
    }

    // ========================================================================
    // Lifecycle
    // ========================================================================

    /**
     * Stop the graph builder consumer thread and auto-save scheduler.
     */
    public void stop() {
        running.set(false);
        if (consumerThread != null) {
            consumerThread.interrupt();
            try {
                consumerThread.join(2000);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }
        if (autoSaveScheduler != null) {
            autoSaveScheduler.shutdownNow();
        }
        logger.log(LogCategory.GRAPH, LogLevel.INFO, "GraphBuilder",
                "Graph builder stopped. Processed: " + nodesProcessed.get()
                        + " nodes, " + edgesCreated.get() + " edges.");
    }

    public RequestGraph getGraph() { return graph; }
    public RelationshipDetector getDetector() { return detector; }
    public long getNodesProcessed() { return nodesProcessed.get(); }
    public long getEdgesCreated() { return edgesCreated.get(); }
    public boolean isRunning() { return running.get(); }

    // --- Serialization helper ---
    private static class NodeData {
        String id;
        String method;
        String host;
        String path;
        String url;
        int statusCode;
        long timestamp;
        int nodeIndex;
        String groupId;
        Map<String, Object> extractedParams;
        Map<String, Object> responseData;
    }
}

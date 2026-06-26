package com.workflowscanner.graph;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import com.workflowscanner.analysis.ApplicationModel;
import com.workflowscanner.classification.EndpointNormalizer;
import com.workflowscanner.classification.RequestClassification;
import com.workflowscanner.classification.RequestClassifier;
import com.workflowscanner.classification.RequestIntent;
import com.workflowscanner.classification.EndpointKey;
import com.workflowscanner.classification.StaticNoiseRules;
import com.workflowscanner.config.ExtensionConfig;
import com.workflowscanner.data.CapturedRequest;
import com.workflowscanner.data.RequestPipeline;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;
import com.workflowscanner.store.RawHttp;
import com.workflowscanner.store.RequestStore;
import com.workflowscanner.store.RequestStoreConversion;
import com.workflowscanner.store.RequestSummary;
import com.workflowscanner.workflow.WorkflowDetector;

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
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Builds and maintains the request graph by:
 * 1. Consuming requests from the RequestPipeline
 * 2. Classifying each request (noise filter, intent detection)
 * 3. Creating RequestNodes with extracted parameters and endpoint keys
 * 4. Computing edges via RelationshipDetector (filtered by ValueKind)
 * 5. Persisting graph data to disk
 * 6. Publishing graph update events
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

    // Classification integration (added in workflow rework)
    private final RequestClassifier classifier = new RequestClassifier();
    private final EndpointNormalizer normalizer = new EndpointNormalizer();

    // Suppression counters
    private final AtomicLong suppressedCount = new AtomicLong(0);
    private final AtomicLong businessActionCount = new AtomicLong(0);
    private final AtomicLong businessReadCount = new AtomicLong(0);
    private final AtomicLong authenticationCount = new AtomicLong(0);

    // Event listeners
    private final List<Runnable> graphUpdateListeners = new ArrayList<>();
    private volatile WorkflowDetector workflowDetector;
    
    // Optional ApplicationModel — set by AnalysisEngine for context-read retention
    private volatile ApplicationModel applicationModel;

    private volatile RequestPipeline pipeline;
    private volatile ExtensionConfig config;
    // Disk-backed canonical store. When set, every request is
    // persisted to it (summary + raw) before the hot graph view
    // is updated, so full backfill can survive at scale.
    private volatile RequestStore requestStore;
    private Thread consumerThread;
    private ScheduledExecutorService autoSaveScheduler;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicLong nodesProcessed = new AtomicLong(0);
    private final AtomicLong edgesCreated = new AtomicLong(0);
    private final AtomicLong storedCount = new AtomicLong(0);
    // When the in-memory graph gets too big, we drop the raw
    // CapturedRequest from RequestNode and rely on the store to
    // serve raw data on demand. Keeps the working set bounded.
    // Default 5000, configurable via ExtensionConfig.hotRawRetention.
    private int hotRawRetention = 5_000;
    // Hard cap on hot-graph node count. Past this, oldest isolated
    // nodes are evicted. Configurable via ExtensionConfig.hotGraphNodeLimit.
    private int hotGraphNodeLimit = 100_000;
    private final AtomicLong rawDropped = new AtomicLong(0);
    private final AtomicLong evictedCount = new AtomicLong(0);
    // Tracks ids of nodes that the user has opened, that are part
    // of an active analysis, or that are pending validation.
    // These are protected from eviction so that reopening the same
    // node always finds the raw payload.
    private final Set<String> pinnedNodeIds = ConcurrentHashMap.newKeySet();

    public GraphBuilder(RequestGraph graph, ExtensionLogger logger) {
        this.graph = graph;
        // Default index cap; start(...) replaces this with the
        // config-driven value if a config is provided.
        this.detector = new RelationshipDetector(graph, logger, 50);
        this.logger = logger;
        // Expose the detector through the graph so HealthCheck
        // (which has only the graph, not the builder) can read
        // the edge-miss diagnostics.
        graph.setRelationshipDetector(this.detector);
    }

    /**
     * Register a listener to be notified when the graph is updated.
     * Used by the analysis pipeline to trigger re-analysis on new data.
     */
    public void addGraphUpdateListener(Runnable listener) {
        graphUpdateListeners.add(listener);
    }

    /**
     * Set the WorkflowDetector to use for candidate detection.
     * Also propagates to the underlying graph for enriched stats.
     */
    public void setWorkflowDetector(WorkflowDetector detector) {
        this.workflowDetector = detector;
        if (detector != null && config != null) {
            graph.setWorkflowDetector(detector, config);
        }
    }

    /**
     * Set the ApplicationModel for retaining context reads and JS-discovered endpoints.
     * Called by AnalysisEngine during startup.
     */
    public void setApplicationModel(ApplicationModel model) {
        this.applicationModel = model;
    }

    /**
     * Set the disk-backed request store. When set, every request
     * (workflow-relevant or not) is persisted to the store as
     * {@link RequestSummary} + {@link RawHttp}. The hot in-memory
     * {@link RequestGraph} is still maintained, but its purpose
     * shifts from "canonical record" to "working view": it holds
     * only the workflow-relevant subset, and the raw HTTP payload
     * is dropped from each node once the graph grows past
     * {@link #HOT_GRAPH_RAW_RETENTION} entries (the raw data
     * remains recoverable via {@link RequestStore#getRaw(String)}).
     */
    public void setRequestStore(RequestStore store) {
        this.requestStore = store;
    }

    private void notifyGraphUpdated() {
        for (Runnable listener : graphUpdateListeners) {
            try {
                listener.run();
            } catch (Exception e) {
                logger.log(LogCategory.ERROR, LogLevel.ERROR, "GraphBuilder",
                        "Graph update listener failed.", e);
            }
        }
    }

    /**
     * Start the background consumer thread that reads from the pipeline
     * and builds the graph incrementally.
     */
    public void start(RequestPipeline pipeline, ExtensionConfig config) {
        this.pipeline = pipeline;
        this.config = config;
        if (config != null) {
            this.hotRawRetention = config.getHotRawRetention();
            this.hotGraphNodeLimit = config.getHotGraphNodeLimit();
            // The detector is created with the default cap in
            // the constructor; the config is read here for the
            // hot-graph budgets. The RelationshipDetector's
            // internal bounded index caps are not changed
            // post-construction because the field is final; that
            // cap defaults to 50 and is a sane default. A future
            // patch can make the cap mutable for live tuning.
            //
            // The noise rules config IS swap-in after construction
            // (setNoiseRulesConfig). This is how user customizations
            // of infrastructureCookieNames, authSessionCookieNames,
            // publicResourcePathPatterns, and workflowStateKeywords
            // flow into the detector's edge-skip logic.
            if (detector != null && config.getNoiseRules() != null) {
                detector.setNoiseRulesConfig(config.getNoiseRules());
            }
        }
        // Propagate config to graph for enriched stats when workflow detector is set
        if (workflowDetector != null && config != null) {
            graph.setWorkflowDetector(workflowDetector, config);
        }

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
     * Process a single request: classify, extract params, create node, detect edges.
     * Noise requests (STATIC_ASSET, TELEMETRY_ANALYTICS, PREFLIGHT, HEALTHCHECK)
     * are suppressed before graph insertion, but ALL requests are persisted
     * to the {@link RequestStore} (when configured) so the disk-backed store
     * is the canonical record of full backfill.
     */
    public void processRequest(CapturedRequest request) {
        try {
            // 1. Classify the request
            RequestClassification classification = classifier.classify(request);

            // 1a. Persist every request to the store (if wired). This
            // is the canonical record. The hot graph below is just a
            // working view, not the source of truth.
            if (requestStore != null) {
                try {
                    RequestSummary summary = RequestStoreConversion.summaryOf(request, classification);
                    RawHttp raw = RequestStoreConversion.rawOf(request);
                    requestStore.put(summary, raw);
                    storedCount.incrementAndGet();
                } catch (Exception e) {
                    logger.log(LogCategory.ERROR, LogLevel.WARN, "GraphBuilder",
                            "RequestStore put failed for " + request, e);
                }
            }

            if (!classification.isWorkflowRelevant()) {
                // Route context-read requests to ApplicationModel before suppression
                if (classification.isBackground()
                        && classification.getIntent() == RequestIntent.CONTEXT_READ) {
                    // Create a minimal node for context-read processing
                    RequestNode contextNode = new RequestNode(request, -1);
                    contextNode.setClassification(classification);
                    EndpointKey contextKey = normalizer.normalize(request);
                    contextNode.setEndpointKey(contextKey);
                    Map<String, Object> responseData = ParameterExtractor.extractResponseData(request);
                    contextNode.setResponseData(responseData);
                    if (applicationModel != null) {
                        applicationModel.ingestContextRead(contextNode, logger);
                    }
                }

                // Route JavaScript files for endpoint discovery
                if (classification.isBackground()
                        && classification.getIntent() == RequestIntent.STATIC_ASSET
                        && StaticNoiseRules.isJavaScriptFile(request.getPath())) {
                    // Extract API endpoints from JS content
                    processJavaScriptForEndpoints(request);
                }

                suppressedCount.incrementAndGet();
                logger.log(LogCategory.GRAPH, LogLevel.DEBUG, "GraphBuilder",
                        "Suppressed " + classification.getIntent() + ": "
                                + request.getMethod() + " " + request.getPath());
                return;
            }

            // 2. Normalize endpoint
            EndpointKey endpointKey = normalizer.normalize(request);

            // 3. Create node
            int index = graph.getNextNodeIndex();
            RequestNode node = new RequestNode(request, index);
            node.setClassification(classification);
            node.setEndpointKey(endpointKey);

            // 4. Extract parameters from request
            Map<String, Object> params = ParameterExtractor.extractRequestParams(request);
            node.setExtractedParams(params);

            // 5. Extract response data
            Map<String, Object> responseData = ParameterExtractor.extractResponseData(request);
            node.setResponseData(responseData);

            // 6. Add node to graph (hot working view — not canonical)
            graph.addNode(node);
            nodesProcessed.incrementAndGet();

            // 6b. === Realism-upgrade-2 incremental vocabulary ===
            //     Observe the new node into the application model
            //     so vocabulary accumulates across analysis runs.
            //     The candidate-level observation in WorkflowDetector
            //     still happens right before scoring, but by then
            //     the model already has the historical vocabulary
            //     from prior runs, so boosts apply on the first
            //     pass for terms the target uses repeatedly.
            if (applicationModel != null) {
                applicationModel.observeNode(node);
            }

            // Track by intent type
            switch (classification.getIntent()) {
                case BUSINESS_ACTION: businessActionCount.incrementAndGet(); break;
                case BUSINESS_READ: businessReadCount.incrementAndGet(); break;
                case AUTHENTICATION: authenticationCount.incrementAndGet(); break;
                default: break;
            }

            // 6a. Smart raw retention. Keep raw HTTP for:
            //   - all live recent traffic (last hotRawRetention / 4
            //     requests are recent by definition)
            //   - pinned nodes (UI-selected, validation target, etc.)
            // Drop raw for:
            //   - backfilled older nodes once we exceed hotRawRetention
            // The raw payload is recoverable from RequestStore via
            // RequestHydrator when a consumer needs it.
            boolean keepRaw = shouldKeepRawInHotGraph(request, node);
            if (!keepRaw) {
                node.setRequest(null);
                rawDropped.incrementAndGet();
            } else {
                pinnedNodeIds.add(node.getId());
            }

            // 6b. Hard cap on hot graph size. When the working set
            // exceeds hotGraphNodeLimit, evict the oldest isolated
            // nodes (then oldest connected) until we are within
            // budget. Evicted nodes remain in RequestStore; the
            // detector indexes are rebuilt lazily on demand.
            if (graph.getNodeCount() > hotGraphNodeLimit) {
                List<String> evicted = graph.evictToBudget(
                        pinnedNodeIds, hotGraphNodeLimit);
                if (!evicted.isEmpty()) {
                    evictedCount.addAndGet(evicted.size());
                    // Drop any evicted ids from the pin set (they
                    // are no longer in the hot graph).
                    pinnedNodeIds.removeAll(evicted);
                }
            }

            // 7. Detect relationships with existing nodes (incremental)
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
                            + " | Intent: " + classification.getIntent()
                            + " | Params: " + params.size()
                            + " | New edges: " + newEdges.size());

            // 8. Notify listeners about graph update
            notifyGraphUpdated();

            // Log chain detection periodically
            if (nodesProcessed.get() % 50 == 0) {
                RequestGraph.GraphStats stats = graph.getStats();
                logger.log(LogCategory.GRAPH, LogLevel.INFO, "GraphBuilder",
                        "Graph stats: " + stats
                                + " | Suppressed: " + suppressedCount.get()
                                + " | Stored: " + storedCount.get()
                                + " | Raw dropped: " + rawDropped.get()
                                + " | Evicted: " + evictedCount.get()
                                + " | Pinned: " + pinnedNodeIds.size());
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
     *
     * <p>Safety guard: writing the full in-memory graph to JSON
     * scales with node count and can OOM on large projects
     * (1M+ nodes). When the hot graph exceeds
     * {@link #HOT_GRAPH_RAW_RETENTION} entries, the canonical
     * record lives in the {@link RequestStore} and the JSON
     * graph files become a debug export only. In that mode we
     * skip the save to avoid blowing heap during shutdown.
     */
    public void saveToDirectory(String directoryPath) {
        if (directoryPath == null || directoryPath.isEmpty()) return;

        int nodeCount = graph.getNodeCount();
        if (nodeCount > hotGraphNodeLimit) {
            logger.log(LogCategory.GRAPH, LogLevel.WARN, "GraphBuilder",
                    "Skipping graph JSON save: " + nodeCount
                            + " nodes exceeds hot-graph node limit "
                            + "(" + hotGraphNodeLimit + "). "
                            + "RequestStore is canonical; full graph JSON is a "
                            + "debug export only and would risk OOM.");
            return;
        }

        try {
            File dir = new File(directoryPath);
            if (!dir.exists()) dir.mkdirs();

            // Save nodes (including raw HTTP data for replay)
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
                nd.classification = node.getClassification();
                nd.endpointKey = node.getEndpointKey();
                // Persist raw HTTP data so loaded nodes can be replayed
                // (View Request/Response, Send to Repeater, validation).
                CapturedRequest req = node.getRequest();
                if (req != null) {
                    nd.source = req.getSource() != null ? req.getSource().name() : null;
                    nd.queryParams = req.getQueryParams();
                    nd.requestHeaders = req.getRequestHeaders();
                    nd.requestBody = req.getRequestBody();
                    nd.responseHeaders = req.getResponseHeaders();
                    nd.responseBody = req.getResponseBody();
                    nd.mimeType = req.getMimeType();
                    nd.referrer = req.getReferrer();
                    nd.contentType = req.getContentType();
                    nd.cookies = req.getCookies();
                }
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
                    if (nd.classification != null) node.setClassification(nd.classification);
                    if (nd.endpointKey != null) node.setEndpointKey(nd.endpointKey);
                    // Restore raw HTTP data so the node is fully replayable
                    // (View Request/Response, Send to Repeater, validation).
                    if (nd.url != null || nd.requestHeaders != null || nd.requestBody != null) {
                        node.setRequest(rebuildCapturedRequest(nd));
                    }
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

            // Repair next node index to avoid collisions with existing indices
            graph.recalculateNextNodeIndex();

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
    public long getSuppressedCount() { return suppressedCount.get(); }
    public long getStoredCount() { return storedCount.get(); }
    public long getRawDroppedCount() { return rawDropped.get(); }
    public long getEvictedCount() { return evictedCount.get(); }
    public RequestStore getRequestStore() { return requestStore; }
    public int getHotRawRetention() { return hotRawRetention; }
    public int getHotGraphNodeLimit() { return hotGraphNodeLimit; }
    public int getPinnedCount() { return pinnedNodeIds.size(); }

    /**
     * Pin a node id so it is not evicted from the hot graph and
     * its raw payload is not dropped. Call this from the UI when
     * the user opens a node, from the validation engine when it
     * selects a target, or from any consumer that needs the
     * payload to remain accessible.
     */
    public void pinNode(String nodeId) {
        if (nodeId != null) pinnedNodeIds.add(nodeId);
    }

    /**
     * Unpin a previously pinned node. Idempotent.
     */
    public void unpinNode(String nodeId) {
        if (nodeId != null) pinnedNodeIds.remove(nodeId);
    }

    /**
     * Smart raw-retention policy. We keep raw HTTP for nodes
     * that meet any of the following:
     *
     * <ul>
     *   <li>The request is recent (came in within the last
     *       {@code hotRawRetention / 4} requests). This is the
     *       live-traffic recent-window.</li>
     *   <li>The request was selected manually via the context
     *       menu (it has a groupId).</li>
     *   <li>The request is part of an active workflow candidate
     *       (workflow score above the analysis threshold).</li>
     *   <li>The hot graph is still below the raw retention budget.</li>
     * </ul>
     *
     * Everything else (backfilled older traffic past the budget)
     * gets its raw payload dropped; the data is recoverable from
     * the disk-backed store.
     */
    private boolean shouldKeepRawInHotGraph(CapturedRequest request, RequestNode node) {
        // Under budget: keep raw for everything.
        if (graph.getNodeCount() <= hotRawRetention) return true;
        // User-grouped (context menu): keep raw.
        if (request.getGroupId() != null) return true;
        // Recent: last hotRawRetention / 4 nodes are "live recent".
        // We approximate "recent" as "created after timestamp
        // cutoff" — the cutoff is the timestamp of the
        // (nodesProcessed - hotRawRetention/4)-th node. But we do
        // not track per-node timestamps cheaply, so use a clock
        // window instead: anything in the last
        // hotRawRetention/4 ms scaled to 1 second each is recent.
        long recencyMs = Math.max(1000L, (long) hotRawRetention / 4 * 1000L);
        if (request.getTimestamp() > System.currentTimeMillis() - recencyMs) {
            return true;
        }
        return false;
    }

    /**
     * Extract API endpoint paths from JavaScript file content using regex.
     * Adds discovered endpoints to the ApplicationModel for LLM context.
     *
     * Supports:
     * - Quoted paths: "/api/orders/123", "/api/orders?status=pending"
     * - Backticks/template strings: `/api/orders/${id}`
     * - Exact "/graphql" and "/api" (no trailing segment)
     * - Full URLs: "https://api.example.com/v1/payments"
     * - Function call style: fetch("/api/..."), axios.get("/api/..."),
     *   client.post("/api/..."), XMLHttpRequest("GET", "/api/...")
     * - Method is taken from the surrounding function call when available
     *   (looks both before and after the URL to handle fetch(..., {method:"POST"}));
     *   it falls back to path-keyword heuristic or GET.
     */
    private void processJavaScriptForEndpoints(CapturedRequest request) {
        if (applicationModel == null) return;
        String body = request.getResponseBody();
        if (body == null || body.isEmpty()) return;

        if (body.length() > 500_000) {
            body = body.substring(0, 500_000); // cap size
        }

        int before = applicationModel.getDiscoveredEndpoints().size();
        String requestHost = request.getHost();

        // Path or full URL inside a quoted/backticked string.
        // Tighter character class than a blanket "anything until the next
        // quote" — the path body is limited to characters that can actually
        // appear in a real URL path or query string. Stops at the closing
        // quote/backtick so a stray `'` in a string literal doesn't swallow
        // the whole file.
        java.util.regex.Pattern endpointPattern = java.util.regex.Pattern.compile(
                "[\"'`]("
                + "(?:https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+)?"
                + "/(?:"
                + "(?:api|v\\d+|graphql|rest)"
                + "(?:[/?#][A-Za-z0-9._~:/?#@!$&()*+,;=%{}-]*)?"
                + ")"
                + ")[\"'`]");
        java.util.regex.Matcher matcher = endpointPattern.matcher(body);
        while (matcher.find()) {
            int matchStart = matcher.start();
            String raw = matcher.group(1);
            String method = inferMethodNear(body, matchStart, "GET");
            if (raw.startsWith("http://") || raw.startsWith("https://")) {
                parseAndAddAbsoluteUrl(raw, method);
            } else {
                addDiscoveredEndpoint(raw, method, requestHost);
            }
        }

        int added = applicationModel.getDiscoveredEndpoints().size() - before;
        if (added > 0) {
            logger.log(LogCategory.GRAPH, LogLevel.INFO, "GraphBuilder",
                    "Discovered " + added + " API endpoints from JS: " + request.getPath());
        }
    }

    /**
     * Parse a full absolute URL discovered in JS and add the host + path
     * separately so it groups with real captured traffic. URI is used to
     * strip the scheme from the host, which would otherwise mismatch
     * EndpointKey records built from HTTP traffic (which store just the host).
     * <p>
     * The raw query string is preserved and reattached to the path before
     * delegation, so {@link #addDiscoveredEndpoint} (which owns the path
     * + query splitting logic) can extract parameter names like
     * {@code role}, {@code tenant_id} into the {@code EndpointKey}.
     */
    private void parseAndAddAbsoluteUrl(String fullUrl, String method) {
        try {
            java.net.URI uri = java.net.URI.create(fullUrl);
            String host = uri.getHost();
            String path = uri.getRawPath();
            if (host == null || path == null || path.isEmpty()) return;
            // Reattach the query so it survives into addDiscoveredEndpoint.
            // Without this, query keys for absolute URLs would be lost.
            String rawQuery = uri.getRawQuery();
            if (rawQuery != null && !rawQuery.isEmpty()) {
                path = path + "?" + rawQuery;
            }
            addDiscoveredEndpoint(path, method, host);
        } catch (IllegalArgumentException ignored) {
            // Malformed URI; skip.
        }
    }

    /**
     * Add a discovered endpoint to the ApplicationModel with host/hostHint handling.
     * Falls back to "js-discovery" when no host context is available.
     * <p>
     * The endpoint is split into path + query-parameter names. The path
     * becomes the EndpointKey's path (cleaned of template placeholders);
     * query-parameter names are passed as the EndpointKey's paramNames
     * set so the LLM and the application model can reason about realistic
     * business-logic surface area.
     */
    private void addDiscoveredEndpoint(String path, String method, String hostHint) {
        if (path == null) return;
        // Split path and query. The path groups endpoints; the query keys
        // capture realistic business parameters (e.g. status, role, tenant_id).
        String query = "";
        int qIdx = path.indexOf('?');
        if (qIdx >= 0) {
            query = path.substring(qIdx + 1);
            path = path.substring(0, qIdx);
        }
        // Drop fragments — they are not part of the endpoint surface.
        int hashIdx = path.indexOf('#');
        if (hashIdx >= 0) path = path.substring(0, hashIdx);

        // Clean up template-style placeholders: ${id} -> :id, {id} -> :id
        String cleanedPath = path.replaceAll("\\$\\{[^}]+}", ":param")
                .replaceAll("\\{([^}]+)\\}", ":$1");
        if (cleanedPath.isEmpty()) return;

        java.util.Set<String> queryKeys = parseQueryKeys(query);

        String host = (hostHint != null && !hostHint.isEmpty()) ? hostHint : "js-discovery";
        applicationModel.addEndpoint(
                new com.workflowscanner.classification.EndpointKey(
                        method, host, cleanedPath, queryKeys));
    }

    /**
     * Parse a raw query string into a set of parameter names. Values are
     * discarded — only names matter for endpoint grouping and LLM context.
     * Handles simple {@code a=1&b=2} and bracket array forms
     * {@code a[]=1&a[]=2} (collapses to "a" in the set).
     */
    private static java.util.Set<String> parseQueryKeys(String query) {
        if (query == null || query.isEmpty()) return java.util.Set.of();
        java.util.Set<String> keys = new java.util.HashSet<>();
        for (String pair : query.split("&")) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            String rawKey = eq >= 0 ? pair.substring(0, eq) : pair;
            // Drop array suffixes to collapse a[] / a[0] to a.
            int bracket = rawKey.indexOf('[');
            if (bracket >= 0) rawKey = rawKey.substring(0, bracket);
            if (!rawKey.isEmpty()) keys.add(rawKey);
        }
        return keys;
    }

    /**
     * Look at the ~200 chars before AND ~300 chars after a path match to find
     * an HTTP method from a surrounding call. The post-match window is
     * important for fetch(url, {method: "POST"}), where the method appears
     * after the URL.
     * <p>
     * Recognized patterns:
     * - axios.post(...), client.get(...), $http.put(...), this.foo.delete(...)
     * - { method: "POST" } or {method: 'PUT'} in either position
     * - XMLHttpRequest open("POST", url) (method before URL)
     * Falls back to a path-keyword heuristic, then to the supplied default.
     */
    private String inferMethodNear(String body, int matchStart, String defaultMethod) {
        int lookbackStart = Math.max(0, matchStart - 200);
        int lookaheadEnd = Math.min(body.length(), matchStart + 300);
        String context = body.substring(lookbackStart, lookaheadEnd);

        // Explicit method: { method: "POST" } or {method: 'PUT'}
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(
                "method\\s*[:=]\\s*[\"']([A-Z]+)[\"']",
                java.util.regex.Pattern.CASE_INSENSITIVE).matcher(context);
        if (m.find()) {
            String found = m.group(1).toUpperCase();
            if (isHttpMethod(found)) return found;
        }

        // axios.{verb}(...), client.{verb}(...), ${prefix}.{verb}(...)
        m = java.util.regex.Pattern.compile(
                "(?:^|[^.$a-zA-Z])(?:axios|client|api|http|\\$http|this\\.[\\w$]+)\\.([a-z]+)\\s*\\(",
                java.util.regex.Pattern.CASE_INSENSITIVE).matcher(context);
        if (m.find()) {
            String verb = m.group(1).toUpperCase();
            if (isHttpMethod(verb)) return verb;
        }

        // xhr.open("POST", ...) or xhr.open('POST', ...) — method appears
        // before the URL, so we use only the pre-match context.
        int lookbackEnd = Math.min(body.length(), matchStart);
        String pre = body.substring(Math.max(0, matchStart - 200), lookbackEnd);
        m = java.util.regex.Pattern.compile(
                "\\.open\\s*\\(\\s*[\"']([A-Z]+)[\"']",
                java.util.regex.Pattern.CASE_INSENSITIVE).matcher(pre);
        if (m.find()) {
            String verb = m.group(1).toUpperCase();
            if (isHttpMethod(verb)) return verb;
        }

        // Path-keyword heuristic as a last resort
        String path = body.substring(matchStart, Math.min(body.length(), matchStart + 120));
        if (path.contains("delete") || path.contains("remove")) return "DELETE";
        if (path.contains("update") || path.contains("edit") || path.contains("/put/")) return "PUT";
        if (path.contains("create") || path.contains("/add") || path.contains("/post/")) return "POST";

        return defaultMethod;
    }

    private static boolean isHttpMethod(String s) {
        return "GET".equals(s) || "POST".equals(s) || "PUT".equals(s)
                || "DELETE".equals(s) || "PATCH".equals(s) || "HEAD".equals(s)
                || "OPTIONS".equals(s);
    }
    public long getBusinessActionCount() { return businessActionCount.get(); }
    public long getBusinessReadCount() { return businessReadCount.get(); }
    public long getAuthenticationCount() { return authenticationCount.get(); }
    public RequestClassifier getClassifier() { return classifier; }
    public EndpointNormalizer getNormalizer() { return normalizer; }
    public WorkflowDetector getWorkflowDetector() { return workflowDetector; }

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
        RequestClassification classification;
        EndpointKey endpointKey;

        // Raw HTTP fields (persisted for replay; nullable when absent)
        String source;
        Map<String, String> queryParams;
        Map<String, List<String>> requestHeaders;
        String requestBody;
        Map<String, List<String>> responseHeaders;
        String responseBody;
        String mimeType;
        String referrer;
        String contentType;
        List<String> cookies;
    }

    /**
     * Rebuild a CapturedRequest from persisted NodeData so loaded nodes
     * retain full replay capability (View Request, Send to Repeater, validation).
     */
    private static CapturedRequest rebuildCapturedRequest(NodeData nd) {
        CapturedRequest req = new CapturedRequest();
        if (nd.id != null) req.setId(nd.id);
        req.setTimestamp(nd.timestamp);
        req.setMethod(nd.method);
        req.setUrl(nd.url);
        req.setHost(nd.host);
        req.setPath(nd.path);
        if (nd.queryParams != null) req.setQueryParams(nd.queryParams);
        if (nd.requestHeaders != null) req.setRequestHeaders(nd.requestHeaders);
        req.setRequestBody(nd.requestBody);
        req.setStatusCode(nd.statusCode);
        if (nd.responseHeaders != null) req.setResponseHeaders(nd.responseHeaders);
        req.setResponseBody(nd.responseBody);
        req.setMimeType(nd.mimeType);
        req.setReferrer(nd.referrer);
        req.setContentType(nd.contentType);
        if (nd.cookies != null) req.setCookies(nd.cookies);
        if (nd.groupId != null) req.setGroupId(nd.groupId);
        if (nd.source != null) {
            try {
                req.setSource(CapturedRequest.Source.valueOf(nd.source));
            } catch (IllegalArgumentException ignored) {
                // Unknown source value from older build — leave default.
            }
        }
        return req;
    }
}

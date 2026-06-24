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
     * are suppressed before graph insertion.
     */
    public void processRequest(CapturedRequest request) {
        try {
            // 1. Classify the request
            RequestClassification classification = classifier.classify(request);
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

            // 6. Add node to graph
            graph.addNode(node);
            nodesProcessed.incrementAndGet();

            // Track by intent type
            switch (classification.getIntent()) {
                case BUSINESS_ACTION: businessActionCount.incrementAndGet(); break;
                case BUSINESS_READ: businessReadCount.incrementAndGet(); break;
                case AUTHENTICATION: authenticationCount.incrementAndGet(); break;
                default: break;
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
                                + " | Suppressed: " + suppressedCount.get());
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

    /**
     * Extract API endpoint paths from JavaScript file content using regex.
     * Adds discovered endpoints to the ApplicationModel for LLM context.
     *
     * Supports:
     * - Quoted paths: "/api/orders/123"
     * - Backticks/template strings: `/api/orders/${id}`
     * - Full URLs: "https://api.example.com/v1/payments"
     * - Function call style: fetch("/api/..."), axios.get("/api/..."),
     *   client.post("/api/..."), XMLHttpRequest("GET", "/api/...")
     * - Method is taken from the surrounding function call when available;
     *   it falls back to GET or path-keyword heuristic.
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

        // Quoted or backticked path starting with /api/ or /vN/ or /graphql or /rest/
        java.util.regex.Pattern pathPattern = java.util.regex.Pattern.compile(
                "[\"'`](/(?:api/|v\\d+/|graphql|rest/)[a-zA-Z0-9_/\\-{}:$]+)[\"'`]");
        java.util.regex.Matcher pathMatcher = pathPattern.matcher(body);
        while (pathMatcher.find()) {
            int start = pathMatcher.start();
            String raw = pathMatcher.group(1);
            String method = inferMethodNear(body, start, "GET");
            addDiscoveredEndpoint(raw, method, requestHost);
        }

        // Full absolute URLs in strings: "https://api.example.com/v1/payments"
        java.util.regex.Pattern urlPattern = java.util.regex.Pattern.compile(
                "[\"'`](https?://[a-zA-Z0-9.\\-]+(?:/[a-zA-Z0-9_/\\-{}:$]+))[\"'`]");
        java.util.regex.Matcher urlMatcher = urlPattern.matcher(body);
        while (urlMatcher.find()) {
            int start = urlMatcher.start();
            String fullUrl = urlMatcher.group(1);
            String method = inferMethodNear(body, start, "GET");
            // Split host and path
            int schemeEnd = fullUrl.indexOf("://") + 3;
            int pathStart = fullUrl.indexOf('/', schemeEnd);
            if (pathStart < 0) continue;
            String host = fullUrl.substring(0, pathStart);
            String path = fullUrl.substring(pathStart);
            addDiscoveredEndpoint(path, method, host);
        }

        int added = applicationModel.getDiscoveredEndpoints().size() - before;
        if (added > 0) {
            logger.log(LogCategory.GRAPH, LogLevel.INFO, "GraphBuilder",
                    "Discovered " + added + " API endpoints from JS: " + request.getPath());
        }
    }

    /**
     * Add a discovered endpoint to the ApplicationModel with host/hostHint handling.
     * Falls back to "js-discovery" when no host context is available.
     */
    private void addDiscoveredEndpoint(String path, String method, String hostHint) {
        if (path == null) return;
        // Clean up template-style placeholders: ${id} -> :id, {id} -> :id
        String cleaned = path.replaceAll("\\$\\{[^}]+}", ":param")
                .replaceAll("\\{([^}]+)\\}", ":$1");
        if (cleaned.isEmpty()) return;

        String host = (hostHint != null && !hostHint.isEmpty()) ? hostHint : "js-discovery";
        applicationModel.addEndpoint(
                new com.workflowscanner.classification.EndpointKey(
                        method, host, cleaned, java.util.Set.of()));
    }

    /**
     * Look at the ~120 chars before a path match and try to identify an HTTP
     * method from a surrounding call: fetch(..., {method:"POST"}),
     * axios.post(...), client.get(...), $http.put(...), XMLHttpRequest open.
     * Falls back to path-keyword heuristic or the supplied default.
     */
    private String inferMethodNear(String body, int matchStart, String defaultMethod) {
        int lookbackStart = Math.max(0, matchStart - 200);
        String context = body.substring(lookbackStart, matchStart);

        // Explicit method: { method: "POST" } or {method:'PUT'}
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

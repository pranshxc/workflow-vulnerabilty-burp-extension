package com.workflowscanner;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;

import com.workflowscanner.analysis.ChainVerdict;
import com.workflowscanner.analysis.ApplicationModel;
import com.workflowscanner.config.ConfigValidator;
import com.workflowscanner.config.ExtensionConfig;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;
import com.workflowscanner.data.RequestPipeline;
import com.workflowscanner.data.ProxyListener;
import com.workflowscanner.data.ContextMenuProvider;
import com.workflowscanner.data.BackfillService;
import com.workflowscanner.graph.RequestGraph;
import com.workflowscanner.graph.GraphBuilder;
import com.workflowscanner.llm.LLMClient;
import com.workflowscanner.analysis.AnalysisEngine;
import com.workflowscanner.validation.ValidationEngine;
import com.workflowscanner.advisory.AdvisoryManager;
import com.workflowscanner.store.RequestStore;
import com.workflowscanner.store.H2RequestStore;
import com.workflowscanner.ui.MainTabPanel;
import com.workflowscanner.workflow.WorkflowDetector;
import com.workflowscanner.workflow.WorkflowCandidate;

import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Workflow Vulnerability Scanner - Burp Suite Extension
 *
 * Detects multi-step workflow vulnerabilities by building a request graph,
 * analyzing chains with an LLM, validating findings via request replay,
 * and reporting confirmed issues as Burp scanner advisories.
 *
 * Full pipeline:
 * [Proxy/Backfill/Context Menu] -> [Scope Filter] -> [Request Pipeline]
 *   -> [Graph Builder] -> [Chain Prioritizer] -> [Analysis Engine + LLM]
 *   -> [Validation Engine] -> [Advisory Layer -> Burp Issues]
 *
 * Uses the Montoya API (modern Burp extension API).
 */
public class WorkflowVulnScanner implements BurpExtension {

    public static final String EXTENSION_NAME = "Workflow Vulnerability Scanner";
    public static final String EXTENSION_VERSION = "1.0.0";

    private MontoyaApi api;
    private ExtensionLogger logger;
    private ExtensionConfig config;
    
    // Auto-analysis debounce
    private final ScheduledExecutorService autoAnalysisScheduler = Executors.newSingleThreadScheduledExecutor(
            r -> new Thread(r, "auto-analysis-debounce"));
    private volatile ScheduledFuture<?> pendingAutoAnalysis;
    
    private EventBus eventBus;
    private RequestGraph graph;
    private RequestPipeline pipeline;
    private GraphBuilder graphBuilder;
    private LLMClient llmClient;
    private AnalysisEngine analysisEngine;
    private ValidationEngine validationEngine;
    private AdvisoryManager advisoryManager;
    private BackfillService backfillService;
    private HealthCheck healthCheck;
    // Disk-backed request store. Opened at startup, closed at shutdown.
    private RequestStore requestStore;
    private MainTabPanel mainTabPanel;
    private WorkflowDetector workflowDetector;
    private ApplicationModel applicationModel;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName(EXTENSION_NAME);

        // === STARTUP SEQUENCE ===

        // 1. Logging subsystem (first - everything else depends on it)
        initLogging();
        logger.log(LogCategory.EXTENSION, LogLevel.INFO, "WorkflowVulnScanner",
                EXTENSION_NAME + " v" + EXTENSION_VERSION + " initializing...");

        // 2. Configuration
        initConfig();
        configureLogging();
        validateConfig();

        // 3. Event bus (before subsystems that publish/subscribe)
        initEventBus();

        // 4. Disk-backed request store (H2 MVStore). Must be open
        //    before any component that wants to call getRequestStore()
        //    (e.g. HealthCheck, the eventual streaming backfill).
        initRequestStore();

        // 5. Graph data store
        initGraph();

        // 6. Request pipeline + backfill service
        initRequestPipeline();

        // 7. Application model — created BEFORE the graph builder starts so
        //    that any traffic arriving during the startup gap is not silently
        //    dropped (context reads, JS-discovered endpoints).
        initApplicationModel();

        // 8. Start graph builder (pipeline -> graph)
        startGraphBuilder();

        // 9. LLM client
        initLLMClient();

        // 10. Analysis engine (wires workflowDetector into graph + analysisEngine)
        initAnalysisEngine();

        // 11. Validation engine
        initValidationEngine();

        // 12. Advisory manager
        initAdvisoryManager();

        // 13. Wire the full pipeline via event bus
        wirePipeline();

        // 14. UI panels
        initUI();

        // 15. HTTP handler (live proxy traffic)
        initHttpHandler();

        // 16. Context menu
        initContextMenu();

        // 17. Health check
        initHealthCheck();

        // 18. Register unload handler
        api.extension().registerUnloadingHandler(new ShutdownHandler());

        logger.log(LogCategory.EXTENSION, LogLevel.INFO, "WorkflowVulnScanner",
                EXTENSION_NAME + " v" + EXTENSION_VERSION + " loaded successfully. "
                        + "Graph: " + graph.getNodeCount() + " nodes, "
                        + graph.getEdgeCount() + " edges.");
    }

    // ========================================================================
    // Subsystem Initialization (fault-tolerant)
    // ========================================================================

    private void initLogging() {
        try {
            this.logger = ExtensionLogger.getInstance();
            logger.initialize(api);
        } catch (Exception e) {
            api.logging().logToOutput("[ERROR] Failed to initialize logging: " + e.getMessage());
            this.logger = ExtensionLogger.getInstance();
        }
    }

    private void configureLogging() {
        try {
            logger.reconfigure(
                    config.getLogRingBufferSize(),
                    config.isFileLoggingEnabled(),
                    config.getLogFileDirectory());
            logger.log(LogCategory.CONFIG, LogLevel.INFO, "WorkflowVulnScanner",
                    "Logging configured. Buffer: " + config.getLogRingBufferSize()
                            + ", File: " + config.isFileLoggingEnabled());
        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "WorkflowVulnScanner",
                    "Failed to configure logging.", e);
        }
    }

    private void initConfig() {
        try {
            this.config = ExtensionConfig.load(api);
            logger.log(LogCategory.CONFIG, LogLevel.INFO, "WorkflowVulnScanner",
                    "Configuration loaded.");
        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "WorkflowVulnScanner",
                    "Failed to load config, using defaults.", e);
            this.config = new ExtensionConfig();
        }
    }

    private void validateConfig() {
        List<String> errors = ConfigValidator.validateAll(config);
        if (!errors.isEmpty()) {
            for (String error : errors) {
                logger.log(LogCategory.CONFIG, LogLevel.WARN, "WorkflowVulnScanner",
                        "Config warning: " + error);
            }
        }
    }

    private void initEventBus() {
        try {
            this.eventBus = new EventBus(logger);
            logger.log(LogCategory.EXTENSION, LogLevel.INFO, "WorkflowVulnScanner",
                    "Event bus initialized.");
        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "WorkflowVulnScanner",
                    "Failed to initialize event bus.", e);
            this.eventBus = new EventBus(logger);
        }
    }

    private void initRequestStore() {
        try {
            String graphDir = config.getGraphDataDirectory();
            String storePath = null;
            if (graphDir != null && !graphDir.isEmpty()) {
                storePath = graphDir + java.io.File.separator + "requests.mv";
            }
            this.requestStore = new H2RequestStore(storePath);
            logger.log(LogCategory.EXTENSION, LogLevel.INFO, "WorkflowVulnScanner",
                    "Request store opened at " + (storePath == null
                            ? "(in-memory)" : storePath)
                            + " — existing records: " + requestStore.countAll());
        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "WorkflowVulnScanner",
                    "Failed to open request store, falling back to in-memory.", e);
            // Last-resort: an in-memory MVStore. Bounded only by heap.
            this.requestStore = new H2RequestStore(null);
        }
    }

    private void initGraph() {
        try {
            this.graph = new RequestGraph();
            this.graphBuilder = new GraphBuilder(graph, logger);
            if (config.getGraphDataDirectory() != null && !config.getGraphDataDirectory().isEmpty()) {
                graphBuilder.loadFromDirectory(config.getGraphDataDirectory());
            }
            logger.log(LogCategory.GRAPH, LogLevel.INFO, "WorkflowVulnScanner",
                    "Graph initialized. Nodes: " + graph.getNodeCount()
                            + ", Edges: " + graph.getEdgeCount());
        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "WorkflowVulnScanner",
                    "Failed to initialize graph.", e);
            this.graph = new RequestGraph();
            this.graphBuilder = new GraphBuilder(graph, logger);
        }
    }

    private void startGraphBuilder() {
        try {
            // Wire the disk-backed store into the graph builder so
            // every captured request is persisted to the store
            // (canonical record) and the hot in-memory graph is
            // kept as a working view of workflow-relevant traffic.
            if (graphBuilder != null && requestStore != null) {
                graphBuilder.setRequestStore(requestStore);
            }
            graphBuilder.start(pipeline, config);
            logger.log(LogCategory.GRAPH, LogLevel.INFO, "WorkflowVulnScanner",
                    "Graph builder started (request store: "
                            + (requestStore != null ? "wired" : "in-memory only") + ").");
        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "WorkflowVulnScanner",
                    "Failed to start graph builder.", e);
        }
    }

    private void initRequestPipeline() {
        try {
            this.pipeline = new RequestPipeline(config, logger);
            this.backfillService = new BackfillService(api, pipeline, config, logger);
            logger.log(LogCategory.EXTENSION, LogLevel.INFO, "WorkflowVulnScanner",
                    "Pipeline and backfill service initialized.");
        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "WorkflowVulnScanner",
                    "Failed to initialize pipeline.", e);
            this.pipeline = new RequestPipeline(config, logger);
            this.backfillService = new BackfillService(api, pipeline, config, logger);
        }
    }

    private void initLLMClient() {
        try {
            this.llmClient = new LLMClient(config, logger);
            logger.log(LogCategory.EXTENSION, LogLevel.INFO, "WorkflowVulnScanner",
                    "LLM client initialized (connection not tested).");
        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "WorkflowVulnScanner",
                    "Failed to initialize LLM client.", e);
            this.llmClient = new LLMClient(config, logger);
        }
    }

    private void initApplicationModel() {
        try {
            this.applicationModel = new ApplicationModel();
            // Wire the ApplicationModel into the graph builder BEFORE it starts
            // consuming traffic, so context reads and JS-discovered endpoints
            // are not dropped during the startup gap.
            if (graphBuilder != null) {
                graphBuilder.setApplicationModel(applicationModel);
            }
            logger.log(LogCategory.EXTENSION, LogLevel.INFO, "WorkflowVulnScanner",
                    "Application model initialized (wired to graphBuilder before start).");
        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "WorkflowVulnScanner",
                    "Failed to initialize application model.", e);
            this.applicationModel = new ApplicationModel();
        }
    }

    private void initAnalysisEngine() {
        try {
            // applicationModel was created in initApplicationModel(); use the
            // existing instance, do not overwrite.
            this.workflowDetector = new WorkflowDetector(config, logger);

            // Set graph context for edge-aware detection
            if (graphBuilder != null && graphBuilder.getDetector() != null) {
                workflowDetector.setGraphContext(graph, graphBuilder.getDetector());
            }

            this.analysisEngine = new AnalysisEngine(graph, llmClient, config, logger);
            analysisEngine.setWorkflowDetector(workflowDetector);
            if (applicationModel != null) {
                analysisEngine.setApplicationModel(applicationModel);
            }
            // applicationModel is already wired into graphBuilder from
            // initApplicationModel(); only set if missing (defensive).
            if (graphBuilder != null && applicationModel != null) {
                graphBuilder.setApplicationModel(applicationModel);
            }

            // Connect graph builder to workflow detector
            if (graphBuilder != null) {
                graphBuilder.setWorkflowDetector(workflowDetector);
            }

            logger.log(LogCategory.EXTENSION, LogLevel.INFO, "WorkflowVulnScanner",
                    "Analysis engine initialized with WorkflowDetector (edge-aware).");
        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "WorkflowVulnScanner",
                    "Failed to initialize analysis engine.", e);
        }
    }

    private void initValidationEngine() {
        try {
            this.validationEngine = new ValidationEngine(api, config, logger);
            // Publish strict / probable counts to the workflow
            // detector so the status bar can show them in O(1).
            if (workflowDetector != null) {
                validationEngine.setMetricsSink(workflowDetector);
            }
            logger.log(LogCategory.EXTENSION, LogLevel.INFO, "WorkflowVulnScanner",
                    "Validation engine initialized.");
        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "WorkflowVulnScanner",
                    "Failed to initialize validation engine.", e);
        }
    }

    private void initAdvisoryManager() {
        try {
            this.advisoryManager = new AdvisoryManager(api, logger);
            logger.log(LogCategory.EXTENSION, LogLevel.INFO, "WorkflowVulnScanner",
                    "Advisory manager initialized.");
        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "WorkflowVulnScanner",
                    "Failed to initialize advisory manager.", e);
        }
    }

    // ========================================================================
    // Pipeline Wiring (Event Bus)
    // ========================================================================

    /**
     * Wire the full pipeline: graph update -> candidate detection -> analysis -> validation -> advisory.
     * This is the critical integration step that connects all subsystems.
     */
    private void wirePipeline() {
        try {
            // Auto-analyze when graph is updated (if auto-analyze is enabled)
            if (graphBuilder != null && analysisEngine != null) {
                graphBuilder.addGraphUpdateListener(() -> {
                    if (config.isAutoAnalyzeNewChains() && !analysisEngine.isRunning()) {
                        // Debounce: cancel pending analysis and reschedule (2s delay)
                        if (pendingAutoAnalysis != null && !pendingAutoAnalysis.isDone()) {
                            pendingAutoAnalysis.cancel(false);
                        }
                        pendingAutoAnalysis = autoAnalysisScheduler.schedule(() -> {
                            if (!analysisEngine.isRunning()) {
                                logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "Pipeline",
                                        "Graph updated (debounced), triggering auto-analysis.");
                                eventBus.publish(EventBus.Event.GRAPH_UPDATED);
                                analysisEngine.start();
                            }
                        }, 2, TimeUnit.SECONDS);
                    }
                });
            }

            // When analysis completes a verdict, auto-validate and create advisory
            if (analysisEngine != null) {
                analysisEngine.addVerdictListener(verdict -> {
                    eventBus.publish(EventBus.Event.ANALYSIS_COMPLETE, verdict);

                    // Auto-validate VULNERABLE or SUSPICIOUS findings
                    if (validationEngine != null
                            && (verdict.isVulnerable() || verdict.isSuspicious())) {
                        try {
                            logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "Pipeline",
                                    "Auto-validating chain " + verdict.getChainId()
                                            + " (" + verdict.getOverallVerdict() + ")");

                            var validationResults = validationEngine.validate(verdict);
                            eventBus.publish(EventBus.Event.VALIDATION_COMPLETE, validationResults);

                            // Create advisory from validated findings
                            if (advisoryManager != null) {
                                var issue = advisoryManager.createFromVerdict(verdict, validationResults);
                                if (issue != null) {
                                    eventBus.publish(EventBus.Event.ISSUE_CREATED, issue);
                                    logger.log(LogCategory.ADVISORY, LogLevel.INFO, "Pipeline",
                                            "Advisory created: " + issue.name());
                                }
                            }
                        } catch (Exception e) {
                            logger.log(LogCategory.ERROR, LogLevel.ERROR, "Pipeline",
                                    "Error in validation/advisory pipeline.", e);
                        }
                    }
                });
            }

            // Pipeline request listener -> event bus
            if (pipeline != null) {
                pipeline.addListener(request -> {
                    eventBus.publish(EventBus.Event.REQUEST_CAPTURED, request);
                });
            }

            logger.log(LogCategory.EXTENSION, LogLevel.INFO, "WorkflowVulnScanner",
                    "Full pipeline wired: analysis -> validation -> advisory.");

        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "WorkflowVulnScanner",
                    "Failed to wire pipeline.", e);
        }
    }

    // ========================================================================
    // UI, HTTP Handler, Context Menu
    // ========================================================================

    private void initUI() {
        try {
            this.mainTabPanel = new MainTabPanel(api, config, logger, graph, graphBuilder,
                    pipeline, llmClient, analysisEngine, advisoryManager, backfillService, healthCheck);
            
            // Wire workflow detector and config into UI sub-panels
            if (mainTabPanel != null && workflowDetector != null) {
                mainTabPanel.setWorkflowDetector(workflowDetector, config);
            }
            
            api.userInterface().registerSuiteTab(EXTENSION_NAME, mainTabPanel.getComponent());
            logger.log(LogCategory.EXTENSION, LogLevel.INFO, "WorkflowVulnScanner",
                    "UI panels registered with status bar.");
        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "WorkflowVulnScanner",
                    "Failed to initialize UI.", e);
        }
    }

    private void initHttpHandler() {
        try {
            ProxyListener proxyListener = new ProxyListener(pipeline, config, logger);
            api.http().registerHttpHandler(proxyListener);
            logger.log(LogCategory.EXTENSION, LogLevel.INFO, "WorkflowVulnScanner",
                    "HTTP handler registered.");
        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "WorkflowVulnScanner",
                    "Failed to register HTTP handler.", e);
        }
    }

    private void initContextMenu() {
        try {
            ContextMenuProvider contextMenu = new ContextMenuProvider(pipeline, config, logger);
            api.userInterface().registerContextMenuItemsProvider(contextMenu);
            logger.log(LogCategory.EXTENSION, LogLevel.INFO, "WorkflowVulnScanner",
                    "Context menu registered.");
        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "WorkflowVulnScanner",
                    "Failed to register context menu.", e);
        }
    }

    private void initHealthCheck() {
        try {
            this.healthCheck = new HealthCheck(logger, pipeline, graphBuilder, graph,
                    llmClient, analysisEngine);
            if (requestStore != null) {
                healthCheck.setRequestStore(requestStore);
            }
            healthCheck.start(60); // Check every 60 seconds
            logger.log(LogCategory.EXTENSION, LogLevel.INFO, "WorkflowVulnScanner",
                    "Health check started (60s interval).");
        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "WorkflowVulnScanner",
                    "Failed to start health check.", e);
        }
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    public MontoyaApi getApi() { return api; }
    public ExtensionLogger getLogger() { return logger; }
    public ExtensionConfig getConfig() { return config; }
    public EventBus getEventBus() { return eventBus; }
    public RequestGraph getGraph() { return graph; }
    public RequestPipeline getPipeline() { return pipeline; }
    public RequestStore getRequestStore() { return requestStore; }
    public BackfillService getBackfillService() { return backfillService; }
    public LLMClient getLlmClient() { return llmClient; }
    public AnalysisEngine getAnalysisEngine() { return analysisEngine; }
    public ValidationEngine getValidationEngine() { return validationEngine; }
    public AdvisoryManager getAdvisoryManager() { return advisoryManager; }

    // ========================================================================
    // Graceful Shutdown
    // ========================================================================

    private class ShutdownHandler implements ExtensionUnloadingHandler {
        @Override
        public void extensionUnloaded() {
            logger.log(LogCategory.EXTENSION, LogLevel.INFO, "WorkflowVulnScanner",
                    "Extension unloading - graceful shutdown...");

            // 1. Stop health check
            shutdown("HealthCheck", () -> { if (healthCheck != null) healthCheck.stop(); });

            // 2. Cancel in-progress analyses
            shutdown("AnalysisEngine", () -> { if (analysisEngine != null) analysisEngine.shutdown(); });

            // 3. Stop graph builder and save graph
            shutdown("GraphBuilder", () -> {
                if (graphBuilder != null) {
                    graphBuilder.stop();
                    if (config.getGraphDataDirectory() != null
                            && !config.getGraphDataDirectory().isEmpty()) {
                        graphBuilder.saveToDirectory(config.getGraphDataDirectory());
                    }
                }
            });

            // 4. Stop backfill service
            shutdown("BackfillService", () -> { if (backfillService != null) backfillService.shutdown(); });

            // 5. Stop pipeline
            shutdown("Pipeline", () -> { if (pipeline != null) pipeline.shutdown(); });

            // 6. Dispose UI
            shutdown("UI", () -> { if (mainTabPanel != null) mainTabPanel.dispose(); });

            // 7. Clear event bus
            shutdown("EventBus", () -> { if (eventBus != null) eventBus.clear(); });

            // 8. Shutdown auto-analysis scheduler (prevents daemon thread leak)
            shutdown("AutoAnalysisScheduler", () -> {
                if (pendingAutoAnalysis != null) {
                    pendingAutoAnalysis.cancel(false);
                    pendingAutoAnalysis = null;
                }
                if (autoAnalysisScheduler != null) {
                    autoAnalysisScheduler.shutdownNow();
                }
            });

            // 9. Save configuration
            shutdown("Config", () -> { if (config != null) config.save(api); });

            // 10. Close the disk-backed request store
            shutdown("RequestStore", () -> {
                if (requestStore != null) requestStore.close();
            });

            // 11. Flush and shutdown logs (last)
            if (logger != null) {
                try {
                    logger.flush();
                    logger.log(LogCategory.EXTENSION, LogLevel.INFO, "ShutdownHandler",
                            "Extension unloaded cleanly.");
                    logger.shutdown();
                } catch (Exception e) {
                    api.logging().logToOutput("Error flushing logs: " + e.getMessage());
                }
            }
        }

        private void shutdown(String name, Runnable action) {
            try {
                action.run();
                logger.log(LogCategory.EXTENSION, LogLevel.INFO, "ShutdownHandler",
                        name + " shut down.");
            } catch (Exception e) {
                logger.log(LogCategory.ERROR, LogLevel.ERROR, "ShutdownHandler",
                        "Error shutting down " + name + ".", e);
            }
        }
    }
}

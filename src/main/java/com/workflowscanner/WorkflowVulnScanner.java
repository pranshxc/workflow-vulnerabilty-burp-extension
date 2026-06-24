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
import com.workflowscanner.ui.MainTabPanel;
import com.workflowscanner.workflow.WorkflowDetector;
import com.workflowscanner.workflow.WorkflowCandidate;

import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
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
    private final AtomicBoolean autoAnalysisScheduled = new AtomicBoolean(false);
    private Timer autoAnalysisTimer;
    
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

        // 4. Graph data store
        initGraph();

        // 5. Request pipeline + backfill service
        initRequestPipeline();

        // 6. Start graph builder (pipeline -> graph)
        startGraphBuilder();

        // 7. LLM client
        initLLMClient();

        // 8. Analysis engine
        initAnalysisEngine();

        // 9. Validation engine
        initValidationEngine();

        // 10. Advisory manager
        initAdvisoryManager();

        // 11. Wire the full pipeline via event bus
        wirePipeline();

        // 12. UI panels
        initUI();

        // 13. HTTP handler (live proxy traffic)
        initHttpHandler();

        // 14. Context menu
        initContextMenu();

        // 15. Health check
        initHealthCheck();

        // 16. Register unload handler
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
            graphBuilder.start(pipeline, config);
            logger.log(LogCategory.GRAPH, LogLevel.INFO, "WorkflowVulnScanner",
                    "Graph builder started.");
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

    private void initAnalysisEngine() {
        try {
            this.applicationModel = new ApplicationModel();
            this.workflowDetector = new WorkflowDetector(config, logger);
            
            // Set graph context for edge-aware detection
            if (graphBuilder != null && graphBuilder.getDetector() != null) {
                workflowDetector.setGraphContext(graph, graphBuilder.getDetector());
            }
            
            this.analysisEngine = new AnalysisEngine(graph, llmClient, config, logger);
            analysisEngine.setWorkflowDetector(workflowDetector);
            analysisEngine.setApplicationModel(applicationModel);

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
                        // Debounce: reset timer on each graph update (2s debounce window)
                        if (autoAnalysisTimer == null) {
                            autoAnalysisTimer = new Timer("auto-analysis-debounce", true);
                        }
                        // Cancel pending execution if one is scheduled
                        if (autoAnalysisScheduled.getAndSet(true)) {
                            autoAnalysisTimer.purge();
                        }
                        autoAnalysisTimer.schedule(new TimerTask() {
                            @Override
                            public void run() {
                                if (!analysisEngine.isRunning()) {
                                    autoAnalysisScheduled.set(false);
                                    logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "Pipeline",
                                            "Graph updated (debounced), triggering auto-analysis.");
                                    eventBus.publish(EventBus.Event.GRAPH_UPDATED);
                                    analysisEngine.start();
                                }
                            }
                        }, 2000L); // 2-second debounce
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

            // 8. Save configuration
            shutdown("Config", () -> { if (config != null) config.save(api); });

            // 9. Flush and shutdown logs (last)
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

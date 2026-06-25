package com.workflowscanner.ui;

import burp.api.montoya.MontoyaApi;
import com.workflowscanner.HealthCheck;
import com.workflowscanner.advisory.AdvisoryManager;
import com.workflowscanner.analysis.AnalysisEngine;
import com.workflowscanner.config.ExtensionConfig;
import com.workflowscanner.data.BackfillService;
import com.workflowscanner.data.RequestPipeline;
import com.workflowscanner.graph.GraphBuilder;
import com.workflowscanner.graph.RequestGraph;
import com.workflowscanner.llm.LLMClient;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.store.RequestStore;
import com.workflowscanner.workflow.WorkflowDetector;

import javax.swing.*;
import java.awt.*;

/**
 * Main tab panel registered in Burp Suite's UI.
 * Contains sub-tabs: Settings, Log, Graph and a status bar at the bottom.
 */
public class MainTabPanel {

    private final JPanel mainPanel;
    private final JTabbedPane tabbedPane;
    private SettingsPanel settingsPanel;
    private StatusBarPanel statusBar;
    private GraphPanel graphPanel;

    public MainTabPanel(MontoyaApi api, ExtensionConfig config, ExtensionLogger logger,
                        RequestGraph graph, GraphBuilder graphBuilder, RequestPipeline pipeline,
                        LLMClient llmClient, AnalysisEngine analysisEngine,
                        AdvisoryManager advisoryManager) {
        this(api, config, logger, graph, graphBuilder, pipeline, llmClient,
                analysisEngine, advisoryManager, null, null);
    }

    @SuppressWarnings("checkstyle:parameternumber")
    public MainTabPanel(MontoyaApi api, ExtensionConfig config, ExtensionLogger logger,
                        RequestGraph graph, GraphBuilder graphBuilder, RequestPipeline pipeline,
                        LLMClient llmClient, AnalysisEngine analysisEngine,
                        AdvisoryManager advisoryManager, BackfillService backfillService) {
        this(api, config, logger, graph, graphBuilder, pipeline, llmClient,
                analysisEngine, advisoryManager, backfillService, null);
    }

    @SuppressWarnings("checkstyle:parameternumber")
    public MainTabPanel(MontoyaApi api, ExtensionConfig config, ExtensionLogger logger,
                        RequestGraph graph, GraphBuilder graphBuilder, RequestPipeline pipeline,
                        LLMClient llmClient, AnalysisEngine analysisEngine,
                        AdvisoryManager advisoryManager, BackfillService backfillService,
                        HealthCheck healthCheck) {

        mainPanel = new JPanel(new BorderLayout());
        tabbedPane = new JTabbedPane();

        // Settings tab
        if (backfillService != null) {
            settingsPanel = new SettingsPanel(api, config, logger, graph, graphBuilder,
                    pipeline, llmClient, analysisEngine, backfillService);
            tabbedPane.addTab("Settings", settingsPanel);
        } else {
            JPanel placeholder = new JPanel(new BorderLayout());
            placeholder.add(new JLabel("  Settings panel requires BackfillService",
                    SwingConstants.CENTER), BorderLayout.CENTER);
            tabbedPane.addTab("Settings", placeholder);
        }

        // Log tab
        LogPanel logPanel = new LogPanel(logger);
        tabbedPane.addTab("Log", logPanel);

        // Graph tab
        graphPanel = new GraphPanel(api, graph, analysisEngine, logger);
        tabbedPane.addTab("Graph", graphPanel);

        mainPanel.add(tabbedPane, BorderLayout.CENTER);

        // Status bar at bottom
        if (healthCheck != null) {
            statusBar = new StatusBarPanel(healthCheck);
            mainPanel.add(statusBar, BorderLayout.SOUTH);
        }
    }

    /**
     * Wire the workflow detector and config into sub-panels that need them.
     * Called after construction when the detector is available.
     */
    public void setWorkflowDetector(WorkflowDetector detector, ExtensionConfig config) {
        for (int i = 0; i < tabbedPane.getTabCount(); i++) {
            Component c = tabbedPane.getComponentAt(i);
            if (c instanceof GraphPanel) {
                ((GraphPanel) c).setWorkflowDetector(detector);
                ((GraphPanel) c).setConfig(config);
            }
        }
    }

    /**
     * Wire the disk-backed request store into all GraphPanels so
     * View Request/Response and Send to Repeater can re-hydrate
     * raw HTTP for backfilled nodes.
     */
    public void setRequestStore(RequestStore store) {
        for (int i = 0; i < tabbedPane.getTabCount(); i++) {
            Component c = tabbedPane.getComponentAt(i);
            if (c instanceof GraphPanel) {
                ((GraphPanel) c).setRequestStore(store);
            }
        }
    }

    /**
     * Get the Swing component to register with Burp's UI.
     */
    public Component getComponent() {
        return mainPanel;
    }

    /**
     * Dispose resources (stop timers, etc.).
     */
    public void dispose() {
        if (settingsPanel != null) {
            settingsPanel.dispose();
        }
        if (statusBar != null) {
            statusBar.stopUpdates();
        }
        if (graphPanel != null) {
            graphPanel.dispose();
        }
    }
}

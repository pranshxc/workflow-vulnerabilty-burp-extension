package com.workflowscanner.ui;

import burp.api.montoya.MontoyaApi;
import com.workflowscanner.advisory.AdvisoryManager;
import com.workflowscanner.analysis.AnalysisEngine;
import com.workflowscanner.config.ExtensionConfig;
import com.workflowscanner.data.BackfillService;
import com.workflowscanner.data.RequestPipeline;
import com.workflowscanner.graph.GraphBuilder;
import com.workflowscanner.graph.RequestGraph;
import com.workflowscanner.llm.LLMClient;
import com.workflowscanner.logging.ExtensionLogger;

import javax.swing.*;
import java.awt.*;

/**
 * Main tab panel registered in Burp Suite's UI.
 * Contains sub-tabs: Settings, Log, Graph.
 */
public class MainTabPanel {

    private final JTabbedPane tabbedPane;
    private SettingsPanel settingsPanel;

    public MainTabPanel(MontoyaApi api, ExtensionConfig config, ExtensionLogger logger,
                        RequestGraph graph, GraphBuilder graphBuilder, RequestPipeline pipeline,
                        LLMClient llmClient, AnalysisEngine analysisEngine,
                        AdvisoryManager advisoryManager) {
        this(api, config, logger, graph, graphBuilder, pipeline, llmClient,
                analysisEngine, advisoryManager, null);
    }

    public MainTabPanel(MontoyaApi api, ExtensionConfig config, ExtensionLogger logger,
                        RequestGraph graph, GraphBuilder graphBuilder, RequestPipeline pipeline,
                        LLMClient llmClient, AnalysisEngine analysisEngine,
                        AdvisoryManager advisoryManager, BackfillService backfillService) {

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
        GraphPanel graphExplorer = new GraphPanel(api, graph, analysisEngine, logger);
        tabbedPane.addTab("Graph", graphExplorer);
    }

    /**
     * Get the Swing component to register with Burp's UI.
     */
    public Component getComponent() {
        return tabbedPane;
    }

    /**
     * Dispose resources (stop timers, etc.).
     */
    public void dispose() {
        if (settingsPanel != null) {
            settingsPanel.dispose();
        }
    }
}

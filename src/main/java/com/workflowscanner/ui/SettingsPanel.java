package com.workflowscanner.ui;

import burp.api.montoya.MontoyaApi;
import com.workflowscanner.analysis.AnalysisEngine;
import com.workflowscanner.config.ExtensionConfig;
import com.workflowscanner.data.BackfillService;
import com.workflowscanner.data.RequestPipeline;
import com.workflowscanner.graph.GraphBuilder;
import com.workflowscanner.graph.RequestGraph;
import com.workflowscanner.llm.LLMClient;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Settings panel for the Workflow Vulnerability Scanner.
 * Provides configuration UI for LLM, graph, backfill, scope, and analysis.
 * All long-running operations run on background threads.
 */
public class SettingsPanel extends JPanel {

    private final MontoyaApi api;
    private final ExtensionConfig config;
    private final ExtensionLogger logger;
    private final RequestGraph graph;
    private final GraphBuilder graphBuilder;
    private final LLMClient llmClient;
    private final AnalysisEngine analysisEngine;
    private final BackfillService backfillService;

    // LLM fields
    private JTextField llmBaseUrlField;
    private JTextField llmModelField;
    private JPasswordField llmApiKeyField;
    private JLabel connectionStatusLabel;

    // Graph fields
    private JTextField graphDirField;
    private JLabel graphStatsLabel;

    // Backfill fields
    private JSpinner backfillLimitSpinner;
    private JRadioButton backfillAllRadio;
    private JRadioButton backfillScopeRadio;
    private JLabel backfillStatusLabel;
    private JButton backfillStartBtn;
    private JButton backfillCancelBtn;

    // Scope fields
    private JTextArea scopePatternsArea;
    private JLabel scopeMatchLabel;

    // Analysis fields
    private JComboBox<Integer> concurrencyCombo;
    private JCheckBox autoAnalyzeCheck;
    private JRadioButton valConservative;
    private JRadioButton valStandard;
    private JRadioButton valAggressive;
    private JLabel analysisStatusLabel;
    private JButton analysisStartBtn;
    private JButton analysisPauseBtn;
    private JButton analysisStopBtn;

    // Timer for live updates
    private Timer updateTimer;

    public SettingsPanel(MontoyaApi api, ExtensionConfig config, ExtensionLogger logger,
                         RequestGraph graph, GraphBuilder graphBuilder, RequestPipeline pipeline,
                         LLMClient llmClient, AnalysisEngine analysisEngine,
                         BackfillService backfillService) {
        this.api = api;
        this.config = config;
        this.logger = logger;
        this.graph = graph;
        this.graphBuilder = graphBuilder;
        this.llmClient = llmClient;
        this.analysisEngine = analysisEngine;
        this.backfillService = backfillService;

        setLayout(new BorderLayout());

        // Title
        JLabel title = new JLabel("  WORKFLOW VULNERABILITY SCANNER - SETTINGS", SwingConstants.LEFT);
        title.setFont(title.getFont().deriveFont(Font.BOLD, 14f));
        title.setBorder(BorderFactory.createEmptyBorder(10, 5, 10, 5));
        add(title, BorderLayout.NORTH);

        // Main content in scroll pane
        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

        content.add(createLLMSection());
        content.add(Box.createVerticalStrut(10));
        content.add(createGraphSection());
        content.add(Box.createVerticalStrut(10));
        content.add(createBackfillSection());
        content.add(Box.createVerticalStrut(10));
        content.add(createScopeSection());
        content.add(Box.createVerticalStrut(10));
        content.add(createAnalysisSection());
        content.add(Box.createVerticalStrut(15));
        content.add(createButtonBar());
        content.add(Box.createVerticalGlue());

        JScrollPane scrollPane = new JScrollPane(content);
        scrollPane.setBorder(null);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        add(scrollPane, BorderLayout.CENTER);

        // Load current config into fields
        loadFromConfig();

        // Start periodic UI update timer
        updateTimer = new Timer(2000, e -> updateLiveStatus());
        updateTimer.start();
    }

    // ========================================================================
    // Section Builders
    // ========================================================================

    private JPanel createLLMSection() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "LLM Configuration",
                TitledBorder.LEFT, TitledBorder.TOP));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 5, 3, 5);
        gbc.anchor = GridBagConstraints.WEST;

        // Base URL
        gbc.gridx = 0; gbc.gridy = 0;
        panel.add(new JLabel("Base URL:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        llmBaseUrlField = new JTextField(30);
        panel.add(llmBaseUrlField, gbc);

        // Model ID
        gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        panel.add(new JLabel("Model ID:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        llmModelField = new JTextField(30);
        panel.add(llmModelField, gbc);

        // API Key
        gbc.gridx = 0; gbc.gridy = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        panel.add(new JLabel("API Key:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        llmApiKeyField = new JPasswordField(30);
        panel.add(llmApiKeyField, gbc);

        // Test Connection button + status
        gbc.gridx = 0; gbc.gridy = 3; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        JButton testBtn = new JButton("Test Connection");
        testBtn.addActionListener(e -> testConnection());
        panel.add(testBtn, gbc);
        gbc.gridx = 1;
        connectionStatusLabel = new JLabel(" ");
        panel.add(connectionStatusLabel, gbc);

        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, panel.getPreferredSize().height));
        return panel;
    }

    private JPanel createGraphSection() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Graph Data Directory",
                TitledBorder.LEFT, TitledBorder.TOP));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 5, 3, 5);
        gbc.anchor = GridBagConstraints.WEST;

        // Path
        gbc.gridx = 0; gbc.gridy = 0;
        panel.add(new JLabel("Path:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        graphDirField = new JTextField(30);
        panel.add(graphDirField, gbc);

        // Browse + Clear buttons
        gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        JButton browseBtn = new JButton("Browse...");
        browseBtn.addActionListener(e -> browseGraphDir());
        btnPanel.add(browseBtn);
        JButton clearBtn = new JButton("Clear Graph Data");
        clearBtn.addActionListener(e -> clearGraphData());
        btnPanel.add(clearBtn);
        gbc.gridwidth = 2;
        panel.add(btnPanel, gbc);

        // Stats
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2;
        graphStatsLabel = new JLabel("Status: loading...");
        panel.add(graphStatsLabel, gbc);

        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, panel.getPreferredSize().height));
        return panel;
    }

    private JPanel createBackfillSection() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Backfill Settings",
                TitledBorder.LEFT, TitledBorder.TOP));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 5, 3, 5);
        gbc.anchor = GridBagConstraints.WEST;

        // Limit
        gbc.gridx = 0; gbc.gridy = 0;
        panel.add(new JLabel("Limit:"), gbc);
        gbc.gridx = 1;
        backfillLimitSpinner = new JSpinner(new SpinnerNumberModel(500, 1, 10000, 100));
        panel.add(backfillLimitSpinner, gbc);
        gbc.gridx = 2;
        panel.add(new JLabel("requests"), gbc);

        // Scope
        gbc.gridx = 0; gbc.gridy = 1;
        panel.add(new JLabel("Scope:"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 2;
        backfillAllRadio = new JRadioButton("All history");
        backfillScopeRadio = new JRadioButton("In-scope only");
        ButtonGroup bg = new ButtonGroup();
        bg.add(backfillAllRadio);
        bg.add(backfillScopeRadio);
        JPanel radioPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        radioPanel.add(backfillAllRadio);
        radioPanel.add(backfillScopeRadio);
        panel.add(radioPanel, gbc);

        // Buttons
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 1;
        backfillStartBtn = new JButton("Start Backfill");
        backfillStartBtn.addActionListener(e -> startBackfill());
        panel.add(backfillStartBtn, gbc);
        gbc.gridx = 1;
        backfillCancelBtn = new JButton("Cancel");
        backfillCancelBtn.setEnabled(false);
        backfillCancelBtn.addActionListener(e -> cancelBackfill());
        panel.add(backfillCancelBtn, gbc);

        // Status
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 3;
        backfillStatusLabel = new JLabel("Progress: Idle");
        panel.add(backfillStatusLabel, gbc);

        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, panel.getPreferredSize().height));
        return panel;
    }

    private JPanel createScopeSection() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Scope Filter",
                TitledBorder.LEFT, TitledBorder.TOP));

        scopePatternsArea = new JTextArea(5, 30);
        scopePatternsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        scopePatternsArea.setToolTipText("One glob pattern per line (e.g., *.example.com)");
        JScrollPane scroll = new JScrollPane(scopePatternsArea);
        panel.add(scroll, BorderLayout.CENTER);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 3));
        JButton clearAllBtn = new JButton("Clear All");
        clearAllBtn.addActionListener(e -> scopePatternsArea.setText(""));
        btnPanel.add(clearAllBtn);
        scopeMatchLabel = new JLabel(" ");
        btnPanel.add(scopeMatchLabel);
        panel.add(btnPanel, BorderLayout.SOUTH);

        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 200));
        return panel;
    }

    private JPanel createAnalysisSection() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Analysis Controls",
                TitledBorder.LEFT, TitledBorder.TOP));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 5, 3, 5);
        gbc.anchor = GridBagConstraints.WEST;

        // Concurrency
        gbc.gridx = 0; gbc.gridy = 0;
        panel.add(new JLabel("Concurrency:"), gbc);
        gbc.gridx = 1;
        concurrencyCombo = new JComboBox<>(new Integer[]{1, 2, 3, 4, 5});
        panel.add(concurrencyCombo, gbc);
        gbc.gridx = 2;
        panel.add(new JLabel("concurrent chains"), gbc);

        // Auto-analyze
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 3;
        autoAnalyzeCheck = new JCheckBox("Analyze new chains automatically");
        panel.add(autoAnalyzeCheck, gbc);

        // Validation profile
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 1;
        panel.add(new JLabel("Validation:"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 2;
        valConservative = new JRadioButton("Conservative");
        valStandard = new JRadioButton("Standard");
        valAggressive = new JRadioButton("Aggressive");
        ButtonGroup valGroup = new ButtonGroup();
        valGroup.add(valConservative);
        valGroup.add(valStandard);
        valGroup.add(valAggressive);
        JPanel valPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        valPanel.add(valConservative);
        valPanel.add(valStandard);
        valPanel.add(valAggressive);
        panel.add(valPanel, gbc);

        // Control buttons
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 1;
        analysisStartBtn = new JButton("Start Analysis");
        analysisStartBtn.addActionListener(e -> startAnalysis());
        panel.add(analysisStartBtn, gbc);
        gbc.gridx = 1;
        analysisPauseBtn = new JButton("Pause");
        analysisPauseBtn.setEnabled(false);
        analysisPauseBtn.addActionListener(e -> togglePauseAnalysis());
        panel.add(analysisPauseBtn, gbc);
        gbc.gridx = 2;
        analysisStopBtn = new JButton("Stop");
        analysisStopBtn.setEnabled(false);
        analysisStopBtn.addActionListener(e -> stopAnalysis());
        panel.add(analysisStopBtn, gbc);

        // Status
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 3;
        analysisStatusLabel = new JLabel("Status: Idle");
        panel.add(analysisStatusLabel, gbc);

        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, panel.getPreferredSize().height));
        return panel;
    }

    private JPanel createButtonBar() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        JButton saveBtn = new JButton("Save Settings");
        saveBtn.addActionListener(e -> saveSettings());
        panel.add(saveBtn);

        JButton resetBtn = new JButton("Reset to Defaults");
        resetBtn.addActionListener(e -> resetToDefaults());
        panel.add(resetBtn);

        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 50));
        return panel;
    }

    // ========================================================================
    // Config Load / Save
    // ========================================================================

    private void loadFromConfig() {
        llmBaseUrlField.setText(config.getLlmBaseUrl());
        llmModelField.setText(config.getLlmModelId());
        llmApiKeyField.setText(config.getLlmApiKey());
        graphDirField.setText(config.getGraphDataDirectory());
        backfillLimitSpinner.setValue(config.getBackfillLimit());
        if (config.isBackfillInScopeOnly()) backfillScopeRadio.setSelected(true);
        else backfillAllRadio.setSelected(true);

        String patterns = String.join("\n", config.getScopeFilterPatterns());
        scopePatternsArea.setText(patterns);

        concurrencyCombo.setSelectedItem(config.getAnalysisConcurrency());
        autoAnalyzeCheck.setSelected(config.isAutoAnalyzeNewChains());

        switch (config.getValidationProfile()) {
            case "conservative": valConservative.setSelected(true); break;
            case "aggressive": valAggressive.setSelected(true); break;
            default: valStandard.setSelected(true); break;
        }
    }

    private void saveSettings() {
        config.setLlmBaseUrl(llmBaseUrlField.getText().trim());
        config.setLlmModelId(llmModelField.getText().trim());
        config.setLlmApiKey(new String(llmApiKeyField.getPassword()));
        config.setGraphDataDirectory(graphDirField.getText().trim());
        config.setBackfillLimit((Integer) backfillLimitSpinner.getValue());
        config.setBackfillInScopeOnly(backfillScopeRadio.isSelected());

        // Parse scope patterns
        String text = scopePatternsArea.getText().trim();
        List<String> patterns = Arrays.stream(text.split("\n"))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());
        config.setScopeFilterPatterns(patterns);

        config.setAnalysisConcurrency((Integer) concurrencyCombo.getSelectedItem());
        config.setAutoAnalyzeNewChains(autoAnalyzeCheck.isSelected());

        if (valConservative.isSelected()) config.setValidationProfile("conservative");
        else if (valAggressive.isSelected()) config.setValidationProfile("aggressive");
        else config.setValidationProfile("standard");

        config.save(api);
        logger.log(LogCategory.CONFIG, LogLevel.INFO, "SettingsPanel", "Settings saved.");
        JOptionPane.showMessageDialog(this, "Settings saved.", "Settings", JOptionPane.INFORMATION_MESSAGE);
    }

    private void resetToDefaults() {
        int result = JOptionPane.showConfirmDialog(this,
                "Reset all settings to defaults?", "Reset Settings",
                JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (result == JOptionPane.YES_OPTION) {
            config.resetToDefaults();
            loadFromConfig();
            logger.log(LogCategory.CONFIG, LogLevel.INFO, "SettingsPanel", "Settings reset to defaults.");
        }
    }

    // ========================================================================
    // Actions
    // ========================================================================

    private void testConnection() {
        // Save current LLM fields to config first
        config.setLlmBaseUrl(llmBaseUrlField.getText().trim());
        config.setLlmModelId(llmModelField.getText().trim());
        config.setLlmApiKey(new String(llmApiKeyField.getPassword()));

        connectionStatusLabel.setText("Testing...");
        connectionStatusLabel.setForeground(Color.GRAY);

        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                return llmClient.testConnection();
            }

            @Override
            protected void done() {
                try {
                    String result = get();
                    if (result != null && result.startsWith("Connected")) {
                        connectionStatusLabel.setText("\u2713 " + result);
                        connectionStatusLabel.setForeground(new Color(0, 128, 0));
                    } else {
                        connectionStatusLabel.setText("\u2717 " + (result != null ? result : "Failed"));
                        connectionStatusLabel.setForeground(Color.RED);
                    }
                } catch (Exception e) {
                    connectionStatusLabel.setText("\u2717 Error: " + e.getMessage());
                    connectionStatusLabel.setForeground(Color.RED);
                }
            }
        }.execute();
    }

    private void browseGraphDir() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        if (!graphDirField.getText().isEmpty()) {
            chooser.setCurrentDirectory(new java.io.File(graphDirField.getText()));
        }
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            graphDirField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void clearGraphData() {
        int result = JOptionPane.showConfirmDialog(this,
                "Are you sure? This deletes all graph data.",
                "Clear Graph Data", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (result == JOptionPane.YES_OPTION) {
            graph.clear();
            logger.log(LogCategory.GRAPH, LogLevel.INFO, "SettingsPanel", "Graph data cleared.");
            updateLiveStatus();
        }
    }

    private void startBackfill() {
        // Save backfill settings first
        config.setBackfillLimit((Integer) backfillLimitSpinner.getValue());
        config.setBackfillInScopeOnly(backfillScopeRadio.isSelected());

        backfillService.start();
        backfillStartBtn.setEnabled(false);
        backfillCancelBtn.setEnabled(true);
    }

    private void cancelBackfill() {
        backfillService.cancel();
        backfillStartBtn.setEnabled(true);
        backfillCancelBtn.setEnabled(false);
    }

    private void startAnalysis() {
        saveSettings(); // Ensure latest config is applied
        analysisEngine.start();
        analysisStartBtn.setEnabled(false);
        analysisPauseBtn.setEnabled(true);
        analysisStopBtn.setEnabled(true);
    }

    private void togglePauseAnalysis() {
        if (analysisEngine.isPaused()) {
            analysisEngine.resume();
            analysisPauseBtn.setText("Pause");
        } else {
            analysisEngine.pause();
            analysisPauseBtn.setText("Resume");
        }
    }

    private void stopAnalysis() {
        analysisEngine.stop();
        analysisStartBtn.setEnabled(true);
        analysisPauseBtn.setEnabled(false);
        analysisPauseBtn.setText("Pause");
        analysisStopBtn.setEnabled(false);
    }

    // ========================================================================
    // Live Status Updates
    // ========================================================================

    private void updateLiveStatus() {
        SwingUtilities.invokeLater(() -> {
            // Graph stats. Show in-heap nodes/edges plus the workflow
            // candidate split (edge-supported vs session-only) so it
            // is obvious where each candidate came from. All numbers
            // are O(1) reads — no graph traversal, no
            // connected-component scan.
            com.workflowscanner.graph.RequestGraph.GraphStats stats = graph.getStats();
            StringBuilder statsText = new StringBuilder("Status: ")
                    .append(stats.nodeCount).append(" nodes (relevant: ")
                    .append(stats.workflowRelevantNodeCount).append("), ")
                    .append(stats.edgeCount).append(" edges (explicit: ")
                    .append(stats.explicitEdgeCount).append(", derived: ")
                    .append(stats.derivedEdgeCount).append(")");
            if (stats.workflowCandidateCount > 0) {
                statsText.append(", ").append(stats.workflowCandidateCount)
                        .append(" candidates (edge: ").append(stats.edgeSupportedCandidateCount)
                        .append(", session: ").append(stats.sessionOnlyCandidateCount)
                        .append(")");
            }
            graphStatsLabel.setText(statsText.toString());

            // Backfill status
            if (backfillService != null) {
                backfillStatusLabel.setText("Progress: " + backfillService.getStatusText());
                boolean running = backfillService.isRunning();
                backfillStartBtn.setEnabled(!running);
                backfillCancelBtn.setEnabled(running);
            }

            // Analysis status
            if (analysisEngine != null) {
                analysisStatusLabel.setText("Status: " + analysisEngine.getProgressText());
                boolean running = analysisEngine.isRunning();
                analysisStartBtn.setEnabled(!running);
                analysisPauseBtn.setEnabled(running);
                analysisStopBtn.setEnabled(running);
            }

            // Scope match count
            int patternCount = (int) Arrays.stream(scopePatternsArea.getText().split("\n"))
                    .map(String::trim).filter(s -> !s.isEmpty()).count();
            scopeMatchLabel.setText(patternCount + " pattern(s) configured");
        });
    }

    /**
     * Stop the update timer (called on extension unload).
     */
    public void dispose() {
        if (updateTimer != null) {
            updateTimer.stop();
        }
    }
}

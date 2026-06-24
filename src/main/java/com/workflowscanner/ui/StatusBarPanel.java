package com.workflowscanner.ui;

import com.workflowscanner.HealthCheck;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.Map;

/**
 * Status bar displayed at the bottom of the main UI tab.
 * Shows live operational metrics from HealthCheck.
 * Updates every 5 seconds via a timer.
 */
public class StatusBarPanel extends JPanel {

    private final JLabel pipelineLabel;
    private final JLabel graphLabel;
    private final JLabel candidatesLabel;
    private final JLabel findingsLabel;
    private final JLabel errorsLabel;
    private final JLabel suppressedLabel;

    private final HealthCheck healthCheck;
    private Timer updateTimer;

    public StatusBarPanel(HealthCheck healthCheck) {
        this.healthCheck = healthCheck;

        setLayout(new FlowLayout(FlowLayout.LEFT, 12, 2));
        setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, Color.LIGHT_GRAY),
                new EmptyBorder(2, 8, 2, 8)));
        setBackground(new Color(245, 245, 245));

        pipelineLabel = createLabel("Pipeline: --");
        graphLabel = createLabel("Graph: --");
        candidatesLabel = createLabel("Candidates: --");
        findingsLabel = createLabel("Findings: --");
        errorsLabel = createLabel("Errors: --");
        suppressedLabel = createLabel("Suppressed: --");

        add(pipelineLabel);
        add(createSeparator());
        add(graphLabel);
        add(createSeparator());
        add(candidatesLabel);
        add(createSeparator());
        add(findingsLabel);
        add(createSeparator());
        add(errorsLabel);
        add(createSeparator());
        add(suppressedLabel);

        startUpdates();
    }

    private JLabel createLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(new Font("Monospaced", Font.PLAIN, 11));
        label.setForeground(Color.DARK_GRAY);
        return label;
    }

    private JSeparator createSeparator() {
        JSeparator sep = new JSeparator(SwingConstants.VERTICAL);
        sep.setPreferredSize(new Dimension(2, 12));
        return sep;
    }

    private void startUpdates() {
        updateTimer = new Timer(5000, e -> updateMetrics());
        updateTimer.start();
        // Initial update
        updateMetrics();
    }

    private void updateMetrics() {
        if (healthCheck == null) return;

        try {
            Map<String, String> metrics = healthCheck.getMetrics();

            String pipelineDepth = metrics.getOrDefault("pipeline_depth", "?");
            String pipelineCapacity = metrics.getOrDefault("pipeline_capacity", "?");
            pipelineLabel.setText("Pipeline: " + pipelineDepth + "/" + pipelineCapacity);

            String nodes = metrics.getOrDefault("graph_nodes", "?");
            String edges = metrics.getOrDefault("graph_edges", "?");
            graphLabel.setText("Graph: " + nodes + "n/" + edges + "e");

            String candidates = metrics.getOrDefault("workflow_candidates", "?");
            candidatesLabel.setText("Candidates: " + candidates);

            String analyzed = metrics.getOrDefault("analyzed_chains", "?");
            String findings = metrics.getOrDefault("findings_count", "?");
            findingsLabel.setText("Findings: " + findings + "/" + analyzed);

            String llmErrors = metrics.getOrDefault("llm_errors", "0");
            String replayErrors = metrics.getOrDefault("replay_errors", "0");
            errorsLabel.setText("Errors: " + llmErrors + "L/" + replayErrors + "R");

            String suppressed = metrics.getOrDefault("suppressed_total", "?");
            suppressedLabel.setText("Suppressed: " + suppressed);

        } catch (Exception ignored) {
            // Health check not available or metrics not ready
        }
    }

    public void stopUpdates() {
        if (updateTimer != null) {
            updateTimer.stop();
        }
    }

    @Override
    public void removeNotify() {
        super.removeNotify();
        stopUpdates();
    }
}

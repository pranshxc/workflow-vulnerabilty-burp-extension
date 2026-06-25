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
    private final JLabel edgesBreakdownLabel;
    private final JLabel findingsLabel;
    private final JLabel errorsLabel;
    private final JLabel suppressedLabel;
    private final JLabel diagnosticLabel;

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
        edgesBreakdownLabel = createLabel("(edge/session split unavailable)");
        findingsLabel = createLabel("Findings: --");
        errorsLabel = createLabel("Errors: --");
        suppressedLabel = createLabel("Suppressed: --");
        // Diagnostic is hidden by default; set visible only when
        // HealthCheck reports edges=0 + candidates>0.
        diagnosticLabel = createLabel("");
        diagnosticLabel.setForeground(new Color(180, 60, 0));
        diagnosticLabel.setVisible(false);

        add(pipelineLabel);
        add(createSeparator());
        add(graphLabel);
        add(createSeparator());
        add(candidatesLabel);
        add(edgesBreakdownLabel);
        add(createSeparator());
        add(findingsLabel);
        add(createSeparator());
        add(errorsLabel);
        add(createSeparator());
        add(suppressedLabel);
        add(diagnosticLabel);

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
            String relevant = metrics.getOrDefault("workflow_relevant_requests", "?");
            graphLabel.setText("Graph: " + nodes + "n/" + edges
                    + "e (relevant: " + relevant + ")");

            String candidates = metrics.getOrDefault("workflow_candidates", "?");
            String edgeSupp = metrics.getOrDefault("edge_supported_candidates", "?");
            String sessionOnly = metrics.getOrDefault("session_only_candidates", "?");
            candidatesLabel.setText("Candidates: " + candidates);
            // Append a short edge-by-type breakdown so the user can
            // see which edge types are present without a full settings
            // panel view. Format: "P/Rd/Rf/C/U" where P=PARAM_REUSE,
            // Rd=REDIRECT, Rf=REFERRER, C=RESPONSE_CORRELATION, U=USER_DEFINED.
            String p = metrics.getOrDefault("edges_by_type_PARAM_REUSE", "0");
            String rd = metrics.getOrDefault("edges_by_type_REDIRECT", "0");
            String rf = metrics.getOrDefault("edges_by_type_REFERRER", "0");
            String c = metrics.getOrDefault("edges_by_type_RESPONSE_CORRELATION", "0");
            String u = metrics.getOrDefault("edges_by_type_USER_DEFINED", "0");
            edgesBreakdownLabel.setText(" (edge: " + edgeSupp + ", session: " + sessionOnly
                    + ") [P:" + p + " Rd:" + rd + " Rf:" + rf + " C:" + c + " U:" + u + "]");

            String analyzed = metrics.getOrDefault("analyzed_chains", "?");
            String findings = metrics.getOrDefault("findings_count", "?");
            findingsLabel.setText("Findings: " + findings + "/" + analyzed);

            String llmErrors = metrics.getOrDefault("llm_errors", "0");
            String replayErrors = metrics.getOrDefault("replay_errors", "0");
            errorsLabel.setText("Errors: " + llmErrors + "L/" + replayErrors + "R");

            String suppressed = metrics.getOrDefault("suppressed_total", "?");
            suppressedLabel.setText("Suppressed: " + suppressed);

            // Diagnostic: zero edges with non-zero candidates usually
            // means edge building never ran. Surface it in red so it
            // is impossible to miss.
            String warning = metrics.getOrDefault("edges_no_candidate_warning", "0");
            boolean show = "1".equals(warning);
            diagnosticLabel.setVisible(show);
            if (show) {
                diagnosticLabel.setText(" \u26A0 edges=0 but candidates=" + candidates
                        + " — run Edge Rebuild");
            }

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

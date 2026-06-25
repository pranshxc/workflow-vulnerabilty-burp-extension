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
            String explicitEdges = metrics.getOrDefault("explicit_edges", "0");
            String derivedEdges = metrics.getOrDefault("derived_edges", "0");
            String relevant = metrics.getOrDefault("workflow_relevant_requests", "?");
            String storedReq = metrics.getOrDefault("stored_requests", "0");
            graphLabel.setText("Graph: " + nodes + "n/" + edges
                    + "e (explicit:" + explicitEdges + " derived:" + derivedEdges
                    + " rel:" + relevant + " stored:" + storedReq + ")");

            String candidates = metrics.getOrDefault("workflow_candidates", "?");
            String edgeSupp = metrics.getOrDefault("edge_supported_candidates", "?");
            String sessionOnly = metrics.getOrDefault("session_only_candidates", "?");
            String analysisReady = metrics.getOrDefault("analysis_ready_candidates", "?");
            String displayOnly = metrics.getOrDefault("display_only_candidates", "?");
            candidatesLabel.setText("Candidates: " + candidates);
            // Format: "(edge:N session:N) [P:N Rd:N Rf:N C:N U:N Wf:N] (ready:N display:N)"
            // Wf = WORKFLOW_SEQUENCE derived edges.
            String p = metrics.getOrDefault("edges_by_type_PARAM_REUSE", "0");
            String rd = metrics.getOrDefault("edges_by_type_REDIRECT", "0");
            String rf = metrics.getOrDefault("edges_by_type_REFERRER", "0");
            String c = metrics.getOrDefault("edges_by_type_RESPONSE_CORRELATION", "0");
            String u = metrics.getOrDefault("edges_by_type_USER_DEFINED", "0");
            String wf = metrics.getOrDefault("edges_by_type_WORKFLOW_SEQUENCE", "0");
            edgesBreakdownLabel.setText(" (edge: " + edgeSupp + ", session: " + sessionOnly
                    + ") [P:" + p + " Rd:" + rd + " Rf:" + rf + " C:" + c + " U:" + u
                    + " Wf:" + wf + "]"
                    + " (ready:" + analysisReady + " display:" + displayOnly + ")");

            String analyzed = metrics.getOrDefault("analyzed_chains", "?");
            String findings = metrics.getOrDefault("findings_count", "?");
            String confirmed = metrics.getOrDefault("confirmed_count", "0");
            String probable = metrics.getOrDefault("probable_count", "0");
            findingsLabel.setText("Findings: " + findings + " (conf:" + confirmed
                    + " prob:" + probable + ")/" + analyzed);

            String llmErrors = metrics.getOrDefault("llm_errors", "0");
            String replayErrors = metrics.getOrDefault("replay_errors", "0");
            errorsLabel.setText("Errors: " + llmErrors + "L/" + replayErrors + "R");

            String suppressed = metrics.getOrDefault("suppressed_total", "?");
            suppressedLabel.setText("Suppressed: " + suppressed);

            // Diagnostic: zero explicit edges with non-zero
            // candidates usually means the explicit edge
            // detection heuristics (referrer, param reuse,
            // cookie correlation) found nothing. Surface it in
            // red so it is impossible to miss. The warning now
            // reads "explicit=0 but candidates=N" so derived
            // WORKFLOW_SEQUENCE edges are not counted as
            // relationship evidence.
            String warning = metrics.getOrDefault("edges_no_candidate_warning", "0");
            boolean show = "1".equals(warning);
            diagnosticLabel.setVisible(show);
            if (show) {
                // Build a short breakdown of the edge-miss
                // diagnostics so the user sees *why* the explicit
                // edges are zero, not just *that* they are zero.
                String referrerP = metrics.getOrDefault("diag_referrer_present", "0");
                String referrerM = metrics.getOrDefault("diag_referrer_matched", "0");
                String paramC = metrics.getOrDefault("diag_param_values_checked", "0");
                String paramR = metrics.getOrDefault("diag_param_values_reused", "0");
                String cookieC = metrics.getOrDefault("diag_non_session_cookies_checked", "0");
                String cookieR = metrics.getOrDefault("diag_non_session_cookies_correlated", "0");
                String respIdx = metrics.getOrDefault("diag_response_values_indexed", "0");
                diagnosticLabel.setText(" \u26A0 explicit=0 but candidates=" + candidates
                        + " — Rf:" + referrerM + "/" + referrerP
                        + " P:" + paramR + "/" + paramC
                        + " C:" + cookieR + "/" + cookieC
                        + " RespIdx:" + respIdx);
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

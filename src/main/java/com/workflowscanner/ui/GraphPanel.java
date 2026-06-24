package com.workflowscanner.ui;

import burp.api.montoya.MontoyaApi;
import com.workflowscanner.analysis.AnalysisEngine;
import com.workflowscanner.analysis.ChainVerdict;
import com.workflowscanner.config.ExtensionConfig;
import com.workflowscanner.graph.EdgeType;
import com.workflowscanner.graph.RequestEdge;
import com.workflowscanner.graph.RequestGraph;
import com.workflowscanner.graph.RequestNode;
import com.workflowscanner.llm.LLMAnalysisResult;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;
import com.workflowscanner.workflow.WorkflowCandidate;
import com.workflowscanner.workflow.WorkflowDetector;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.DoubleSupplier;

/**
 * Graph visualization panel with chain explorer.
 * Three-pane layout: chain list | graph view | node detail.
 */
public class GraphPanel extends JPanel {

    private final MontoyaApi api;
    private final RequestGraph graph;
    private final AnalysisEngine analysisEngine;
    private final ExtensionLogger logger;

    // Workflow candidate display (added in workflow rework)
    private WorkflowDetector workflowDetector;
    private ExtensionConfig config;

    // Chain list (left)
    private DefaultListModel<ChainItem> chainListModel;
    private JList<ChainItem> chainList;
    private JComboBox<String> hostFilter;
    private JLabel chainCountLabel;

    // Graph view (right-top)
    private ChainGraphView graphView;

    // Node detail (right-bottom)
    private JTextArea nodeDetailArea;
    private JPanel nodeButtonPanel;
    private RequestNode selectedNode;
    private List<RequestNode> selectedChain;

    private Timer refreshTimer;

    public GraphPanel(MontoyaApi api, RequestGraph graph, AnalysisEngine analysisEngine,
                      ExtensionLogger logger) {
        this(api, graph, analysisEngine, logger, null, null);
    }

    public GraphPanel(MontoyaApi api, RequestGraph graph, AnalysisEngine analysisEngine,
                      ExtensionLogger logger,
                      WorkflowDetector workflowDetector, ExtensionConfig config) {
        this.api = api;
        this.graph = graph;
        this.analysisEngine = analysisEngine;
        this.logger = logger;
        this.workflowDetector = workflowDetector;
        this.config = config;

        setLayout(new BorderLayout());

        // Top bar
        add(createTopBar(), BorderLayout.NORTH);

        // Main split: left (chain list) | right (graph + detail)
        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplit.setDividerLocation(250);

        // Left: chain list
        mainSplit.setLeftComponent(createChainListPanel());

        // Right: graph view + node detail
        JSplitPane rightSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        rightSplit.setResizeWeight(0.65);

        graphView = new ChainGraphView();
        JScrollPane graphScroll = new JScrollPane(graphView);
        graphScroll.setBorder(BorderFactory.createTitledBorder("Chain Graph View"));
        rightSplit.setTopComponent(graphScroll);

        rightSplit.setBottomComponent(createNodeDetailPanel());

        mainSplit.setRightComponent(rightSplit);
        add(mainSplit, BorderLayout.CENTER);

        // Refresh timer
        refreshTimer = new Timer(3000, e -> refreshChainList());
        refreshTimer.start();

        refreshChainList();
    }

    // ========================================================================
    // Top Bar
    // ========================================================================

    private JPanel createTopBar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        bar.add(new JLabel("Host Filter:"));
        hostFilter = new JComboBox<>();
        hostFilter.addItem("All hosts");
        hostFilter.addActionListener(e -> refreshChainList());
        bar.add(hostFilter);

        chainCountLabel = new JLabel("Chains: 0");
        bar.add(chainCountLabel);

        JButton refreshBtn = new JButton("Refresh");
        refreshBtn.addActionListener(e -> refreshChainList());
        bar.add(refreshBtn);

        JLabel statsLabel = new JLabel();
        bar.add(statsLabel);

        return bar;
    }

    // ========================================================================
    // Chain List (Left Panel)
    // ========================================================================

    private JPanel createChainListPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Workflow Chains"));

        chainListModel = new DefaultListModel<>();
        chainList = new JList<>(chainListModel);
        chainList.setCellRenderer(new ChainListRenderer(() -> config != null ? config.getWorkflowScoreThreshold() : 20.0));
        chainList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        chainList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) onChainSelected();
        });

        panel.add(new JScrollPane(chainList), BorderLayout.CENTER);
        return panel;
    }

    // ========================================================================
    // Node Detail (Right-Bottom)
    // ========================================================================

    private JPanel createNodeDetailPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Node Detail"));

        nodeDetailArea = new JTextArea();
        nodeDetailArea.setEditable(false);
        nodeDetailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        nodeDetailArea.setLineWrap(true);
        nodeDetailArea.setWrapStyleWord(true);
        panel.add(new JScrollPane(nodeDetailArea), BorderLayout.CENTER);

        nodeButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 3));

        JButton viewReqBtn = new JButton("View Request");
        viewReqBtn.addActionListener(e -> viewRequest());
        nodeButtonPanel.add(viewReqBtn);

        JButton viewRespBtn = new JButton("View Response");
        viewRespBtn.addActionListener(e -> viewResponse());
        nodeButtonPanel.add(viewRespBtn);

        JButton analyzeBtn = new JButton("Analyze Node");
        analyzeBtn.addActionListener(e -> analyzeSelectedNode());
        nodeButtonPanel.add(analyzeBtn);

        JButton repeaterBtn = new JButton("Send to Repeater");
        repeaterBtn.addActionListener(e -> sendToRepeater());
        nodeButtonPanel.add(repeaterBtn);

        panel.add(nodeButtonPanel, BorderLayout.SOUTH);
        return panel;
    }

    /**
     * Set the workflow detector for candidate-based display.
     */
    public void setWorkflowDetector(WorkflowDetector detector) {
        this.workflowDetector = detector;
    }

    /**
     * Set the config (for threshold display).
     */
    public void setConfig(ExtensionConfig config) {
        this.config = config;
    }

    // ========================================================================
    // Data Refresh
    // ========================================================================

    private void refreshChainList() {
        double displayThreshold = config != null
                ? config.getWorkflowCandidateThreshold() : 10.0;

        // Get workflow candidates (if detector available) or fallback to connected components
        List<WorkflowCandidate> candidates;
        if (workflowDetector != null) {
            // Use last results if available (read-only, no side effects)
            List<WorkflowCandidate> lastResults = workflowDetector.getLastResults();
            if (!lastResults.isEmpty()) {
                candidates = lastResults;
            } else {
                // Preview candidates without scoring or side effects
                candidates = workflowDetector.previewCandidates(
                        new ArrayList<>(graph.getNodes().values()));
            }
            // Filter to display-worthy candidates only
            candidates = candidates.stream()
                    .filter(c -> c.getWorkflowScore() >= displayThreshold)
                    .toList();
        } else {
            // Fallback: show connected components as "chains"
            candidates = new ArrayList<>();
            for (List<RequestNode> component : graph.getConnectedComponents()) {
                WorkflowCandidate fallback = new WorkflowCandidate();
                for (RequestNode node : component) fallback.addStep(node);
                fallback.setWorkflowType(com.workflowscanner.workflow.WorkflowType.UNKNOWN_BUSINESS_FLOW);
                candidates.add(fallback);
            }
        }

        // Update host filter
        Set<String> hosts = graph != null ? graph.getAllHosts() : Set.of();
        String currentHost = (String) hostFilter.getSelectedItem();
        hostFilter.removeAllItems();
        hostFilter.addItem("All hosts");
        for (String host : hosts) hostFilter.addItem(host);
        if (currentHost != null) hostFilter.setSelectedItem(currentHost);

        // Filter by host
        String filterHost = (String) hostFilter.getSelectedItem();
        List<WorkflowCandidate> filtered = new ArrayList<>();
        for (WorkflowCandidate candidate : candidates) {
            if ("All hosts".equals(filterHost) || candidateContainsHost(candidate, filterHost)) {
                filtered.add(candidate);
            }
        }

        // Build chain items with verdict info
        chainListModel.clear();
        for (int i = 0; i < filtered.size(); i++) {
            WorkflowCandidate candidate = filtered.get(i);
            String fingerprint = ChainVerdict.generateFingerprint(candidate.getSteps());
            ChainVerdict verdict = analysisEngine != null
                    ? analysisEngine.getVerdictByFingerprint(fingerprint) : null;
            chainListModel.addElement(new ChainItem(i + 1, candidate, verdict));
        }

        chainCountLabel.setText("Candidates: " + filtered.size());
    }

    private boolean candidateContainsHost(WorkflowCandidate candidate, String host) {
        for (RequestNode node : candidate.getSteps()) {
            if (host != null && host.equalsIgnoreCase(node.getHost())) return true;
        }
        return false;
    }

    // ========================================================================
    // Selection Handlers
    // ========================================================================

    private void onChainSelected() {
        ChainItem item = chainList.getSelectedValue();
        if (item == null) return;

        selectedChain = item.candidate.getSteps();
        selectedNode = null;

        // Update graph view
        List<RequestEdge> chainEdges = new ArrayList<>();
        // Show both graph edges between steps AND supporting edges
        for (RequestNode node : selectedChain) {
            chainEdges.addAll(graph.getEdgesForNode(node.getId()));
        }
        chainEdges.addAll(item.candidate.getSupportingEdges());
        graphView.setChain(selectedChain, chainEdges, item.verdict);

        // Show candidate info in detail area
        StringBuilder sb = new StringBuilder();
        sb.append("Candidate: ").append(item.candidate.getId()).append("\n");
        sb.append("Score: ").append(String.format("%.1f", item.candidate.getWorkflowScore())).append("\n");
        sb.append("Type: ").append(item.candidate.getWorkflowType()).append("\n");
        sb.append("Steps: ").append(item.candidate.size()).append("\n");
        sb.append("Session: ").append(item.candidate.getSessionKey()).append("\n");
        sb.append("Supporting edges: ").append(item.candidate.getSupportingEdges().size()).append("\n\n");

        // Evidence summary
        String evidenceSummary = item.candidate.getEvidence().summarize();
        if (!evidenceSummary.isEmpty()) {
            sb.append("Evidence:\n").append(evidenceSummary).append("\n\n");
        }

        if (item.verdict != null) {
            sb.append("Analysis: ").append(item.verdict.getOverallVerdict()).append("\n");
        }
        sb.append("Select a node in the graph view above for details.");
        nodeDetailArea.setText(sb.toString());
    }

    private void onNodeSelected(RequestNode node) {
        this.selectedNode = node;
        if (node == null) {
            nodeDetailArea.setText("");
            return;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Node #").append(node.getNodeIndex()).append(": ");
        sb.append(node.getMethod()).append(" ").append(node.getUrl()).append("\n");
        sb.append("Status: ").append(node.getStatusCode()).append("\n\n");

        // Edges
        List<RequestEdge> edges = graph.getEdgesForNode(node.getId());
        if (!edges.isEmpty()) {
            sb.append("Edges:\n");
            for (RequestEdge edge : edges) {
                String dir = edge.getSourceNodeId().equals(node.getId()) ? "->" : "<-";
                String otherId = edge.getSourceNodeId().equals(node.getId())
                        ? edge.getTargetNodeId() : edge.getSourceNodeId();
                RequestNode other = graph.getNode(otherId);
                sb.append("  ").append(dir).append(" ");
                if (other != null) sb.append("Node#").append(other.getNodeIndex());
                sb.append(" [").append(edge.getType()).append(" ");
                sb.append(String.format("%.2f", edge.getConfidence())).append("]\n");
                if (edge.getEvidence() != null) {
                    sb.append("    ").append(edge.getEvidence()).append("\n");
                }
            }
            sb.append("\n");
        }

        // Parameters
        if (node.getExtractedParams() != null && !node.getExtractedParams().isEmpty()) {
            sb.append("Parameters:\n");
            for (Map.Entry<String, Object> entry : node.getExtractedParams().entrySet()) {
                String val = entry.getValue() != null ? entry.getValue().toString() : "";
                if (val.length() > 80) val = val.substring(0, 80) + "...";
                sb.append("  ").append(entry.getKey()).append(": ").append(val).append("\n");
            }
            sb.append("\n");
        }

        // Analysis verdict
        ChainItem item = chainList.getSelectedValue();
        if (item != null && item.verdict != null && item.verdict.getNodeResults() != null) {
            List<RequestNode> steps = item.candidate.getSteps();
            int idx = steps.indexOf(node);
            if (idx >= 0 && idx < item.verdict.getNodeResults().size()) {
                LLMAnalysisResult result = item.verdict.getNodeResults().get(idx);
                if (result != null) {
                    sb.append("Analysis: ").append(result.getVerdict());
                    sb.append(" (").append(String.format("%.0f%%", result.getConfidence() * 100)).append(")\n");
                    if (result.getReasoning() != null) {
                        sb.append(result.getReasoning()).append("\n");
                    }
                }
            }
        }

        nodeDetailArea.setText(sb.toString());
        nodeDetailArea.setCaretPosition(0);
    }

    // ========================================================================
    // Node Actions
    // ========================================================================

    private void viewRequest() {
        if (selectedNode == null || selectedNode.getRequest() == null) return;
        showTextDialog("Request - Node #" + selectedNode.getNodeIndex(),
                buildRequestText(selectedNode));
    }

    private void viewResponse() {
        if (selectedNode == null || selectedNode.getRequest() == null) return;
        showTextDialog("Response - Node #" + selectedNode.getNodeIndex(),
                buildResponseText(selectedNode));
    }

    private void analyzeSelectedNode() {
        ChainItem item = chainList.getSelectedValue();
        if (item == null || item.candidate == null) return;
        logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "GraphPanel",
                "User triggered analysis for workflow candidate " + item.candidate.getId());
        analysisEngine.analyzeCandidate(item.candidate, true);
    }

    private void sendToRepeater() {
        if (selectedNode == null || selectedNode.getRequest() == null) return;
        try {
            String url = selectedNode.getRequest().getUrl();
            String method = selectedNode.getRequest().getMethod();
            var httpReq = burp.api.montoya.http.message.requests.HttpRequest.httpRequest(url).withMethod(method);
            if (selectedNode.getRequest().getRequestBody() != null) {
                httpReq = httpReq.withBody(selectedNode.getRequest().getRequestBody());
            }
            api.repeater().sendToRepeater(httpReq, "WF-Node#" + selectedNode.getNodeIndex());
            logger.log(LogCategory.EXTENSION, LogLevel.INFO, "GraphPanel",
                    "Sent Node#" + selectedNode.getNodeIndex() + " to Repeater.");
        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "GraphPanel",
                    "Failed to send to Repeater.", e);
        }
    }

    private String buildRequestText(RequestNode node) {
        StringBuilder sb = new StringBuilder();
        sb.append(node.getMethod()).append(" ").append(node.getUrl()).append("\n\n");
        if (node.getRequest().getRequestHeaders() != null) {
            for (var entry : node.getRequest().getRequestHeaders().entrySet()) {
                for (String val : entry.getValue()) {
                    sb.append(entry.getKey()).append(": ").append(val).append("\n");
                }
            }
        }
        if (node.getRequest().getRequestBody() != null) {
            sb.append("\n").append(node.getRequest().getRequestBody());
        }
        return sb.toString();
    }

    private String buildResponseText(RequestNode node) {
        StringBuilder sb = new StringBuilder();
        sb.append("HTTP ").append(node.getStatusCode()).append("\n\n");
        if (node.getRequest().getResponseHeaders() != null) {
            for (var entry : node.getRequest().getResponseHeaders().entrySet()) {
                for (String val : entry.getValue()) {
                    sb.append(entry.getKey()).append(": ").append(val).append("\n");
                }
            }
        }
        if (node.getRequest().getResponseBody() != null) {
            sb.append("\n").append(node.getRequest().getResponseBody());
        }
        return sb.toString();
    }

    private void showTextDialog(String title, String text) {
        JTextArea area = new JTextArea(text);
        area.setEditable(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane scroll = new JScrollPane(area);
        scroll.setPreferredSize(new Dimension(700, 500));
        JOptionPane.showMessageDialog(this, scroll, title, JOptionPane.PLAIN_MESSAGE);
    }

    public void dispose() {
        if (refreshTimer != null) refreshTimer.stop();
    }

    // ========================================================================
    // Chain Graph View (Custom Painted)
    // ========================================================================

    private class ChainGraphView extends JPanel {
        private List<RequestNode> chain;
        private List<RequestEdge> edges;
        private ChainVerdict verdict;
        private final Map<String, Rectangle> nodeBounds = new HashMap<>();

        private static final int NODE_W = 220;
        private static final int NODE_H = 45;
        private static final int V_GAP = 60;
        private static final int H_PAD = 40;
        private static final int V_PAD = 30;

        ChainGraphView() {
            setBackground(Color.WHITE);
            addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    for (var entry : nodeBounds.entrySet()) {
                        if (entry.getValue().contains(e.getPoint())) {
                            RequestNode node = graph.getNode(entry.getKey());
                            if (node != null) onNodeSelected(node);
                            repaint();
                            return;
                        }
                    }
                }
            });
        }

        void setChain(List<RequestNode> chain, List<RequestEdge> edges, ChainVerdict verdict) {
            this.chain = chain;
            this.edges = edges;
            this.verdict = verdict;
            nodeBounds.clear();

            int height = chain != null ? V_PAD * 2 + chain.size() * (NODE_H + V_GAP) : 200;
            setPreferredSize(new Dimension(NODE_W + H_PAD * 2, height));
            revalidate();
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            if (chain == null || chain.isEmpty()) {
                g.setColor(Color.GRAY);
                g.drawString("Select a chain from the list", 20, 30);
                return;
            }

            Graphics2D g2 = (Graphics2D) g;
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            nodeBounds.clear();

            // Draw edges first (behind nodes)
            for (int i = 0; i < chain.size() - 1; i++) {
                RequestNode from = chain.get(i);
                RequestNode to = chain.get(i + 1);
                int x1 = H_PAD + NODE_W / 2;
                int y1 = V_PAD + i * (NODE_H + V_GAP) + NODE_H;
                int y2 = V_PAD + (i + 1) * (NODE_H + V_GAP);

                // Find edge between these nodes
                RequestEdge edge = findEdge(from.getId(), to.getId());
                Color edgeColor = edge != null ? getEdgeColor(edge.getType()) : Color.LIGHT_GRAY;
                g2.setColor(edgeColor);
                g2.setStroke(new BasicStroke(2));
                g2.drawLine(x1, y1, x1, y2);

                // Arrow head
                int[] xPoints = {x1 - 5, x1 + 5, x1};
                int[] yPoints = {y2 - 8, y2 - 8, y2};
                g2.fillPolygon(xPoints, yPoints, 3);

                // Edge label
                if (edge != null) {
                    g2.setFont(g2.getFont().deriveFont(Font.PLAIN, 10f));
                    String label = edge.getType().name() + " (" + String.format("%.1f", edge.getConfidence()) + ")";
                    g2.drawString(label, x1 + 10, (y1 + y2) / 2 + 4);
                }
            }

            // Draw nodes
            g2.setStroke(new BasicStroke(1));
            for (int i = 0; i < chain.size(); i++) {
                RequestNode node = chain.get(i);
                int x = H_PAD;
                int y = V_PAD + i * (NODE_H + V_GAP);

                Rectangle bounds = new Rectangle(x, y, NODE_W, NODE_H);
                nodeBounds.put(node.getId(), bounds);

                // Node color based on verdict
                Color fillColor = getNodeColor(node, i);
                g2.setColor(fillColor);
                g2.fillRoundRect(x, y, NODE_W, NODE_H, 10, 10);

                // Border
                boolean isSelected = selectedNode != null && selectedNode.getId().equals(node.getId());
                g2.setColor(isSelected ? Color.BLUE : Color.DARK_GRAY);
                g2.setStroke(new BasicStroke(isSelected ? 3 : 1));
                g2.drawRoundRect(x, y, NODE_W, NODE_H, 10, 10);

                // Text
                g2.setColor(Color.BLACK);
                g2.setFont(g2.getFont().deriveFont(Font.BOLD, 12f));
                String methodPath = (node.getMethod() != null ? node.getMethod() : "?") + " "
                        + (node.getPath() != null ? truncate(node.getPath(), 25) : "/");
                g2.drawString(methodPath, x + 8, y + 18);

                g2.setFont(g2.getFont().deriveFont(Font.PLAIN, 11f));
                g2.setColor(Color.DARK_GRAY);
                g2.drawString("-> " + node.getStatusCode() + "  [Node #" + node.getNodeIndex() + "]",
                        x + 8, y + 35);

                g2.setStroke(new BasicStroke(1));
            }
        }

        private Color getNodeColor(RequestNode node, int chainIndex) {
            if (verdict != null && verdict.getNodeResults() != null
                    && chainIndex < verdict.getNodeResults().size()) {
                LLMAnalysisResult result = verdict.getNodeResults().get(chainIndex);
                if (result != null) {
                    if (result.isVulnerable()) return new Color(255, 200, 200);
                    if (result.isSuspicious()) return new Color(255, 240, 200);
                    return new Color(200, 255, 200);
                }
            }
            return new Color(230, 230, 230); // Not analyzed
        }

        private Color getEdgeColor(EdgeType type) {
            switch (type) {
                case REDIRECT: return Color.BLUE;
                case REFERRER: return new Color(0, 150, 0);
                case PARAM_REUSE: return new Color(220, 140, 0);
                case RESPONSE_CORRELATION: return new Color(150, 0, 200);
                case TIME_WINDOW: return Color.GRAY;
                case USER_DEFINED: return Color.CYAN;
                default: return Color.LIGHT_GRAY;
            }
        }

        private RequestEdge findEdge(String fromId, String toId) {
            if (edges == null) return null;
            for (RequestEdge edge : edges) {
                if ((edge.getSourceNodeId().equals(fromId) && edge.getTargetNodeId().equals(toId))
                        || (edge.getSourceNodeId().equals(toId) && edge.getTargetNodeId().equals(fromId))) {
                    return edge;
                }
            }
            return null;
        }

        private String truncate(String s, int max) {
            return s.length() <= max ? s : s.substring(0, max) + "...";
        }
    }

    // ========================================================================
    // Chain List Item & Renderer
    // ========================================================================

    private static class ChainItem {
        final int index;
        final WorkflowCandidate candidate;
        final ChainVerdict verdict;

        ChainItem(int index, WorkflowCandidate candidate, ChainVerdict verdict) {
            this.index = index;
            this.candidate = candidate;
            this.verdict = verdict;
        }

        String getStatusIcon(double threshold) {
            if (verdict == null) {
                if (candidate.getWorkflowScore() >= threshold) return "\u25B6"; // play
                return "\u25CB"; // empty circle
            }
            if (verdict.isVulnerable()) return "\u2605"; // star
            if (verdict.isSuspicious()) return "\u26A0"; // warning
            return "\u2713"; // checkmark
        }

        Color getStatusColor(double threshold) {
            if (verdict == null) {
                if (candidate.getWorkflowScore() >= threshold) return new Color(0, 100, 200); // blue for analysis-ready
                return Color.GRAY;
            }
            if (verdict.isVulnerable()) return Color.RED;
            if (verdict.isSuspicious()) return new Color(200, 150, 0);
            return new Color(0, 128, 0);
        }

        String getStatusText() {
            if (verdict == null) return "Not analyzed";
            return verdict.getOverallVerdict();
        }
    }

    private static class ChainListRenderer extends DefaultListCellRenderer {
        private final DoubleSupplier thresholdSupplier;

        ChainListRenderer(DoubleSupplier thresholdSupplier) {
            this.thresholdSupplier = thresholdSupplier;
        }

        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value,
                                                       int index, boolean isSelected, boolean cellHasFocus) {
            super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            if (value instanceof ChainItem) {
                ChainItem item = (ChainItem) value;
                double threshold = thresholdSupplier.getAsDouble();
                String host = item.candidate.getSteps().isEmpty()
                        ? "?" : item.candidate.getSteps().get(0).getHost();
                setText(String.format("%s [%.0f] %s %s (%d) - %s",
                        item.getStatusIcon(threshold),
                        item.candidate.getWorkflowScore(),
                        item.candidate.getWorkflowType().name().substring(0, Math.min(4,
                                item.candidate.getWorkflowType().name().length())),
                        item.candidate.getId(),
                        item.candidate.size(),
                        host));
                if (!isSelected) {
                    setForeground(item.getStatusColor(threshold));
                }
            }
            return this;
        }
    }
}

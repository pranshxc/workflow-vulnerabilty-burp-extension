package com.workflowscanner.ui;

import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogEntry;
import com.workflowscanner.logging.LogLevel;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Real-time, filterable, searchable log viewer panel.
 * Displays log entries from ExtensionLogger with category/level/text filtering,
 * auto-scroll, detail view, and export.
 */
public class LogPanel extends JPanel {

    private final ExtensionLogger logger;

    // Table
    private JTable logTable;
    private LogTableModel tableModel;

    // Detail
    private JTextArea detailArea;

    // Filters
    private final java.util.Map<LogCategory, JCheckBox> categoryChecks = new java.util.LinkedHashMap<>();
    private JRadioButton levelAll, levelInfo, levelWarn, levelError;
    private JTextField searchField;
    private JLabel filterCountLabel;

    // Controls
    private JCheckBox autoScrollCheck;
    private final AtomicBoolean needsRefresh = new AtomicBoolean(false);
    private Timer refreshTimer;

    public LogPanel(ExtensionLogger logger) {
        this.logger = logger;
        setLayout(new BorderLayout());

        // Top: filter bar
        add(createFilterBar(), BorderLayout.NORTH);

        // Center: split pane (table + detail)
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(0.7);

        // Log table
        tableModel = new LogTableModel();
        logTable = new JTable(tableModel);
        logTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        logTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        logTable.getColumnModel().getColumn(0).setPreferredWidth(140); // Timestamp
        logTable.getColumnModel().getColumn(1).setPreferredWidth(80);  // Category
        logTable.getColumnModel().getColumn(2).setPreferredWidth(50);  // Level
        logTable.getColumnModel().getColumn(3).setPreferredWidth(600); // Message
        logTable.setDefaultRenderer(Object.class, new LogCellRenderer());
        logTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) showSelectedDetail();
        });

        JScrollPane tableScroll = new JScrollPane(logTable);
        splitPane.setTopComponent(tableScroll);

        // Detail pane
        JPanel detailPanel = new JPanel(new BorderLayout());
        detailPanel.setBorder(BorderFactory.createTitledBorder("Detail View"));
        detailArea = new JTextArea();
        detailArea.setEditable(false);
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        detailArea.setLineWrap(true);
        detailArea.setWrapStyleWord(true);
        detailPanel.add(new JScrollPane(detailArea), BorderLayout.CENTER);

        JPanel detailBtnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton copyBtn = new JButton("Copy to Clipboard");
        copyBtn.addActionListener(e -> copyDetailToClipboard());
        detailBtnPanel.add(copyBtn);
        detailPanel.add(detailBtnPanel, BorderLayout.SOUTH);

        splitPane.setBottomComponent(detailPanel);
        add(splitPane, BorderLayout.CENTER);

        // Register live listener
        logger.addListener(entry -> needsRefresh.set(true));

        // Refresh timer (500ms)
        refreshTimer = new Timer(500, e -> {
            if (needsRefresh.getAndSet(false)) {
                refreshTable();
            }
        });
        refreshTimer.start();

        // Initial load
        refreshTable();
    }

    // ========================================================================
    // Filter Bar
    // ========================================================================

    private JPanel createFilterBar() {
        JPanel bar = new JPanel();
        bar.setLayout(new BoxLayout(bar, BoxLayout.Y_AXIS));
        bar.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Row 1: Category checkboxes
        JPanel catRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 3, 2));
        catRow.add(new JLabel("Filters: "));
        for (LogCategory cat : LogCategory.values()) {
            JCheckBox cb = new JCheckBox(cat.getShortName(), true);
            cb.setToolTipText(cat.getDescription());
            cb.addActionListener(e -> refreshTable());
            categoryChecks.put(cat, cb);
            catRow.add(cb);
        }
        bar.add(catRow);

        // Row 2: Level + Search + Controls
        JPanel controlRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));

        controlRow.add(new JLabel("Level: "));
        levelAll = new JRadioButton("ALL", true);
        levelInfo = new JRadioButton("INFO+");
        levelWarn = new JRadioButton("WARN+");
        levelError = new JRadioButton("ERROR");
        ButtonGroup levelGroup = new ButtonGroup();
        levelGroup.add(levelAll);
        levelGroup.add(levelInfo);
        levelGroup.add(levelWarn);
        levelGroup.add(levelError);
        levelAll.addActionListener(e -> refreshTable());
        levelInfo.addActionListener(e -> refreshTable());
        levelWarn.addActionListener(e -> refreshTable());
        levelError.addActionListener(e -> refreshTable());
        controlRow.add(levelAll);
        controlRow.add(levelInfo);
        controlRow.add(levelWarn);
        controlRow.add(levelError);

        controlRow.add(Box.createHorizontalStrut(15));
        controlRow.add(new JLabel("Search: "));
        searchField = new JTextField(20);
        searchField.addActionListener(e -> refreshTable());
        // Also refresh on each keystroke with a small delay
        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { needsRefresh.set(true); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { needsRefresh.set(true); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { needsRefresh.set(true); }
        });
        controlRow.add(searchField);

        controlRow.add(Box.createHorizontalStrut(15));
        autoScrollCheck = new JCheckBox("Auto-scroll", true);
        controlRow.add(autoScrollCheck);

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> { logger.clear(); refreshTable(); });
        controlRow.add(clearBtn);

        JButton exportBtn = new JButton("Export...");
        exportBtn.addActionListener(e -> exportLogs());
        controlRow.add(exportBtn);

        controlRow.add(Box.createHorizontalStrut(10));
        filterCountLabel = new JLabel(" ");
        controlRow.add(filterCountLabel);

        bar.add(controlRow);
        return bar;
    }

    // ========================================================================
    // Table Refresh
    // ========================================================================

    private void refreshTable() {
        Set<LogCategory> categories = getSelectedCategories();
        LogLevel minLevel = getSelectedLevel();
        String search = searchField != null ? searchField.getText().trim() : "";
        if (search.isEmpty()) search = null;

        List<LogEntry> entries = logger.getEntries(categories, minLevel, search, 0, 0);
        int totalCount = logger.getEntryCount();

        final List<LogEntry> snapshot = new ArrayList<>(entries);
        final int total = totalCount;
        final int filtered = snapshot.size();

        SwingUtilities.invokeLater(() -> {
            tableModel.setEntries(snapshot);
            filterCountLabel.setText("Showing " + filtered + " of " + total + " entries");

            // Auto-scroll to bottom
            if (autoScrollCheck.isSelected() && logTable.getRowCount() > 0) {
                int lastRow = logTable.getRowCount() - 1;
                logTable.scrollRectToVisible(logTable.getCellRect(lastRow, 0, true));
            }
        });
    }

    private Set<LogCategory> getSelectedCategories() {
        Set<LogCategory> selected = EnumSet.noneOf(LogCategory.class);
        for (var entry : categoryChecks.entrySet()) {
            if (entry.getValue().isSelected()) {
                selected.add(entry.getKey());
            }
        }
        return selected.isEmpty() ? null : selected; // null = all
    }

    private LogLevel getSelectedLevel() {
        if (levelError.isSelected()) return LogLevel.ERROR;
        if (levelWarn.isSelected()) return LogLevel.WARN;
        if (levelInfo.isSelected()) return LogLevel.INFO;
        return null; // ALL
    }

    // ========================================================================
    // Detail View
    // ========================================================================

    private void showSelectedDetail() {
        int row = logTable.getSelectedRow();
        if (row < 0 || row >= tableModel.getRowCount()) {
            detailArea.setText("");
            return;
        }
        LogEntry entry = tableModel.getEntryAt(row);
        if (entry == null) {
            detailArea.setText("");
            return;
        }
        detailArea.setText(entry.toString());
        detailArea.setCaretPosition(0);
    }

    private void copyDetailToClipboard() {
        String text = detailArea.getText();
        if (text != null && !text.isEmpty()) {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(text), null);
        }
    }

    // ========================================================================
    // Export
    // ========================================================================

    private void exportLogs() {
        String[] options = {"Plain Text (.txt)", "JSON (.json)", "Cancel"};
        int choice = JOptionPane.showOptionDialog(this,
                "Select export format:", "Export Logs",
                JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE,
                null, options, options[0]);

        if (choice == 2 || choice == JOptionPane.CLOSED_OPTION) return;

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File(choice == 0
                ? "workflow-scanner-logs.txt" : "workflow-scanner-logs.json"));

        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;

        File file = chooser.getSelectedFile();
        Set<LogCategory> categories = getSelectedCategories();
        LogLevel minLevel = getSelectedLevel();
        String search = searchField.getText().trim();
        if (search.isEmpty()) search = null;

        try {
            int count;
            if (choice == 0) {
                count = logger.exportToFile(file.getAbsolutePath(), categories, minLevel, search);
            } else {
                count = logger.exportToJsonFile(file.getAbsolutePath(), categories, minLevel, search);
            }
            JOptionPane.showMessageDialog(this,
                    "Exported " + count + " entries to " + file.getName(),
                    "Export Complete", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                    "Export failed: " + e.getMessage(),
                    "Export Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    // ========================================================================
    // Cleanup
    // ========================================================================

    public void dispose() {
        if (refreshTimer != null) refreshTimer.stop();
    }

    // ========================================================================
    // Table Model
    // ========================================================================

    private static class LogTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = {"Timestamp", "Category", "Level", "Message"};
        private List<LogEntry> entries = new ArrayList<>();

        void setEntries(List<LogEntry> newEntries) {
            this.entries = newEntries;
            fireTableDataChanged();
        }

        LogEntry getEntryAt(int row) {
            return row >= 0 && row < entries.size() ? entries.get(row) : null;
        }

        @Override public int getRowCount() { return entries.size(); }
        @Override public int getColumnCount() { return COLUMNS.length; }
        @Override public String getColumnName(int col) { return COLUMNS[col]; }

        @Override
        public Object getValueAt(int row, int col) {
            if (row >= entries.size()) return "";
            LogEntry entry = entries.get(row);
            switch (col) {
                case 0: return entry.getFormattedTimestamp();
                case 1: return entry.getCategory().getShortName();
                case 2: return entry.getLevel().name();
                case 3: return entry.getMessage();
                default: return "";
            }
        }
    }

    // ========================================================================
    // Cell Renderer (color-coded by level)
    // ========================================================================

    private static class LogCellRenderer extends DefaultTableCellRenderer {
        private static final Color DEBUG_COLOR = Color.GRAY;
        private static final Color WARN_COLOR = new Color(200, 150, 0);
        private static final Color ERROR_COLOR = new Color(200, 0, 0);

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            Component c = super.getTableCellRendererComponent(
                    table, value, isSelected, hasFocus, row, column);

            if (!isSelected) {
                String level = (String) table.getModel().getValueAt(row, 2);
                switch (level) {
                    case "DEBUG": c.setForeground(DEBUG_COLOR); break;
                    case "WARN":  c.setForeground(WARN_COLOR); break;
                    case "ERROR": c.setForeground(ERROR_COLOR); break;
                    default:      c.setForeground(table.getForeground()); break;
                }
            }
            return c;
        }
    }
}

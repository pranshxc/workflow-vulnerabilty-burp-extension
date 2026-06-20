package com.workflowscanner.data;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import com.workflowscanner.config.ExtensionConfig;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Provides context menu items for sending requests to the Workflow Scanner.
 * Available in Proxy History, Repeater, and Target Site Map.
 *
 * Features:
 * - "Send to Workflow Scanner" for single or multiple selected requests
 * - Multiple selections are grouped as a potential workflow chain
 * - Scope filter applied uniformly
 * - All actions logged
 */
public class ContextMenuProvider implements ContextMenuItemsProvider {

    private final RequestPipeline pipeline;
    private final ScopeFilter scopeFilter;
    private final ExtensionLogger logger;

    public ContextMenuProvider(RequestPipeline pipeline, ExtensionConfig config, ExtensionLogger logger) {
        this.pipeline = pipeline;
        this.scopeFilter = new ScopeFilter(config);
        this.logger = logger;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        List<HttpRequestResponse> selectedItems = event.selectedRequestResponses();
        if (selectedItems == null || selectedItems.isEmpty()) {
            return menuItems;
        }

        int count = selectedItems.size();
        String label = count == 1
                ? "Send to Workflow Scanner"
                : "Send " + count + " requests to Workflow Scanner";

        JMenuItem sendToScanner = new JMenuItem(label);
        sendToScanner.addActionListener(e -> {
            // Run on a background thread to avoid blocking the UI
            new Thread(() -> processSelectedRequests(selectedItems), "WorkflowScanner-ContextMenu").start();
        });

        menuItems.add(sendToScanner);
        return menuItems;
    }

    /**
     * Process selected requests from the context menu.
     * Multiple selections are treated as a group (potential workflow chain).
     */
    private void processSelectedRequests(List<HttpRequestResponse> selectedItems) {
        int count = selectedItems.size();
        String groupId = count > 1 ? UUID.randomUUID().toString() : null;

        logger.log(LogCategory.EXTENSION, LogLevel.INFO, "ContextMenu",
                "User sent " + count + " request(s) to Workflow Scanner."
                        + (groupId != null ? " Group ID: " + groupId : ""));

        int submitted = 0;
        int filtered = 0;

        for (HttpRequestResponse item : selectedItems) {
            try {
                CapturedRequest captured = RequestConverter.fromRequestResponse(
                        item.request(), item.response(), CapturedRequest.Source.CONTEXT_MENU);

                // Apply scope filter
                if (!scopeFilter.isInScope(captured.getHost())) {
                    filtered++;
                    logger.log(LogCategory.EXTENSION, LogLevel.DEBUG, "ContextMenu",
                            "Out of scope, skipped: " + captured.getMethod() + " " + captured.getUrl());
                    continue;
                }

                captured.setInScope(true);

                // Set group ID for multi-select (marks them as a user-defined chain)
                if (groupId != null) {
                    captured.setGroupId(groupId);
                }

                boolean added = pipeline.submit(captured);
                if (added) {
                    submitted++;
                }
            } catch (Exception e) {
                logger.log(LogCategory.ERROR, LogLevel.ERROR, "ContextMenu",
                        "Error processing context menu request.", e);
            }
        }

        logger.log(LogCategory.EXTENSION, LogLevel.INFO, "ContextMenu",
                "Context menu processing complete. Submitted: " + submitted
                        + ", Filtered (scope): " + filtered
                        + ", Total selected: " + count);
    }
}

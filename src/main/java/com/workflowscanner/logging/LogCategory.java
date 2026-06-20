package com.workflowscanner.logging;

/**
 * Log categories for the extension's logging subsystem.
 * Each log entry is categorized for filtering and display.
 *
 * Categories:
 * - LLM_REQUEST:  Outbound LLM API call (full prompt, model, parameters)
 * - LLM_RESPONSE: Inbound LLM response (full response body, tokens used, latency)
 * - BACKFILL:     Proxy history backfill progress (count, scope, duration)
 * - GRAPH:        Graph building events (node added, edge created, merge, etc.)
 * - ANALYSIS:     Analysis pipeline events (node selected, verdict, reasoning)
 * - ADVISORY:     Burp issue creation/update events
 * - CONFIG:       Configuration changes
 * - ERROR:        Errors and exceptions with full stack traces
 * - EXTENSION:    Lifecycle events (init, shutdown, subsystem status)
 */
public enum LogCategory {
    LLM_REQUEST("LLM_REQ",   "LLM Request",  "Outbound LLM API calls"),
    LLM_RESPONSE("LLM_RES",  "LLM Response", "Inbound LLM responses"),
    BACKFILL("BACKFILL",     "Backfill",     "Proxy history backfill events"),
    GRAPH("GRAPH",           "Graph",        "Graph building events"),
    ANALYSIS("ANALYSIS",     "Analysis",     "Analysis pipeline events"),
    ADVISORY("ADVISORY",     "Advisory",     "Burp issue creation/update"),
    CONFIG("CONFIG",         "Config",       "Configuration changes"),
    ERROR("ERROR",           "Error",        "Errors and exceptions"),
    EXTENSION("EXTENSION",   "Extension",    "Lifecycle events");

    private final String shortName;
    private final String displayName;
    private final String description;

    LogCategory(String shortName, String displayName, String description) {
        this.shortName = shortName;
        this.displayName = displayName;
        this.description = description;
    }

    public String getShortName() { return shortName; }
    public String getDisplayName() { return displayName; }
    public String getDescription() { return description; }
}

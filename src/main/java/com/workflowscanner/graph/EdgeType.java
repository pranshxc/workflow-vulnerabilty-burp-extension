package com.workflowscanner.graph;

/**
 * Types of relationships between request nodes in the graph.
 */
public enum EdgeType {
    REDIRECT,              // HTTP 3xx redirect chain
    REFERRER,              // Referer header points to source
    TIME_WINDOW,           // Requests within configurable time window
    PARAM_REUSE,           // Parameter value from response appears in next request
    RESPONSE_CORRELATION,  // Response body data used in subsequent request
    USER_DEFINED           // Manually grouped by user via context menu
}

package com.workflowscanner.graph;

import java.util.Set;

/**
 * Types of relationships between request nodes in the graph.
 *
 * <p><b>Explicit vs derived edges (status-clarity rework):</b>
 * <ul>
 *   <li>Explicit edges ({@link #REDIRECT}, {@link #REFERRER},
 *       {@link #PARAM_REUSE}, {@link #RESPONSE_CORRELATION},
 *       {@link #USER_DEFINED}) are produced by RelationshipDetector
 *       from observable HTTP-level signals: redirect headers,
 *       referer headers, response value reuse, cookie correlation,
 *       and user manual grouping.</li>
 *   <li>Derived edges ({@link #WORKFLOW_SEQUENCE}) are produced by
 *       WorkflowDetector after a candidate has been finalized: they
 *       connect consecutive steps in the candidate so the graph
 *       reflects workflow structure even when no explicit edges
 *       were found. Derived edges are useful for the graph
 *       visualisation and chain reconstruction but are not treated
 *       as strong object-flow evidence by the scorer.</li>
 * </ul>
 *
 * <p>{@link #TIME_WINDOW} is kept for legacy code paths and
 * counters but is intentionally not produced by
 * RelationshipDetector — it caused noisy fake chains and is now
 * context-only.
 *
 * <p><b>P0-QUALITY-GATE:</b> {@link #TIME_WINDOW} is now also
 * filtered on graph load (see {@code GraphBuilder.loadFromDirectory})
 * and on live edge creation. A previous audit found 18,303
 * TIME_WINDOW edges in a large backfilled dataset, dominating
 * 72% of all edges and contributing zero workflow signal.
 * They are kept in the enum for backward compatibility with
 * old export files but are never created or counted.
 */
public enum EdgeType {
    REDIRECT,              // HTTP 3xx redirect chain
    REFERRER,              // Referer header points to source
    TIME_WINDOW,           // Requests within configurable time window (DEPRECATED: never emitted, dropped on load)
    PARAM_REUSE,           // Parameter value from response appears in next request
    RESPONSE_CORRELATION,  // Response body data used in subsequent request
    USER_DEFINED,          // Manually grouped by user via context menu
    WORKFLOW_SEQUENCE      // Derived edge between consecutive steps in a workflow candidate
    ;

    /**
     * Explicit edge types — produced by RelationshipDetector from
     * observable HTTP-level signals. Status panels use this set to
     * separate the "real" relationship count from derived/structural
     * edges like {@link #WORKFLOW_SEQUENCE}.
     */
    public static final Set<EdgeType> EXPLICIT = Set.of(
            REDIRECT, REFERRER, PARAM_REUSE, RESPONSE_CORRELATION, USER_DEFINED);

    /**
     * Derived edge types — produced by WorkflowDetector after a
     * candidate has been finalized. Useful for graph structure
     * and chain reconstruction; not strong exploit evidence.
     */
    public static final Set<EdgeType> DERIVED = Set.of(WORKFLOW_SEQUENCE);

    /**
     * Returns true if this edge type is "explicit" — produced by
     * the RelationshipDetector from HTTP-level signals.
     */
    public boolean isExplicit() {
        return EXPLICIT.contains(this);
    }

    /**
     * Returns true if this edge type is "derived" — produced by the
     * WorkflowDetector to represent workflow structure.
     */
    public boolean isDerived() {
        return DERIVED.contains(this);
    }
}

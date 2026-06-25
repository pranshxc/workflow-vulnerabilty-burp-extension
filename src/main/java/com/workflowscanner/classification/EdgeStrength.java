package com.workflowscanner.classification;

/**
 * Categorizes the strength of a relationship edge between two request nodes.
 * Used by WorkflowDetector to decide which edges participate in workflow chain formation.
 *
 * STRONG edges are sufficient to form a workflow chain by themselves.
 * MEDIUM edges contribute but need corroboration.
 * WEAK edges are not sufficient alone.
 * CONTEXT_ONLY edges should never create workflow chains — they provide informational context only.
 *
 * <p><b>Workflow-sequence edges:</b> The {@code WORKFLOW_SEQUENCE} edge
 * type (added in the status-clarity rework) is produced by
 * WorkflowDetector to connect consecutive steps in a candidate. It
 * is always treated as WEAK by {@code RelationshipDetector.getEdgeStrength}
 * because it is structural, not object-flow evidence — it is a
 * derived edge, not an explicit relationship.
 */
public enum EdgeStrength {
    STRONG,       // redirect, user-defined, business-token value flow
    MEDIUM,       // referrer to business endpoint, object-ID reuse, response-to-request param
    WEAK,         // same-host time proximity, referrer to static/telemetry, derived workflow-sequence edges
    CONTEXT_ONLY  // session cookie propagation, telemetry dependency, static asset dependency
}

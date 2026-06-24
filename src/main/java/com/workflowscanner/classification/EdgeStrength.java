package com.workflowscanner.classification;

/**
 * Categorizes the strength of a relationship edge between two request nodes.
 * Used by WorkflowDetector to decide which edges participate in workflow chain formation.
 *
 * STRONG edges are sufficient to form a workflow chain by themselves.
 * MEDIUM edges contribute but need corroboration.
 * WEAK edges are not sufficient alone.
 * CONTEXT_ONLY edges should never create workflow chains — they provide informational context only.
 */
public enum EdgeStrength {
    STRONG,       // redirect, user-defined, business-token value flow
    MEDIUM,       // referrer to business endpoint, object-ID reuse, response-to-request param
    WEAK,         // same-host time proximity, referrer to static/telemetry
    CONTEXT_ONLY  // session cookie propagation, telemetry dependency, static asset dependency
}

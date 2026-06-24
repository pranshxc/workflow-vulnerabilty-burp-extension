package com.workflowscanner.classification;

/**
 * Classifies the intent of a captured HTTP request.
 * Used by RequestClassifier to determine if a request should become a graph node,
 * be dropped as noise, or be downweighted.
 */
public enum RequestIntent {
    /** State-changing business operation (POST/PUT/PATCH/DELETE with business keywords) */
    BUSINESS_ACTION,
    /** Read-only business API call (GET with business path, JSON response) */
    BUSINESS_READ,
    /** Authentication-related (login, logout, MFA, token refresh, registration) */
    AUTHENTICATION,
    /** Workflow state transition (form submission, verification step, confirmation) */
    WORKFLOW_STATE,
    /** Static file asset (CSS, images, fonts, etc.) */
    STATIC_ASSET,
    /** Background polling (notifications, heartbeat, status, polling endpoints) */
    BACKGROUND_POLLING,
    /** Analytics, telemetry, metrics beacons */
    TELEMETRY_ANALYTICS,
    /** Third-party domain requests */
    THIRD_PARTY,
    /** CORS preflight OPTIONS request */
    PREFLIGHT,
    /** Health check or monitoring endpoint */
    HEALTHCHECK,
    /** Authentication context read (e.g. /api/me, /api/user) — not a workflow step,
     *  but retained for ApplicationModel context */
    CONTEXT_READ,
    /** Cannot determine intent confidently */
    UNKNOWN
}

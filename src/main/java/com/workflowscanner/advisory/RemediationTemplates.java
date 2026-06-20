package com.workflowscanner.advisory;

/**
 * Per-vulnerability-type remediation guidance.
 * Returns specific, actionable remediation text.
 */
public class RemediationTemplates {

    public static String getRemediation(String vulnerabilityType) {
        if (vulnerabilityType == null) return getGenericRemediation();

        switch (vulnerabilityType) {
            case "step_skipping":
                return "<h4>Remediation: Step Skipping</h4>\n"
                        + "<p>Implement server-side state validation at each workflow step. "
                        + "Each step should verify that all prerequisite steps were completed "
                        + "in the current session before proceeding.</p>\n"
                        + "<ul>\n"
                        + "<li>Use server-side session state to track workflow progress</li>\n"
                        + "<li>Validate step completion tokens that cannot be forged by the client</li>\n"
                        + "<li>Re-validate all business rules at each step, not just the first</li>\n"
                        + "<li>Reject requests that arrive out of sequence</li>\n"
                        + "</ul>";

            case "value_manipulation":
                return "<h4>Remediation: Value Manipulation</h4>\n"
                        + "<p>Never trust client-submitted values for security-critical data. "
                        + "Re-validate and re-calculate all values server-side at each step.</p>\n"
                        + "<ul>\n"
                        + "<li>Store prices, totals, and quantities in server-side session state</li>\n"
                        + "<li>Re-calculate totals from server-side data at payment/confirmation steps</li>\n"
                        + "<li>Use signed tokens for values that must pass through the client</li>\n"
                        + "<li>Validate that submitted values match server-side expectations</li>\n"
                        + "</ul>";

            case "race_condition":
                return "<h4>Remediation: Race Condition</h4>\n"
                        + "<p>Implement proper concurrency controls to prevent "
                        + "time-of-check-to-time-of-use (TOCTOU) vulnerabilities.</p>\n"
                        + "<ul>\n"
                        + "<li>Use database-level locking (SELECT FOR UPDATE) for critical operations</li>\n"
                        + "<li>Implement optimistic concurrency control with version numbers</li>\n"
                        + "<li>Use idempotency keys for one-time operations</li>\n"
                        + "<li>Apply rate limiting to prevent rapid concurrent requests</li>\n"
                        + "</ul>";

            case "replay_attack":
                return "<h4>Remediation: Replay Attack</h4>\n"
                        + "<p>Implement idempotency controls to prevent one-time actions "
                        + "from being repeated.</p>\n"
                        + "<ul>\n"
                        + "<li>Use unique idempotency keys for each transaction</li>\n"
                        + "<li>Mark actions as completed in the database and reject duplicates</li>\n"
                        + "<li>Use nonces or one-time tokens that are invalidated after use</li>\n"
                        + "<li>Implement server-side deduplication for critical operations</li>\n"
                        + "</ul>";

            case "idor_in_workflow":
                return "<h4>Remediation: IDOR in Workflow</h4>\n"
                        + "<p>Implement proper authorization checks at every step of the workflow, "
                        + "not just the entry point.</p>\n"
                        + "<ul>\n"
                        + "<li>Verify resource ownership at each workflow step</li>\n"
                        + "<li>Use indirect references (mapped to session) instead of direct IDs</li>\n"
                        + "<li>Validate that the authenticated user has access to the referenced resource</li>\n"
                        + "<li>Log and alert on access attempts to other users' resources</li>\n"
                        + "</ul>";

            case "missing_rate_limit":
                return "<h4>Remediation: Missing Rate Limit</h4>\n"
                        + "<p>Implement rate limiting on sensitive endpoints to prevent abuse.</p>\n"
                        + "<ul>\n"
                        + "<li>Apply per-user and per-IP rate limits on state-changing endpoints</li>\n"
                        + "<li>Use exponential backoff for repeated failures</li>\n"
                        + "<li>Return 429 Too Many Requests with Retry-After header</li>\n"
                        + "<li>Monitor and alert on rate limit violations</li>\n"
                        + "</ul>";

            case "state_confusion":
                return "<h4>Remediation: State Confusion</h4>\n"
                        + "<p>Ensure consistent state management across all workflow steps.</p>\n"
                        + "<ul>\n"
                        + "<li>Use atomic transactions for multi-step state changes</li>\n"
                        + "<li>Implement state machine validation (only valid transitions allowed)</li>\n"
                        + "<li>Invalidate stale state when new actions are taken</li>\n"
                        + "<li>Use optimistic locking to detect concurrent modifications</li>\n"
                        + "</ul>";

            default:
                return getGenericRemediation();
        }
    }

    private static String getGenericRemediation() {
        return "<h4>Remediation</h4>\n"
                + "<p>Review the identified workflow for proper server-side validation:</p>\n"
                + "<ul>\n"
                + "<li>Validate state transitions server-side at each step</li>\n"
                + "<li>Never trust client-reported state or values</li>\n"
                + "<li>Implement proper authorization checks at every endpoint</li>\n"
                + "<li>Use anti-CSRF tokens for state-changing requests</li>\n"
                + "<li>Apply rate limiting to sensitive operations</li>\n"
                + "</ul>";
    }
}

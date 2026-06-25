package com.workflowscanner.analysis;

import com.workflowscanner.classification.NoiseRulesConfig;
import com.workflowscanner.classification.PrivateContextDetector;
import com.workflowscanner.config.ExtensionConfig;
import com.workflowscanner.graph.EdgeType;
import com.workflowscanner.graph.RequestEdge;
import com.workflowscanner.graph.RequestNode;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;
import com.workflowscanner.validation.ValidationResult;
import com.workflowscanner.workflow.WorkflowCandidate;
import com.workflowscanner.workflow.WorkflowType;

import java.util.List;
import java.util.Set;

/**
 * Final gate between LLM analysis + validation and the production
 * of Burp audit issues.
 *
 * <p><b>Why this exists:</b> the previous pipeline exported advisories
 * for LLM hypotheses even when:
 * <ul>
 *   <li>validation failed (replay returned no response, mutation did
 *       not apply, scope blocked the test);</li>
 *   <li>the candidate was session-only with no explicit edges, no
 *       state-changing steps, and an unknown workflow type;</li>
 *   <li>the endpoint was a public resource (blockchain wallet,
 *       token price) and the LLM was treating the public read as
 *       IDOR.</li>
 * </ul>
 * Those advisories polluted the Burp issue list with low-signal
 * noise. The gate is the single place that asks
 * "is this worth a Burp issue?" — and answers with a
 * {@link ReportabilityDecision} that the
 * {@link com.workflowscanner.advisory.AdvisoryManager} must respect.
 *
 * <p><b>Decision precedence (highest first):</b>
 * <ol>
 *   <li>REPORT_CONFIRMED — any strict (CONFIRMED) validation proof</li>
 *   <li>SUPPRESS_PUBLIC_RESOURCE — public-resource pattern + no
 *       auth-bound ownership proof</li>
 *   <li>SUPPRESS_VALIDATION_FAILED — all tests failed/empty AND
 *       user has not opted in to failed-validation hypotheses</li>
 *   <li>SUPPRESS_READ_ONLY_SESSION_ONLY — session-only candidate,
 *       all steps are GET/HEAD, no explicit edges, no probable
 *       validation, and user has not opted in to read-only
 *       candidates</li>
 *   <li>REPORT_NEEDS_REVIEW — has probable validation, OR has
 *       explicit edges, OR has state-changing steps, OR is a
 *       critical workflow type</li>
 *   <li>SUPPRESS_LOW_SIGNAL — none of the above</li>
 * </ol>
 *
 * <p>The gate is intentionally conservative: when in doubt, it
 * suppresses and logs the reason. Promoting a finding to a Burp
 * issue is a high-friction action; suppressing a low-signal
 * hypothesis is cheap and reversible (the verdict is still in the
 * extension log and accessible through the Graph tab).
 */
public class ReportabilityGate {

    /** HTTP methods that change server state. */
    private static final Set<String> STATE_CHANGING_METHODS = Set.of(
            "POST", "PUT", "PATCH", "DELETE");

    /**
     * Workflow types that imply user-bound or business-critical
     * state. Findings on these are never "low-signal" even if the
     * candidate is read-only, because the workflow itself is
     * state-changing in nature (e.g. a price lookup in a CHECKOUT
     * workflow is meaningful context for IDOR).
     */
    private static final Set<WorkflowType> CRITICAL_WORKFLOW_TYPES = Set.of(
            WorkflowType.AUTHENTICATION,
            WorkflowType.PASSWORD_RESET,
            WorkflowType.CHECKOUT,
            WorkflowType.PAYMENT,
            WorkflowType.TRANSFER,
            WorkflowType.ROLE_ADMIN,
            WorkflowType.APPROVAL,
            WorkflowType.INVITATION,
            WorkflowType.FILE_UPLOAD
    );

    private final ExtensionConfig config;
    private final ExtensionLogger logger;
    private final PublicResourceClassifier publicResourceClassifier;
    private final PrivateContextDetector privateContextDetector;

    public ReportabilityGate(ExtensionConfig config, ExtensionLogger logger) {
        this.config = config;
        this.logger = logger;
        NoiseRulesConfig nrc = config != null && config.getNoiseRules() != null
                ? config.getNoiseRules()
                : NoiseRulesConfig.withDefaults();
        this.publicResourceClassifier = new PublicResourceClassifier(nrc);
        this.privateContextDetector = new PrivateContextDetector(nrc);
    }

    /**
     * Decide whether a finding derived from a candidate + validation
     * results is worth turning into a Burp issue. Always returns a
     * non-null {@link ReportabilityDecision}; callers should branch
     * on {@link ReportabilityDecision#shouldReport()}.
     *
     * @param verdict           the LLM verdict for the chain
     * @param candidate         the workflow candidate
     * @param validationResults the validation results for this chain
     *                          (may be null or empty)
     * @param customReason      optional caller-supplied reason to
     *                          include in the log (e.g. for override
     *                          paths); may be null
     * @return the decision; never null
     */
    public ReportabilityDecision decide(ChainVerdict verdict,
                                        WorkflowCandidate candidate,
                                        List<ValidationResult> validationResults,
                                        String customReason) {
        // === P0-QUALITY-GATE: fail closed ===
        // The gate must default to SUPPRESS, never REPORT, so a
        // bug elsewhere in the pipeline cannot leak unconfirmed
        // findings to the Burp issue list.

        // (0a) No verdict -> no issue.
        if (verdict == null) {
            logDecision(verdict, candidate, ReportabilityDecision.SUPPRESS_LOW_SIGNAL,
                    customReason + " (no verdict)");
            return ReportabilityDecision.SUPPRESS_LOW_SIGNAL;
        }

        // (0b) No candidate -> only report on strict confirmation.
        if (candidate == null) {
            boolean hasStrictConfirmation = validationResults != null
                    && validationResults.stream().anyMatch(ValidationResult::isConfirmedStrict);
            if (hasStrictConfirmation && (verdict.isVulnerable() || verdict.isSuspicious())) {
                return report(verdict, candidate, ReportabilityDecision.REPORT_CONFIRMED,
                        customReason + " (strict confirmation, no candidate)");
            }
            logDecision(verdict, candidate, ReportabilityDecision.SUPPRESS_LOW_SIGNAL,
                    customReason + " (no candidate, no strict confirmation)");
            return ReportabilityDecision.SUPPRESS_LOW_SIGNAL;
        }

        boolean isSafe = verdict.isSafe();
        boolean isVulnerable = verdict.isVulnerable();
        boolean isSuspicious = verdict.isSuspicious();
        double confidence = verdict.getOverallConfidence();

        // (0c) Safe verdict never produces an issue.
        if (isSafe) {
            return suppress(verdict, candidate, ReportabilityDecision.SUPPRESS_LOW_SIGNAL,
                    customReason + " (overallVerdict=SAFE)");
        }

        // (0d) Zero confidence -> the LLM did not commit to a finding.
        // Even if validation later produces strict confirmation we
        // will catch that in (1). The default is to suppress.
        if (confidence <= 0.0) {
            boolean hasStrictConfirmation = validationResults != null
                    && validationResults.stream().anyMatch(ValidationResult::isConfirmedStrict);
            if (!hasStrictConfirmation) {
                return suppress(verdict, candidate, ReportabilityDecision.SUPPRESS_ZERO_CONFIDENCE,
                        customReason + " (zero confidence, no strict confirmation)");
            }
        }

        boolean hasStrictConfirmation = validationResults != null
                && validationResults.stream().anyMatch(ValidationResult::isConfirmedStrict);
        boolean hasProbableValidation = validationResults != null
                && validationResults.stream()
                .anyMatch(r -> r.getProofLevel() == ValidationResult.ProofLevel.PROBABLE);
        boolean validationAllFailed = validationResults != null
                && !validationResults.isEmpty()
                && validationResults.stream().allMatch(r ->
                        r.getProofLevel() == ValidationResult.ProofLevel.ERROR
                                || r.getProofLevel() == ValidationResult.ProofLevel.NOT_CONFIRMED);
        boolean validationSkipped = validationResults == null || validationResults.isEmpty();

        boolean hasExplicitEdges = candidate.getSupportingEdges() != null
                && candidate.getSupportingEdges().stream()
                .anyMatch(e -> e.getType() != null && e.getType().isExplicit());
        boolean hasStateChanging = candidate.getSteps() != null
                && candidate.getSteps().stream()
                .anyMatch(n -> STATE_CHANGING_METHODS.contains(
                        n.getMethod() == null ? "" : n.getMethod().toUpperCase()));
        boolean criticalWorkflow = CRITICAL_WORKFLOW_TYPES.contains(candidate.getWorkflowType());
        boolean userDefined = candidate.getSupportingEdges() != null
                && candidate.getSupportingEdges().stream()
                .anyMatch(e -> e.getType() == EdgeType.USER_DEFINED);

        boolean readOnly = !hasStateChanging;
        boolean sessionOnly = !hasExplicitEdges;
        boolean isInfrastructurePolling = candidate.getSteps() != null
                && candidate.getSteps().stream().anyMatch(n ->
                        n.getClassification() != null
                                && (n.getClassification().getIntent()
                                        == com.workflowscanner.classification.RequestIntent.TELEMETRY_ANALYTICS
                                || n.getClassification().getIntent()
                                        == com.workflowscanner.classification.RequestIntent.BACKGROUND_POLLING));

        // (1) Strict confirmation always wins. Any CONFIRMED test
        //     means the business effect was observed.
        if (hasStrictConfirmation && (isVulnerable || isSuspicious)) {
            return report(verdict, candidate, ReportabilityDecision.REPORT_CONFIRMED,
                    customReason + " (strict confirmation)");
        }

        // (2) Infrastructure polling pattern: telemetry, feature
        //     flags, /collect, /metrics. The candidate contains at
        //     least one step classified as TELEMETRY_ANALYTICS or
        //     BACKGROUND_POLLING.
        if (isInfrastructurePolling) {
            return suppress(verdict, candidate,
                    ReportabilityDecision.SUPPRESS_INFRASTRUCTURE_POLLING,
                    customReason + " (telemetry / feature-flag / polling endpoint in chain)");
        }

        // (3) Public-resource pattern: a read-only public data lookup
        //     (price, weather, blog, blockchain balance, public
        //     catalog item) where the chain carries no private
        //     context. The LLM is likely calling this IDOR; the gate
        //     refuses unless the candidate has auth-bound
        //     ownership.
        if (publicResourceClassifier.isPublicResourceFinding(candidate)) {
            RequestNode privateStep = privateContextDetector.findPrivateContextStep(
                    candidate.getSteps());
            String privContextNote = privateStep != null
                    ? " (private-context step present: " + privateStep.getPath() + ")"
                    : " (no private context in chain)";
            return suppress(verdict, candidate,
                    ReportabilityDecision.SUPPRESS_PUBLIC_RESOURCE,
                    customReason + " (public-data lookup, no auth-bound ownership" + privContextNote + ")");
        }

        // (4) All validation tests failed AND user has not opted in
        //     to failed-validation hypotheses. The validation
        //     engine emits ERROR / NOT_CONFIRMED when:
        //       - the mutation could not be applied,
        //       - replay returned no response,
        //       - the server rejected the test,
        //       - the test was dry-run.
        //     None of these produce trustworthy findings.
        if (validationAllFailed) {
            if (!config.isReportFailedValidationHypotheses()) {
                return suppress(verdict, candidate,
                        ReportabilityDecision.SUPPRESS_VALIDATION_FAILED,
                        customReason + " (validation all failed/empty)");
            }
            // User opted in: continue to the next check.
        }

        // (5) LLM-only finding: no validation ran at all. Without
        //     the reportLLMOnlyFindings opt-in, suppress.
        if (validationSkipped) {
            if (!config.isReportLLMOnlyFindings()) {
                return suppress(verdict, candidate,
                        ReportabilityDecision.SUPPRESS_LLM_ONLY,
                        customReason + " (no validation ran; reportLLMOnlyFindings=false)");
            }
        }

        // (6) Unconfirmed finding (no strict, no probable) AND
        //     user has not opted in to unconfirmed reports.
        if (!hasStrictConfirmation && !hasProbableValidation) {
            if (!config.isReportUnconfirmedFindings()) {
                return suppress(verdict, candidate,
                        ReportabilityDecision.SUPPRESS_UNCONFIRMED,
                        customReason + " (unconfirmed; reportUnconfirmedFindings=false)");
            }
        }

        // (7) Read-only session-only candidate with no validation
        //     support. The exact pattern from the noisy 1inch
        //     dataset: GET /price, GET /balance, GET /price.
        if (readOnly && sessionOnly && !hasProbableValidation && !userDefined) {
            if (!config.isAnalyzeReadOnlyCandidates()) {
                return suppress(verdict, candidate,
                        ReportabilityDecision.SUPPRESS_READ_ONLY_SESSION_ONLY,
                        customReason + " (read-only session-only, no probable validation)");
            }
        }

        // (8) Has any of: probable validation, explicit edge, state
        //     change, critical workflow type, or user-defined group.
        if (hasProbableValidation || hasExplicitEdges || hasStateChanging
                || criticalWorkflow || userDefined) {
            if (isVulnerable || isSuspicious) {
                String why;
                if (hasProbableValidation) why = "probable validation";
                else if (hasExplicitEdges) why = "explicit edges";
                else if (hasStateChanging) why = "state-changing step";
                else if (criticalWorkflow) why = "critical workflow type";
                else why = "user-defined group";
                return report(verdict, candidate, ReportabilityDecision.REPORT_NEEDS_REVIEW,
                        customReason + " (" + why + ")");
            }
        }

        // (9) Fallback: no evidence worth a Burp issue.
        return suppress(verdict, candidate, ReportabilityDecision.SUPPRESS_LOW_SIGNAL,
                customReason + " (no probable/explicit/state-change/critical/user-defined)");
    }

    /**
     * Convenience overload without a custom reason.
     */
    public ReportabilityDecision decide(ChainVerdict verdict,
                                        WorkflowCandidate candidate,
                                        List<ValidationResult> validationResults) {
        return decide(verdict, candidate, validationResults, "");
    }

    private ReportabilityDecision report(ChainVerdict verdict, WorkflowCandidate candidate,
                                          ReportabilityDecision decision, String customReason) {
        logDecision(verdict, candidate, decision, customReason);
        return decision;
    }

    private ReportabilityDecision suppress(ChainVerdict verdict, WorkflowCandidate candidate,
                                            ReportabilityDecision decision, String customReason) {
        logDecision(verdict, candidate, decision, customReason);
        return decision;
    }

    private void logDecision(ChainVerdict verdict, WorkflowCandidate candidate,
                              ReportabilityDecision decision, String customReason) {
        if (logger == null) return;
        // === P0-QUALITY-GATE: enriched suppression log ===
        // Every suppression logs candidate id, verdict, confidence,
        // workflow type, step count, edge counts, and decision reason
        // so the user can see exactly what was filtered and why.
        String tag = (decision.shouldReport() ? "REPORT" : "SUPPRESS")
                + " " + decision.name();
        String chain = verdict != null && verdict.getChainId() != null ? verdict.getChainId() : "<no-id>";
        String type = verdict != null && verdict.getVulnerabilityType() != null
                ? verdict.getVulnerabilityType() : "unknown";
        String reason = decision.defaultReason();
        if (customReason != null && !customReason.isEmpty()) {
            reason = customReason;
        }
        double confidence = verdict != null ? verdict.getOverallConfidence() : 0.0;
        String verdictStr = verdict != null && verdict.getOverallVerdict() != null
                ? verdict.getOverallVerdict() : "<null>";
        int stepCount = candidate != null && candidate.getSteps() != null
                ? candidate.getSteps().size() : 0;
        int explicitEdges = candidate != null ? candidate.getExplicitSupportingEdgeCount() : 0;
        boolean hasStateChanging = candidate != null && candidate.getSteps() != null
                && candidate.getSteps().stream().anyMatch(n -> {
                    String m = n.getMethod() == null ? "" : n.getMethod().toUpperCase();
                    return "POST".equals(m) || "PUT".equals(m) || "PATCH".equals(m) || "DELETE".equals(m);
                });
        String workflowType = candidate != null && candidate.getWorkflowType() != null
                ? candidate.getWorkflowType().name() : "<null>";
        String host = "<none>";
        if (candidate != null && candidate.getSteps() != null && !candidate.getSteps().isEmpty()) {
            String h = candidate.getSteps().get(0).getHost();
            if (h != null) host = h;
        }
        try {
            logger.log(LogCategory.ADVISORY,
                    decision.shouldReport() ? LogLevel.INFO : LogLevel.DEBUG,
                    "ReportabilityGate",
                    tag + " chain=" + chain
                            + " verdict=" + verdictStr
                            + " confidence=" + String.format("%.2f", confidence)
                            + " type=" + type
                            + " workflowType=" + workflowType
                            + " host=" + host
                            + " steps=" + stepCount
                            + " explicitEdges=" + explicitEdges
                            + " stateChanging=" + hasStateChanging
                            + " candidateScore=" + String.format("%.1f",
                                    candidate != null ? candidate.getWorkflowScore() : 0)
                            + " reason=" + reason);
        } catch (Exception ignored) {
            // Logger is optional in unit tests.
        }
    }
}

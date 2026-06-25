package com.workflowscanner.advisory;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import com.workflowscanner.analysis.ChainVerdict;
import com.workflowscanner.analysis.ReportabilityDecision;
import com.workflowscanner.analysis.ReportabilityGate;
import com.workflowscanner.data.CapturedRequest;
import com.workflowscanner.graph.RequestNode;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;
import com.workflowscanner.store.RequestHydrator;
import com.workflowscanner.store.RequestStore;
import com.workflowscanner.validation.ValidationResult;
import com.workflowscanner.workflow.WorkflowCandidate;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Manages creation and lifecycle of Burp Suite scanner issues (advisories)
 * for confirmed and high-confidence workflow vulnerabilities.
 *
 * Features:
 * - Creates custom AuditIssue with rich HTML detail
 * - Severity/confidence mapping per vuln type + validation status
 * - Issue deduplication via fingerprint
 * - Cross-references between related issues
 * - Issue tracking and statistics
 *
 * <p><b>Reportability gate (reportability rework):</b> the manager
 * delegates the "is this worth a Burp issue?" decision to
 * {@link ReportabilityGate}. The gate's decision is final for the
 * default config; the {@code reportUnconfirmedFindings},
 * {@code reportLLMOnlyFindings}, and
 * {@code reportFailedValidationHypotheses} settings can re-enable
 * suppressed findings for users who want to see every hypothesis.
 */
public class AdvisoryManager {

    private final MontoyaApi api;
    private final ExtensionLogger logger;

    // Deduplication: fingerprint -> issue
    private final Map<String, WorkflowAuditIssue> issueFingerprintMap = new ConcurrentHashMap<>();
    private final List<WorkflowAuditIssue> allIssues = new CopyOnWriteArrayList<>();
    private final Set<String> dismissedFingerprints = ConcurrentHashMap.newKeySet();

    // Disk-backed request store. When set, the manager re-hydrates
    // raw HTTP for each chain node before building the evidence
    // issue so backfilled candidates still produce complete
    // request/response pairs in the Burp UI.
    private volatile RequestStore requestStore;

    // Reportability gate. When set, every createFromVerdict call
    // is filtered through the gate so low-signal findings never
    // become Burp issues. Set externally by the bootstrap.
    private volatile ReportabilityGate reportabilityGate;

    // Live counters for the status panel. Read by HealthCheck so
    // the user can see how many findings the gate suppressed and
    // for what reason. O(1) reads, no graph scans.
    private final AtomicLong suppressedByGate = new AtomicLong(0);
    private final AtomicLong suppressedPublicResource = new AtomicLong(0);
    private final AtomicLong suppressedValidationFailed = new AtomicLong(0);
    private final AtomicLong suppressedLowSignal = new AtomicLong(0);
    private final AtomicLong suppressedZeroConfidence = new AtomicLong(0);
    private final AtomicLong suppressedLLMOnly = new AtomicLong(0);
    private final AtomicLong suppressedUnconfirmed = new AtomicLong(0);
    private final AtomicLong suppressedInfrastructurePolling = new AtomicLong(0);
    private final AtomicLong suppressedReadOnlySessionOnly = new AtomicLong(0);
    private final AtomicLong reportedNeedsReview = new AtomicLong(0);
    private final AtomicLong reportedConfirmed = new AtomicLong(0);

    public AdvisoryManager(MontoyaApi api, ExtensionLogger logger) {
        this.api = api;
        this.logger = logger;
        logger.log(LogCategory.ADVISORY, LogLevel.DEBUG, "AdvisoryManager", "Advisory manager created.");
    }

    public void setRequestStore(RequestStore store) {
        this.requestStore = store;
    }

    /**
     * Set the reportability gate. When unset, the manager falls
     * back to the legacy "validated / probable / errored" branch
     * for backward compatibility with code paths that have not yet
     * been updated to use the gate.
     */
    public void setReportabilityGate(ReportabilityGate gate) {
        this.reportabilityGate = gate;
    }

    /**
     * Backward-compatible entry point: no candidate passed to the
     * gate. The gate will fall back to a low-signal decision when
     * it cannot see the candidate's supporting edges / public
     * endpoint pattern. Prefer the 3-arg overload.
     */
    public WorkflowAuditIssue createFromVerdict(ChainVerdict verdict,
                                                  List<ValidationResult> validationResults) {
        return createFromVerdict(verdict, validationResults, null);
    }

    /**
     * Create a Burp advisory from a chain verdict and optional
     * validation results. Handles deduplication, severity mapping,
     * and issue registration.
     *
     * <p><b>Reportability gate (reportability rework):</b> when a
     * gate is set, the call goes through {@code gate.decide(...)}
     * first and the issue is suppressed (return null, no Burp
     * issue) if the gate's decision is a SUPPRESS_* outcome. The
     * {@code candidate} is optional but recommended — without it,
     * the gate cannot evaluate public-resource patterns or
     * explicit-edge support and falls back to a low-signal
     * decision.
     *
     * @param verdict           the LLM verdict for the chain
     * @param validationResults the validation results; may be null/empty
     * @param candidate         the workflow candidate backing this
     *                          verdict; may be null
     * @return the created issue, or null if suppressed by the gate
     *         or deduplicated/dismissed
     */
    public WorkflowAuditIssue createFromVerdict(ChainVerdict verdict,
                                                  List<ValidationResult> validationResults,
                                                  WorkflowCandidate candidate) {
        if (verdict == null) return null;

        // === P0-QUALITY-GATE: hard guard for zero confidence ===
        // Even if the gate has a bug, never create an issue from a
        // 0% confidence verdict (which means the LLM did not commit
        // to a finding). This is the last line of defense.
        if (verdict.getOverallConfidence() <= 0.0) {
            boolean hasStrictConfirmation = validationResults != null
                    && validationResults.stream().anyMatch(ValidationResult::isConfirmedStrict);
            if (!hasStrictConfirmation) {
                suppressedZeroConfidence.incrementAndGet();
                suppressedByGate.incrementAndGet();
                if (logger != null) {
                    logger.log(LogCategory.ADVISORY, LogLevel.DEBUG, "AdvisoryManager",
                            "Suppressed hard-guard: zero confidence, no strict confirmation: "
                                    + verdict.getVulnerabilityType()
                                    + " chain=" + verdict.getChainId());
                }
                return null;
            }
        }

        // Reportability gate: if it suppresses, return null BEFORE
        // the safe-verdict / dedup short-circuits, so the counters
        // for suppression are always incremented when the gate is
        // consulted. (The safe-verdict check is also a low-signal
        // SUPPRESS, but it's cheap and uninteresting to count.)
        if (reportabilityGate != null) {
            ReportabilityDecision decision = reportabilityGate.decide(
                    verdict, candidate, validationResults);
            if (decision.isSuppressed()) {
                suppressedByGate.incrementAndGet();
                switch (decision) {
                    case SUPPRESS_PUBLIC_RESOURCE: suppressedPublicResource.incrementAndGet(); break;
                    case SUPPRESS_VALIDATION_FAILED: suppressedValidationFailed.incrementAndGet(); break;
                    case SUPPRESS_INFRASTRUCTURE_POLLING: suppressedInfrastructurePolling.incrementAndGet(); break;
                    case SUPPRESS_ZERO_CONFIDENCE: suppressedZeroConfidence.incrementAndGet(); break;
                    case SUPPRESS_LLM_ONLY: suppressedLLMOnly.incrementAndGet(); break;
                    case SUPPRESS_UNCONFIRMED: suppressedUnconfirmed.incrementAndGet(); break;
                    case SUPPRESS_READ_ONLY_SESSION_ONLY: suppressedReadOnlySessionOnly.incrementAndGet(); break;
                    case SUPPRESS_LOW_SIGNAL:
                    default: suppressedLowSignal.incrementAndGet(); break;
                }
                if (logger != null) {
                    logger.log(LogCategory.ADVISORY, LogLevel.DEBUG, "AdvisoryManager",
                            "Suppressed by gate [" + decision.name() + "]: "
                                    + verdict.getVulnerabilityType()
                                    + " chain=" + verdict.getChainId());
                }
                return null;
            }
            // Track what we report too.
            if (decision == ReportabilityDecision.REPORT_CONFIRMED) {
                reportedConfirmed.incrementAndGet();
            } else if (decision == ReportabilityDecision.REPORT_NEEDS_REVIEW) {
                reportedNeedsReview.incrementAndGet();
            }
        } else {
            // === P0-QUALITY-GATE: no gate wired is a fail-closed path ===
            // Without a gate, refuse to create issues from unconfirmed
            // findings. The only safe branch is CONFIRMED strict
            // validation or a safe verdict (suppressed below).
            if (!verdict.isSafe()) {
                boolean hasStrictConfirmation = validationResults != null
                        && validationResults.stream().anyMatch(ValidationResult::isConfirmedStrict);
                if (!hasStrictConfirmation) {
                    suppressedByGate.incrementAndGet();
                    suppressedLowSignal.incrementAndGet();
                    if (logger != null) {
                        logger.log(LogCategory.ADVISORY, LogLevel.WARN, "AdvisoryManager",
                                "No reportability gate wired; suppressed unconfirmed finding: "
                                        + verdict.getVulnerabilityType()
                                        + " chain=" + verdict.getChainId());
                    }
                    return null;
                }
            }
            // Safe verdict short-circuit (no issue, but don't suppress-count).
            if (verdict.isSafe()) return null;
        }

        // Generate fingerprint for deduplication
        String fingerprint = generateFingerprint(verdict);

        // Check if dismissed
        if (dismissedFingerprints.contains(fingerprint)) {
            logger.log(LogCategory.ADVISORY, LogLevel.DEBUG, "AdvisoryManager",
                    "Issue dismissed by user, skipping: " + fingerprint);
            return null;
        }

        // Check for duplicate
        if (issueFingerprintMap.containsKey(fingerprint)) {
            logger.log(LogCategory.ADVISORY, LogLevel.DEBUG, "AdvisoryManager",
                    "Duplicate issue, skipping: " + fingerprint);
            return null;
        }

        // Determine if validated. We use the strict accessor: only
        // CONFIRMED proof levels count as "validated" for high-severity
        // issue creation. PROBABLE findings are downgraded to medium
        // severity and labeled as needing review; this prevents a flood
        // of false-confirmed Burp issues driven by response similarity.
        boolean validated = validationResults != null
                && validationResults.stream().anyMatch(ValidationResult::isConfirmedStrict);
        boolean probable = !validated && validationResults != null
                && validationResults.stream().anyMatch(ValidationResult::isConfirmed);
        boolean errored = !validated && !probable && validationResults != null
                && validationResults.stream().anyMatch(
                        r -> r.getProofLevel() == ValidationResult.ProofLevel.ERROR);

        // Map severity and confidence
        AuditIssueSeverity severity = SeverityMapper.mapSeverity(
                verdict.getVulnerabilityType(), validated, verdict.getOverallVerdict());
        AuditIssueConfidence confidence = SeverityMapper.mapConfidence(
                verdict.getVulnerabilityType(), validated, verdict.getOverallVerdict());

        // Build issue name
        String vulnType = verdict.getVulnerabilityType() != null
                ? formatVulnType(verdict.getVulnerabilityType()) : "Workflow Vulnerability";
        String issueName = "Workflow " + vulnType;
        if (validated) issueName += " (Confirmed)";
        else if (probable) issueName += " (Needs Review)";
        else if (errored) issueName += " (Test Failed)";

        // Determine base URL from chain
        String baseUrl = "";
        if (verdict.getChain() != null && !verdict.getChain().isEmpty()) {
            RequestNode firstNode = verdict.getChain().get(0);
            if (firstNode.getUrl() != null) {
                baseUrl = extractBaseUrl(firstNode.getUrl());
            }
        }

        // Build HTML detail
        String detail = IssueDetailBuilder.buildDetail(verdict, validationResults);

        // Build remediation
        String remediation = RemediationTemplates.getRemediation(verdict.getVulnerabilityType());

        // Build evidence from actual request/response pairs
        List<HttpRequestResponse> evidence = buildEvidence(verdict);

        // Create the issue
        WorkflowAuditIssue issue = new WorkflowAuditIssue(
                issueName, detail, remediation, baseUrl,
                severity, confidence,
                evidence,
                fingerprint);

        // Register with Burp
        try {
            api.siteMap().add(issue);
            logger.log(LogCategory.ADVISORY, LogLevel.INFO, "AdvisoryManager",
                    "Created advisory: " + issueName + " [" + severity + "/" + confidence + "]"
                            + " for " + baseUrl);
        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "AdvisoryManager",
                    "Failed to register issue with Burp.", e);
        }

        // Track
        issueFingerprintMap.put(fingerprint, issue);
        allIssues.add(issue);

        return issue;
    }

    /**
     * Dismiss an issue (mark as false positive).
     */
    public void dismissIssue(String fingerprint) {
        dismissedFingerprints.add(fingerprint);
        issueFingerprintMap.remove(fingerprint);
        logger.log(LogCategory.ADVISORY, LogLevel.INFO, "AdvisoryManager",
                "Issue dismissed: " + fingerprint);
    }

    /**
     * Generate a deduplication fingerprint.
     * Based on: vulnerability_type + primary endpoint + affected parameters.
     */
    private String generateFingerprint(ChainVerdict verdict) {
        StringBuilder fp = new StringBuilder();
        fp.append(verdict.getVulnerabilityType() != null ? verdict.getVulnerabilityType() : "unknown");
        fp.append('|');

        // Primary endpoint (last node in chain, typically the vulnerable one)
        if (verdict.getChain() != null && !verdict.getChain().isEmpty()) {
            RequestNode lastNode = verdict.getChain().get(verdict.getChain().size() - 1);
            fp.append(lastNode.getMethod()).append(':').append(lastNode.getPath());
        }
        fp.append('|');

        // Affected parameters
        if (verdict.getNodeResults() != null) {
            List<String> params = new ArrayList<>();
            for (var result : verdict.getNodeResults()) {
                if (result != null && result.getAffectedParameters() != null) {
                    params.addAll(result.getAffectedParameters());
                }
            }
            Collections.sort(params);
            fp.append(String.join(",", params));
        }

        return fp.toString();
    }

    private String extractBaseUrl(String url) {
        if (url == null) return "";
        try {
            int protoEnd = url.indexOf("://");
            if (protoEnd < 0) return url;
            int pathStart = url.indexOf('/', protoEnd + 3);
            return pathStart > 0 ? url.substring(0, pathStart) : url;
        } catch (Exception e) {
            return url;
        }
    }

    private String formatVulnType(String type) {
        if (type == null) return "Unknown";
        String[] words = type.split("_");
        StringBuilder sb = new StringBuilder();
        for (String word : words) {
            if (!word.isEmpty()) {
                sb.append(Character.toUpperCase(word.charAt(0)));
                sb.append(word.substring(1)).append(' ');
            }
        }
        return sb.toString().trim();
    }

    /**
     * Build evidence list from the verdict's chain.
     * Converts captured request/response data into Burp HttpRequestResponse objects.
     */
    private List<HttpRequestResponse> buildEvidence(ChainVerdict verdict) {
        List<HttpRequestResponse> evidence = new ArrayList<>();
        if (verdict.getChain() == null) return evidence;

        for (RequestNode node : verdict.getChain()) {
            if (node.getUrl() == null) continue;
            // Re-hydrate from the store if the hot graph dropped raw.
            if (node.getRequest() == null && requestStore != null) {
                RequestHydrator.ensureHydrated(node, requestStore);
            }
            try {
                // Build Burp HttpRequest from URL
                HttpRequest request = HttpRequest.httpRequest(node.getUrl());
                request = request.withMethod(node.getMethod() != null ? node.getMethod() : "GET");

                // Add body if available
                CapturedRequest captured = node.getRequest();
                if (captured != null) {
                    // Copy headers
                    if (captured.getRequestHeaders() != null) {
                        for (Map.Entry<String, List<String>> entry :
                                captured.getRequestHeaders().entrySet()) {
                            for (String value : entry.getValue()) {
                                request = request.withAddedHeader(entry.getKey(), value);
                            }
                        }
                    }
                    if (captured.getRequestBody() != null && !captured.getRequestBody().isEmpty()) {
                        request = request.withBody(captured.getRequestBody());
                    }
                }

                // Build Burp HttpResponse from status code and body
                HttpResponse response = null;
                if (captured != null && captured.getResponseBody() != null) {
                    StringBuilder respBuilder = new StringBuilder();
                    respBuilder.append("HTTP/1.1 ").append(node.getStatusCode()).append(" OK\r\n");
                    if (captured.getResponseHeaders() != null) {
                        for (Map.Entry<String, List<String>> entry :
                                captured.getResponseHeaders().entrySet()) {
                            for (String value : entry.getValue()) {
                                respBuilder.append(entry.getKey()).append(": ").append(value).append("\r\n");
                            }
                        }
                    }
                    respBuilder.append("\r\n").append(captured.getResponseBody());
                    response = HttpResponse.httpResponse(respBuilder.toString());
                } else {
                    response = HttpResponse.httpResponse(httpStatusCodeLine(node.getStatusCode()));
                }

                HttpRequestResponse pair = HttpRequestResponse.httpRequestResponse(request, response);
                evidence.add(pair);

            } catch (Exception e) {
                logger.log(LogCategory.ERROR, LogLevel.DEBUG, "AdvisoryManager",
                        "Could not build evidence for " + node.getMethod() + " " + node.getPath(), e);
            }
        }
        return evidence;
    }

    private String httpStatusCodeLine(int statusCode) {
        switch (statusCode) {
            case 200: return "HTTP/1.1 200 OK\r\n\r\n";
            case 201: return "HTTP/1.1 201 Created\r\n\r\n";
            case 204: return "HTTP/1.1 204 No Content\r\n\r\n";
            case 301: return "HTTP/1.1 301 Moved Permanently\r\n\r\n";
            case 302: return "HTTP/1.1 302 Found\r\n\r\n";
            case 304: return "HTTP/1.1 304 Not Modified\r\n\r\n";
            case 400: return "HTTP/1.1 400 Bad Request\r\n\r\n";
            case 401: return "HTTP/1.1 401 Unauthorized\r\n\r\n";
            case 403: return "HTTP/1.1 403 Forbidden\r\n\r\n";
            case 404: return "HTTP/1.1 404 Not Found\r\n\r\n";
            case 405: return "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
            case 429: return "HTTP/1.1 429 Too Many Requests\r\n\r\n";
            case 500: return "HTTP/1.1 500 Internal Server Error\r\n\r\n";
            case 502: return "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            case 503: return "HTTP/1.1 503 Service Unavailable\r\n\r\n";
            default:  return "HTTP/1.1 " + statusCode + " Unknown\r\n\r\n";
        }
    }

    // --- Accessors ---

    public List<WorkflowAuditIssue> getAllIssues() {
        return Collections.unmodifiableList(allIssues);
    }

    public int getIssueCount() { return allIssues.size(); }

    public int getDismissedCount() { return dismissedFingerprints.size(); }

    public boolean isDuplicate(String fingerprint) {
        return issueFingerprintMap.containsKey(fingerprint);
    }

    // --- Reportability-gate counters ---

    /** Total findings suppressed by the gate (any reason). */
    public long getSuppressedByGateCount() { return suppressedByGate.get(); }

    /** Findings suppressed because the endpoint is a public resource. */
    public long getSuppressedPublicResourceCount() { return suppressedPublicResource.get(); }

    /** Findings suppressed because all validation tests failed. */
    public long getSuppressedValidationFailedCount() { return suppressedValidationFailed.get(); }

    /** Findings suppressed as low-signal (no probable/explicit/state-change/critical). */
    public long getSuppressedLowSignalCount() { return suppressedLowSignal.get(); }

    /** Findings suppressed because verdict confidence was 0%. */
    public long getSuppressedZeroConfidenceCount() { return suppressedZeroConfidence.get(); }

    /** Findings suppressed because they are LLM-only with no validation. */
    public long getSuppressedLLMOnlyCount() { return suppressedLLMOnly.get(); }

    /** Findings suppressed because they are unconfirmed. */
    public long getSuppressedUnconfirmedCount() { return suppressedUnconfirmed.get(); }

    /** Findings suppressed because the chain contains infrastructure polling. */
    public long getSuppressedInfrastructurePollingCount() { return suppressedInfrastructurePolling.get(); }

    /** Findings suppressed because they are read-only session-only. */
    public long getSuppressedReadOnlySessionOnlyCount() { return suppressedReadOnlySessionOnly.get(); }

    /** Findings reported as needs-review (probable validation / explicit edges / state-change / critical). */
    public long getReportedNeedsReviewCount() { return reportedNeedsReview.get(); }

    /** Findings reported as confirmed (strict proof). */
    public long getReportedConfirmedCount() { return reportedConfirmed.get(); }
}

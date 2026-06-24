package com.workflowscanner.advisory;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import com.workflowscanner.analysis.ChainVerdict;
import com.workflowscanner.data.CapturedRequest;
import com.workflowscanner.graph.RequestNode;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;
import com.workflowscanner.validation.ValidationResult;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

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
 */
public class AdvisoryManager {

    private final MontoyaApi api;
    private final ExtensionLogger logger;

    // Deduplication: fingerprint -> issue
    private final Map<String, WorkflowAuditIssue> issueFingerprintMap = new ConcurrentHashMap<>();
    private final List<WorkflowAuditIssue> allIssues = new CopyOnWriteArrayList<>();
    private final Set<String> dismissedFingerprints = ConcurrentHashMap.newKeySet();

    public AdvisoryManager(MontoyaApi api, ExtensionLogger logger) {
        this.api = api;
        this.logger = logger;
        logger.log(LogCategory.ADVISORY, LogLevel.DEBUG, "AdvisoryManager", "Advisory manager created.");
    }

    /**
     * Create a Burp advisory from a chain verdict and optional validation results.
     * Handles deduplication, severity mapping, and issue registration.
     *
     * @return The created issue, or null if deduplicated/dismissed
     */
    public WorkflowAuditIssue createFromVerdict(ChainVerdict verdict,
                                                  List<ValidationResult> validationResults) {
        if (verdict == null || verdict.isSafe()) return null;

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

        // Determine if validated
        boolean validated = validationResults != null
                && validationResults.stream().anyMatch(ValidationResult::isConfirmed);

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
}

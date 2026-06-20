package com.workflowscanner.advisory;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import com.workflowscanner.analysis.ChainVerdict;
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

        // Create the issue
        WorkflowAuditIssue issue = new WorkflowAuditIssue(
                issueName, detail, remediation, baseUrl,
                severity, confidence,
                Collections.emptyList(), // Evidence request/responses added separately
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

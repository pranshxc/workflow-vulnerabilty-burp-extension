package com.workflowscanner.advisory;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.collaborator.Interaction;

import java.util.List;
import java.util.Collections;

/**
 * Custom Burp Suite AuditIssue for workflow vulnerabilities.
 * Provides rich HTML-formatted detail visible in Burp's Scanner/Issues tab.
 */
public class WorkflowAuditIssue implements AuditIssue {

    private final String name;
    private final String detail;
    private final String remediation;
    private final String baseUrl;
    private final AuditIssueSeverity severity;
    private final AuditIssueConfidence confidence;
    private final List<HttpRequestResponse> requestResponses;
    private final String fingerprint;

    public WorkflowAuditIssue(String name, String detail, String remediation,
                               String baseUrl, AuditIssueSeverity severity,
                               AuditIssueConfidence confidence,
                               List<HttpRequestResponse> requestResponses,
                               String fingerprint) {
        this.name = name;
        this.detail = detail;
        this.remediation = remediation;
        this.baseUrl = baseUrl;
        this.severity = severity;
        this.confidence = confidence;
        this.requestResponses = requestResponses;
        this.fingerprint = fingerprint;
    }

    @Override
    public String name() { return name; }

    @Override
    public String detail() { return detail; }

    @Override
    public String remediation() { return remediation; }

    @Override
    public String baseUrl() { return baseUrl; }

    @Override
    public AuditIssueSeverity severity() { return severity; }

    @Override
    public AuditIssueConfidence confidence() { return confidence; }

    @Override
    public List<HttpRequestResponse> requestResponses() { return requestResponses; }

    @Override
    public HttpService httpService() {
        if (baseUrl != null && !baseUrl.isEmpty()) {
            try {
                String remaining = baseUrl;
                boolean isHttps = false;
                if (remaining.startsWith("https://")) {
                    remaining = remaining.substring(8);
                    isHttps = true;
                } else if (remaining.startsWith("http://")) {
                    remaining = remaining.substring(7);
                }
                int portIdx = remaining.indexOf(':');
                int pathIdx = remaining.indexOf('/');
                String host;
                int port = isHttps ? 443 : 80;
                if (portIdx > 0 && (pathIdx < 0 || portIdx < pathIdx)) {
                    host = remaining.substring(0, portIdx);
                    String portStr = pathIdx > 0 ? remaining.substring(portIdx + 1, pathIdx) : remaining.substring(portIdx + 1);
                    String portNum = portStr.replaceAll("[^0-9].*", "");
                    if (!portNum.isEmpty()) port = Integer.parseInt(portNum);
                } else {
                    host = pathIdx > 0 ? remaining.substring(0, pathIdx) : remaining;
                }
                return HttpService.httpService(host, port, isHttps);
            } catch (Exception e) {
                return HttpService.httpService("unknown", 443, true);
            }
        }
        return HttpService.httpService("unknown", 443, true);
    }

    @Override
    public List<Interaction> collaboratorInteractions() { return Collections.emptyList(); }

    @Override
    public AuditIssueDefinition definition() {
        return AuditIssueDefinition.auditIssueDefinition(name, remediation, remediation, severity);
    }

    public String getFingerprint() { return fingerprint; }
}

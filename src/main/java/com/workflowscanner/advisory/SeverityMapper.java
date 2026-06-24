package com.workflowscanner.advisory;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

/**
 * Maps vulnerability types and validation status to Burp severity and confidence.
 *
 * <p><b>Validation rework:</b> the {@code validated} parameter is now
 * driven by strict proof level (CONFIRMED only) from
 * {@link com.workflowscanner.validation.ValidationResult}. Findings that
 * are only PROBABLE (response similarity without business-effect proof)
 * get downgraded severity and confidence so they do not flood Burp as
 * high-severity false positives.
 *
 * | Vulnerability Type          | Validated | Severity | Confidence |
 * |-----------------------------|-----------|----------|------------|
 * | Step skipping (financial)   | Yes       | HIGH     | CERTAIN    |
 * | Step skipping (financial)   | No        | MEDIUM   | TENTATIVE  |
 * | Value manipulation (price)  | Yes       | HIGH     | CERTAIN    |
 * | Value manipulation (other)  | Yes       | MEDIUM   | FIRM       |
 * | Race condition              | Yes       | HIGH     | FIRM       |
 * | Race condition              | No        | LOW      | TENTATIVE  |
 * | Replay/repeat abuse         | Yes       | MEDIUM   | CERTAIN    |
 * | IDOR in workflow            | Yes       | HIGH     | CERTAIN    |
 * | IDOR in workflow            | No        | MEDIUM   | TENTATIVE  |
 * | Missing rate limit          | Yes       | LOW      | FIRM       |
 * | State confusion             | Yes       | MEDIUM   | FIRM       |
 * | Generic suspicious          | No        | INFO     | TENTATIVE  |
 */
public class SeverityMapper {

    public static AuditIssueSeverity mapSeverity(String vulnerabilityType, boolean validated,
                                                   String overallVerdict) {
        if ("SAFE".equals(overallVerdict)) return AuditIssueSeverity.INFORMATION;

        if (vulnerabilityType == null) {
            return "VULNERABLE".equals(overallVerdict)
                    ? AuditIssueSeverity.MEDIUM : AuditIssueSeverity.INFORMATION;
        }

        switch (vulnerabilityType) {
            case "step_skipping":
                return validated ? AuditIssueSeverity.HIGH : AuditIssueSeverity.MEDIUM;
            case "value_manipulation":
                return validated ? AuditIssueSeverity.HIGH : AuditIssueSeverity.MEDIUM;
            case "race_condition":
                return validated ? AuditIssueSeverity.HIGH : AuditIssueSeverity.LOW;
            case "replay_attack":
                return AuditIssueSeverity.MEDIUM;
            case "idor_in_workflow":
                return validated ? AuditIssueSeverity.HIGH : AuditIssueSeverity.MEDIUM;
            case "missing_rate_limit":
                return AuditIssueSeverity.LOW;
            case "state_confusion":
                return AuditIssueSeverity.MEDIUM;
            default:
                return "VULNERABLE".equals(overallVerdict)
                        ? AuditIssueSeverity.MEDIUM : AuditIssueSeverity.INFORMATION;
        }
    }

    public static AuditIssueConfidence mapConfidence(String vulnerabilityType, boolean validated,
                                                       String overallVerdict) {
        if ("SAFE".equals(overallVerdict)) return AuditIssueConfidence.TENTATIVE;

        if (validated) {
            // Validated findings get higher confidence
            if (vulnerabilityType != null) {
                switch (vulnerabilityType) {
                    case "step_skipping":
                    case "value_manipulation":
                    case "replay_attack":
                    case "idor_in_workflow":
                        return AuditIssueConfidence.CERTAIN;
                    case "race_condition":
                    case "state_confusion":
                    case "missing_rate_limit":
                        return AuditIssueConfidence.FIRM;
                    default:
                        return AuditIssueConfidence.FIRM;
                }
            }
            return AuditIssueConfidence.FIRM;
        } else {
            // Unvalidated findings are always TENTATIVE; we no longer
            // pretend they are firm. The AdvisoryManager adds a "Needs
            // Review" suffix to the issue name for these.
            return AuditIssueConfidence.TENTATIVE;
        }
    }
}

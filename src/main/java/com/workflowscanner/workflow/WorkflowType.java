package com.workflowscanner.workflow;

import com.workflowscanner.classification.BusinessKeywordRules;
import com.workflowscanner.graph.RequestNode;

import java.util.List;

/**
 * Classifies the business purpose of a detected workflow candidate.
 * Detected by WorkflowDetector based on path patterns, method types,
 * and parameter names across the candidate's steps.
 */
public enum WorkflowType {
    AUTHENTICATION,
    REGISTRATION,
    PASSWORD_RESET,
    CHECKOUT,
    PAYMENT,
    ORDER_MANAGEMENT,
    PROFILE_UPDATE,
    ROLE_ADMIN,
    FILE_UPLOAD,
    INVITATION,
    APPROVAL,
    TRANSFER,
    UNKNOWN_BUSINESS_FLOW;

    /**
     * Detect workflow type from a list of steps.
     */
    public static WorkflowType detect(List<RequestNode> steps) {
        if (steps == null || steps.isEmpty()) return UNKNOWN_BUSINESS_FLOW;

        // Collect path keywords across all steps
        boolean hasAuth = false;
        boolean hasFinancial = false;
        boolean hasAdmin = false;
        boolean hasUpload = false;
        boolean hasProfile = false;
        boolean hasInvite = false;
        boolean hasApproval = false;
        boolean hasRegister = false;
        boolean hasPasswordReset = false;
        boolean hasTransfer = false;

        for (RequestNode node : steps) {
            String path = node.getPath() != null ? node.getPath().toLowerCase() : "";
            String method = node.getMethod() != null ? node.getMethod().toUpperCase() : "GET";

            // Check for specific workflow patterns
            if (path.contains("login") || path.contains("signin") || path.contains("oauth")
                    || path.contains("mfa") || path.contains("2fa")) hasAuth = true;
            if (path.contains("register") || path.contains("signup")) hasRegister = true;
            if (path.contains("reset") && (path.contains("password") || path.contains("passwd")))
                hasPasswordReset = true;
            if (path.contains("checkout") || (path.contains("payment") && method.equals("POST")))
                hasFinancial = true;
            if (path.contains("pay") || path.contains("charge") || path.contains("purchase"))
                hasFinancial = true;
            if (path.contains("admin") || path.contains("role") || path.contains("permission"))
                hasAdmin = true;
            if (path.contains("upload") || path.contains("file/") || path.contains("document"))
                hasUpload = true;
            if (path.contains("profile") || path.contains("settings") || path.contains("account"))
                hasProfile = true;
            if (path.contains("invite") || path.contains("invitation")) hasInvite = true;
            if (path.contains("approve") || path.contains("reject") || path.contains("review"))
                hasApproval = true;
            if (path.contains("transfer") || path.contains("send") && path.contains("money"))
                hasTransfer = true;
        }

        // Determine type (priority order — most specific first)
        if (hasAuth && hasRegister) return REGISTRATION;
        if (hasPasswordReset) return PASSWORD_RESET;
        if (hasAuth) return AUTHENTICATION;
        if (hasTransfer && hasFinancial) return TRANSFER;
        if (hasFinancial && (hasAuth || hasAdmin)) return CHECKOUT;
        if (hasFinancial) return PAYMENT;
        if (hasInvite && hasApproval) return INVITATION;
        if (hasApproval) return APPROVAL;
        if (hasAdmin) return ROLE_ADMIN;
        if (hasUpload) return FILE_UPLOAD;
        if (hasProfile) return PROFILE_UPDATE;

        return UNKNOWN_BUSINESS_FLOW;
    }
}

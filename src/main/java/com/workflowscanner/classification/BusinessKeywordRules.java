package com.workflowscanner.classification;

import java.util.Set;

/**
 * Static rule sets for identifying business-relevant requests.
 * Used by RequestClassifier to score and classify requests.
 */
public class BusinessKeywordRules {

    // State-changing HTTP methods
    private static final Set<String> STATE_CHANGING_METHODS = Set.of("POST", "PUT", "DELETE", "PATCH");

    // Path keywords indicating authentication/authorization
    private static final Set<String> AUTH_KEYWORDS = Set.of(
            "login", "signin", "sign-in", "sign_in", "auth", "oauth", "token",
            "session", "register", "signup", "sign-up", "sign_up", "password",
            "reset", "verify", "verification", "logout", "signout", "sign-out",
            "sign_out", "mfa", "2fa", "otp", "totp", "sso", "session/refresh",
            "token/refresh", "forgot", "forgot-password", "change-password",
            "change_password", "reset-password", "reset_password");

    // Path keywords indicating authentication/authorization
    private static final Set<String> FINANCIAL_KEYWORDS = Set.of(
            "payment", "pay", "checkout", "cart", "order", "purchase",
            "transfer", "transaction", "billing", "invoice", "refund",
            "subscribe", "subscription", "price", "amount", "charge",
            "withdraw", "deposit", "balance", "wallet", "credit", "debit",
            "coupon", "promo", "discount", "tax", "shipping", "fulfillment");

    // Path keywords for workflow state transitions
    private static final Set<String> WORKFLOW_STEP_KEYWORDS = Set.of(
            "step", "stage", "phase", "wizard", "flow", "process",
            "submit", "confirm", "confirmation", "complete", "done",
            "next", "back", "previous", "continue", "start", "begin",
            "draft", "save", "preview", "review", "approve", "reject",
            "cancel", "undo", "rollback", "retry");

    // Path keywords for CRUD/management
    private static final Set<String> MANAGEMENT_KEYWORDS = Set.of(
            "create", "update", "delete", "remove", "edit", "add",
            "manage", "settings", "profile", "account", "admin",
            "invite", "invitation", "member", "team", "organization",
            "role", "permission", "user", "users", "config", "configuration");

    // Parameter names indicating business-critical data
    private static final Set<String> CRITICAL_PARAM_NAMES = Set.of(
            "amount", "price", "total", "quantity", "role", "permission",
            "user_id", "account_id", "order_id", "payment_id",
            "email", "phone", "address", "password", "ssn", "credit_card",
            "admin", "is_admin", "isadmin", "level", "access_level");

    // Business-relevant path segment keywords
    private static final Set<String> BUSINESS_NOUNS = Set.of(
            "user", "users", "account", "accounts", "order", "orders",
            "product", "products", "payment", "payments", "invoice", "invoices",
            "transaction", "transactions", "customer", "customers",
            "subscription", "subscriptions", "organization", "organizations",
            "team", "teams", "member", "members", "role", "roles",
            "permission", "permissions", "report", "reports", "document",
            "documents", "file", "files", "ticket", "tickets", "message",
            "messages", "notification", "notifications", "item", "items",
            "category", "categories", "address", "addresses", "contact",
            "contacts", "group", "groups", "project", "projects", "task", "tasks");

    /**
     * Check if an HTTP method is state-changing.
     */
    public static boolean isStateChanging(String method) {
        return method != null && STATE_CHANGING_METHODS.contains(method.toUpperCase());
    }

    /**
     * Score a path based on business keyword presence.
     * Higher scores indicate more business-relevant paths.
     */
    public static int scorePath(String path) {
        if (path == null) return 0;
        String lower = path.toLowerCase();
        int score = 0;

        for (String keyword : AUTH_KEYWORDS) {
            if (lower.contains(keyword)) { score += 5; break; }
        }
        for (String keyword : FINANCIAL_KEYWORDS) {
            if (lower.contains(keyword)) { score += 7; break; }
        }
        for (String keyword : WORKFLOW_STEP_KEYWORDS) {
            if (lower.contains(keyword)) { score += 3; break; }
        }
        for (String keyword : MANAGEMENT_KEYWORDS) {
            if (lower.contains(keyword)) { score += 2; break; }
        }
        for (String noun : BUSINESS_NOUNS) {
            if (lower.contains(noun)) { score += 1; break; }
        }

        return score;
    }

    /**
     * Check if a path contains authentication keywords.
     */
    public static boolean isAuthPath(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase();
        for (String keyword : AUTH_KEYWORDS) {
            if (lower.contains(keyword)) return true;
        }
        return false;
    }

    /**
     * Check if a path contains financial keywords.
     */
    public static boolean isFinancialPath(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase();
        for (String keyword : FINANCIAL_KEYWORDS) {
            if (lower.contains(keyword)) return true;
        }
        return false;
    }

    /**
     * Check if a path matches workflow step patterns.
     */
    public static boolean isWorkflowStep(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase();
        for (String keyword : WORKFLOW_STEP_KEYWORDS) {
            if (lower.contains(keyword)) return true;
        }
        return false;
    }

    /**
     * Check if a set of parameter names contains business-critical data.
     */
    public static boolean hasCriticalParameters(Set<String> paramNames) {
        if (paramNames == null) return false;
        for (String name : paramNames) {
            String lower = name.toLowerCase();
            for (String critical : CRITICAL_PARAM_NAMES) {
                if (lower.equals(critical) || lower.endsWith("." + critical)) return true;
            }
        }
        return false;
    }

    /**
     * Check if a parameter name indicates a security-critical value.
     */
    public static boolean isSecurityParameter(String paramName) {
        if (paramName == null) return false;
        String lower = paramName.toLowerCase();
        return lower.contains("token") || lower.contains("csrf") || lower.contains("nonce")
                || lower.contains("secret") || lower.contains("key") || lower.contains("password")
                || lower.contains("auth") || lower.equals("_csrf");
    }
}

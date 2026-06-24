package com.workflowscanner.classification;

import java.util.Set;
import java.util.regex.Pattern;

/**
 * Classifies the semantic kind of a parameter value.
 * Used by ParameterExtractor to determine whether a value is interesting
 * for correlation/edge creation.
 */
public enum ValueKind {
    BUSINESS_ID,
    SECURITY_TOKEN,
    SESSION_TOKEN,
    MONEY,
    EMAIL,
    USERNAME,
    STATUS,
    BOOLEANISH,
    STATIC_CONFIG,
    LOW_ENTROPY,
    UNKNOWN;

    // Known session cookie names (do not create workflow edges from these)
    private static final Set<String> SESSION_COOKIE_NAMES = Set.of(
            "jsessionid", "phpsessid", "connect.sid", "session", "_auth",
            "access_token", "refresh_token", "sid", "token", "auth",
            "awsalb", "lb", "sessionid", "__cfduid");

    // Known business ID parameter name patterns
    private static final Set<String> BUSINESS_ID_NAMES = Set.of(
            "id", "order_id", "orderid", "user_id", "userid", "account_id",
            "accountid", "transaction_id", "transactionid", "payment_id",
            "paymentid", "cart_id", "cartid", "product_id", "productid",
            "customer_id", "customerid", "invoice_id", "invoiceid",
            "resource_id", "resourceid", "object_id", "objectid");

    // Known workflow token parameter names
    private static final Set<String> WORKFLOW_TOKEN_NAMES = Set.of(
            "csrf_token", "csrf", "_csrf", "authenticity_token",
            "checkout_token", "payment_token", "state_token",
            "workflow_token", "step_token", "flow_token",
            "verification_token", "reset_token", "invite_token");

    // Money parameter names
    private static final Set<String> MONEY_NAMES = Set.of(
            "amount", "price", "total", "subtotal", "tax", "shipping",
            "discount", "fee", "charge", "value", "cost", "balance",
            "payment_amount", "order_total", "unit_price", "quantity");

    // Common low-entropy values that should never create edges
    private static final Set<String> LOW_ENTROPY_VALUES = Set.of(
            "true", "false", "null", "none", "undefined", "yes", "no",
            "on", "off", "0", "1", "-1", "en", "en-us", "en_us",
            "dark", "light", "default", "html", "text", "json",
            "application/json", "text/html", "utf-8", "utf8",
            "pending", "active", "inactive", "disabled", "enabled",
            "success", "error", "failed", "ok", "asc", "desc");

    private static final Pattern UUID_PATTERN =
            Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                    Pattern.CASE_INSENSITIVE);
    private static final Pattern HEX_PATTERN =
            Pattern.compile("^[0-9a-f]{8,}$", Pattern.CASE_INSENSITIVE);
    private static final Pattern NUMERIC_PATTERN = Pattern.compile("^\\d+$");
    private static final Pattern DECIMAL_PATTERN = Pattern.compile("^\\d+\\.?\\d*$");
    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");

    /**
     * Classify a parameter value based on its name and value.
     *
     * @param name  parameter name (lowercased)
     * @param value parameter value
     * @return the classified ValueKind
     */
    public static ValueKind classify(String name, String value) {
        if (name == null || value == null || value.isEmpty()) return LOW_ENTROPY;
        String lowerName = name.toLowerCase();
        String lowerValue = value.toLowerCase();

        // Session cookies — not workflow-relevant
        if (SESSION_COOKIE_NAMES.contains(lowerName)) return SESSION_TOKEN;
        if (lowerName.startsWith("cookie.") && SESSION_COOKIE_NAMES.contains(lowerName.replace("cookie.", ""))) {
            return SESSION_TOKEN;
        }

        // Check low-entropy values first
        if (value.length() < 4 || LOW_ENTROPY_VALUES.contains(lowerValue)) return LOW_ENTROPY;
        if (BOOLEANISH_NAMES.contains(lowerName) && (lowerValue.equals("true") || lowerValue.equals("false") || lowerValue.equals("0") || lowerValue.equals("1"))) {
            return BOOLEANISH;
        }

        // Money
        if (MONEY_NAMES.contains(lowerName)) return MONEY;
        if (lowerName.contains("price") || lowerName.contains("amount") || lowerName.contains("total")) {
            if (DECIMAL_PATTERN.matcher(value).matches()) return MONEY;
        }

        // Email
        if (EMAIL_PATTERN.matcher(value).matches()) return EMAIL;

        // Business ID patterns
        if (BUSINESS_ID_NAMES.contains(lowerName)) return BUSINESS_ID;
        if (lowerName.endsWith("_id") || lowerName.endsWith("id")) return BUSINESS_ID;
        if (NUMERIC_PATTERN.matcher(value).matches() && value.length() >= 4) return BUSINESS_ID;
        if (UUID_PATTERN.matcher(value).matches()) return BUSINESS_ID;
        if (HEX_PATTERN.matcher(value).matches() && value.length() >= 8) return BUSINESS_ID;

        // Workflow/security tokens
        if (WORKFLOW_TOKEN_NAMES.contains(lowerName)) return SECURITY_TOKEN;
        if (lowerName.contains("token") || lowerName.contains("csrf") || lowerName.contains("nonce")) {
            return SECURITY_TOKEN;
        }

        // Status values
        if (STATUS_NAMES.contains(lowerName)) return STATUS;

        // Static config
        if (STATIC_CONFIG_NAMES.contains(lowerName)) return STATIC_CONFIG;

        return UNKNOWN;
    }

    /**
     * Whether this value kind should create graph edges via parameter reuse.
     */
    public boolean isCorrelationRelevant() {
        return this == BUSINESS_ID || this == SECURITY_TOKEN || this == MONEY || this == EMAIL;
    }

    /**
     * Whether this value kind represents a business-relevant value flow.
     * Broader than correlation: includes USERNAME, STATUS, and UNKNOWN
     * (which may carry domain-specific meaning), but excludes SESSION_TOKEN,
     * BOOLEANISH, STATIC_CONFIG, and LOW_ENTROPY.
     */
    public boolean isBusinessValue() {
        return this == BUSINESS_ID || this == SECURITY_TOKEN || this == MONEY
                || this == EMAIL || this == USERNAME || this == STATUS
                || this == UNKNOWN;
    }

    private static final Set<String> BOOLEANISH_NAMES = Set.of(
            "active", "enabled", "disabled", "visible", "show", "hide",
            "required", "optional", "readonly", "read_only", "checked",
            "selected", "has_more", "hasmore", "archived", "locked");

    private static final Set<String> STATUS_NAMES = Set.of(
            "status", "state", "phase", "stage", "mode", "result",
            "outcome", "level", "priority", "type", "kind", "category");

    private static final Set<String> STATIC_CONFIG_NAMES = Set.of(
            "version", "locale", "language", "lang", "theme", "timezone",
            "tz", "format", "layout", "view", "template", "source",
            "platform", "environment", "env", "channel", "tab", "section");
}

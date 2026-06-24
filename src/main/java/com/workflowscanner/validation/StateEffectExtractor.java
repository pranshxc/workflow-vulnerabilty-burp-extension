package com.workflowscanner.validation;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Lightweight business-state extractor. Given two response bodies (before
 * and after a validation test), produces a {@link StateCheck} that records
 * what business surface area actually changed: new identifiers, changed
 * field values, success markers, and cross-tenant access markers.
 *
 * <p>The extractor deliberately avoids full JSON / HTML parsing. Instead it
 * uses targeted regexes for high-signal fields that show up in most
 * production APIs. The point is to upgrade a {@code PROBABLE} similarity
 * finding to a {@code CONFIRMED} business-effect finding when there is
 * concrete evidence; this is not a full AST analysis.
 */
public final class StateEffectExtractor {

    // Common business-identifier keys we care about
    private static final Set<String> BUSINESS_ID_KEYS = Set.of(
            "id", "order_id", "orderid", "user_id", "userid", "account_id",
            "accountid", "transaction_id", "transactionid", "payment_id",
            "paymentid", "cart_id", "cartid", "product_id", "productid",
            "customer_id", "customerid", "invoice_id", "invoiceid",
            "resource_id", "resourceid", "object_id", "objectid", "ref",
            "reference", "ticket", "ticket_id", "case_id", "session_id");

    // Common status / state keys
    private static final Set<String> STATUS_KEYS = Set.of(
            "status", "state", "phase", "stage", "result", "outcome",
            "approved", "verified", "confirmed", "completed", "settled",
            "active", "enabled", "role");

    // High-signal success markers
    private static final Set<String> SUCCESS_MARKER_KEYWORDS = Set.of(
            "order confirmed", "payment approved", "payment received",
            "order placed", "transaction successful", "subscription active",
            "role updated to admin", "role changed to admin", "access granted",
            "verification complete", "approved successfully", "request approved");

    // Cross-tenant / IDOR access markers
    private static final Set<String> ACCESS_MARKER_KEYWORDS = Set.of(
            "another user's", "not your account", "permission denied",
            "unauthorized access", "cross-tenant");

    // Pattern: "key": "value" or "key":"value" — value is a quoted string
    // Capture group 1 = key (without quotes), group 2 = value
    private static final Pattern QUOTED_FIELD = Pattern.compile(
            "\"?([A-Za-z_][A-Za-z0-9_\\-]{0,40})\"?\\s*[:=]\\s*\"([^\"]{1,200})\"");

    /**
     * Compare two response bodies and produce a {@link StateCheck} describing
     * what changed. The check itself reports whether any concrete effect
     * was observed via {@link StateCheck#isEffectObserved()}.
     */
    public static StateCheck diff(String followUpUrl, int beforeStatus, String beforeBody,
                                  int afterStatus, String afterBody) {
        StateCheck check = new StateCheck(followUpUrl, beforeStatus, afterStatus);

        Set<String> beforeIds = extractIds(beforeBody);
        Set<String> afterIds = extractIds(afterBody);
        if (!afterIds.isEmpty()) {
            Set<String> newIds = new LinkedHashSet<>(afterIds);
            newIds.removeAll(beforeIds);
            check.getNewIds().addAll(newIds);
        }

        // Field-by-field change detection for status / money / role / etc.
        if (beforeBody != null && afterBody != null) {
            for (String key : collectKeys(beforeBody, afterBody)) {
                String beforeValue = firstValueOf(beforeBody, key);
                String afterValue = firstValueOf(afterBody, key);
                if (beforeValue == null || afterValue == null) continue;
                if (beforeValue.equals(afterValue)) continue;
                if (BUSINESS_ID_KEYS.contains(key.toLowerCase(Locale.ROOT))
                        || STATUS_KEYS.contains(key.toLowerCase(Locale.ROOT))) {
                    check.getChangedFields().add(key + ":" + beforeValue + "->" + afterValue);
                }
            }
        }

        // Success / access markers
        String afterLower = afterBody != null ? afterBody.toLowerCase(Locale.ROOT) : "";
        for (String marker : SUCCESS_MARKER_KEYWORDS) {
            if (afterLower.contains(marker)) {
                check.getSuccessMarkers().add(marker);
            }
        }
        for (String marker : ACCESS_MARKER_KEYWORDS) {
            if (afterLower.contains(marker)) {
                check.getAccessMarkers().add(marker);
            }
        }

        return check;
    }

    /**
     * Pull identifier-like values out of a response body. Used to detect
     * "a new id appeared in the test response that wasn't in the original".
     * The matcher is intentionally permissive — we just collect quoted
     * values for known id keys.
     */
    static Set<String> extractIds(String body) {
        Set<String> ids = new LinkedHashSet<>();
        if (body == null) return ids;
        Matcher m = QUOTED_FIELD.matcher(body);
        while (m.find()) {
            String key = m.group(1).toLowerCase(Locale.ROOT);
            if (BUSINESS_ID_KEYS.contains(key)) {
                ids.add(m.group(2));
            }
        }
        return ids;
    }

    private static Set<String> collectKeys(String a, String b) {
        Set<String> keys = new LinkedHashSet<>();
        collectKeysInto(a, keys);
        collectKeysInto(b, keys);
        return keys;
    }

    private static void collectKeysInto(String body, Set<String> out) {
        if (body == null) return;
        Matcher m = QUOTED_FIELD.matcher(body);
        while (m.find()) {
            out.add(m.group(1));
        }
    }

    private static String firstValueOf(String body, String key) {
        if (body == null) return null;
        // Look for "key": "value" or "key":"value" with optional whitespace
        Pattern p = Pattern.compile(
                "\"?\\b" + java.util.regex.Pattern.quote(key) + "\"?\\s*[:=]\\s*\"([^\"]+)\"");
        Matcher m = p.matcher(body);
        return m.find() ? m.group(1) : null;
    }
}

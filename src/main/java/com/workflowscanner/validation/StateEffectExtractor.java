package com.workflowscanner.validation;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
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
 *
 * <p><b>Reliability rules (validation rework follow-up):</b>
 * <ul>
 *   <li>Success markers are only added when they newly appear in the
 *       after-body. A success string that already exists in the
 *       before-body is not evidence of a new effect.</li>
 *   <li>Access markers are limited to positive signals (we reached
 *       another user's resource). Failure messages like "permission
 *       denied" or "unauthorized access" are inverted and would falsely
 *       promote a denied attempt — they are deliberately excluded.</li>
 *   <li>Numeric and boolean values are extracted as well as quoted
 *       strings, so business fields like {@code amount}, {@code quantity}
 *       and {@code approved} are visible in the diff.</li>
 *   <li>Callers should pair this with a fresh before/after fetch (see
 *       {@link ValidationEngine#validateStateEffects}) — the diff itself
 *       is only as good as the baseline it is given.</li>
 * </ul>
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

    // High-signal business-numeric keys: changes in these almost always
    // represent a real state change (price, balance, quantity, etc.).
    private static final Set<String> NUMERIC_BUSINESS_KEYS = Set.of(
            "amount", "price", "total", "subtotal", "balance", "credit",
            "debit", "discount", "quantity", "qty", "count", "score",
            "limit", "fee", "tax", "tip");

    // High-signal success markers. Only added when the marker newly
    // appears in the after-body, never when it was already there.
    private static final Set<String> SUCCESS_MARKER_KEYWORDS = Set.of(
            "order confirmed", "payment approved", "payment received",
            "order placed", "transaction successful", "subscription active",
            "role updated to admin", "role changed to admin", "access granted",
            "verification complete", "approved successfully", "request approved",
            "thank you for your order", "your order has been placed",
            "checkout complete", "payment successful");

    // Positive cross-tenant / IDOR access markers. These indicate the
    // test reached another user's resource, which is the strong IDOR
    // signal. Deliberately excludes failure-like strings such as
    // "permission denied" or "unauthorized access" — those would
    // indicate a failed attempt, not a successful cross-tenant read.
    private static final Set<String> ACCESS_MARKER_KEYWORDS = Set.of(
            "another user's", "owned by", "belongs to",
            "account owner", "customer details",
            "billing address", "organization_id", "tenant_id");

    // Pattern: "key": "value" or "key":"value" — value is a quoted string
    // Capture group 1 = key (without quotes), group 2 = value
    private static final Pattern QUOTED_FIELD = Pattern.compile(
            "\"?([A-Za-z_][A-Za-z0-9_\\-]{0,40})\"?\\s*[:=]\\s*\"([^\"]{1,200})\"");

    // Pattern: "key": <scalar> where <scalar> is numeric, boolean, or null
    // Capture group 1 = key, group 2 = raw scalar literal
    private static final Pattern SCALAR_FIELD = Pattern.compile(
            "\"?([A-Za-z_][A-Za-z0-9_\\-]{0,40})\"?\\s*[:=]\\s*"
                    + "(-?\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?|true|false|null)\\b");

    // Maximum body bytes fed into the regex passes. Beyond this we
    // truncate; we only need a representative sample for the diff.
    private static final int MAX_BODY_BYTES = 200_000;

    /**
     * Compare two response bodies and produce a {@link StateCheck} describing
     * what changed. The check itself reports whether any concrete effect
     * was observed via {@link StateCheck#isEffectObserved()}.
     */
    public static StateCheck diff(String followUpUrl, int beforeStatus, String beforeBody,
                                  int afterStatus, String afterBody) {
        StateCheck check = new StateCheck(followUpUrl, beforeStatus, afterStatus);

        beforeBody = safeBody(beforeBody);
        afterBody = safeBody(afterBody);

        Set<String> beforeIds = extractIds(beforeBody);
        Set<String> afterIds = extractIds(afterBody);
        if (!afterIds.isEmpty()) {
            Set<String> newIds = new LinkedHashSet<>(afterIds);
            newIds.removeAll(beforeIds);
            check.getNewIds().addAll(newIds);
        }

        // Field-by-field change detection for status / business-id / numeric keys.
        if (beforeBody != null && afterBody != null) {
            for (String key : collectKeys(beforeBody, afterBody)) {
                String beforeValue = firstValueOf(beforeBody, key);
                String afterValue = firstValueOf(afterBody, key);
                if (beforeValue == null || afterValue == null) continue;
                if (beforeValue.equals(afterValue)) continue;
                String lower = key.toLowerCase(Locale.ROOT);
                if (BUSINESS_ID_KEYS.contains(lower)
                        || STATUS_KEYS.contains(lower)
                        || NUMERIC_BUSINESS_KEYS.contains(lower)) {
                    check.getChangedFields().add(key + ":" + beforeValue + "->" + afterValue);
                }
            }
        }

        // Success markers: only count newly appeared ones. A success
        // string that was already in the before-body is not new
        // evidence.
        String beforeLower = beforeBody != null ? beforeBody.toLowerCase(Locale.ROOT) : "";
        String afterLower = afterBody != null ? afterBody.toLowerCase(Locale.ROOT) : "";
        for (String marker : SUCCESS_MARKER_KEYWORDS) {
            String m = marker.toLowerCase(Locale.ROOT);
            if (afterLower.contains(m) && !beforeLower.contains(m)) {
                check.getSuccessMarkers().add(marker);
            }
        }
        // Access markers: only count newly appeared ones. Same rule.
        for (String marker : ACCESS_MARKER_KEYWORDS) {
            String m = marker.toLowerCase(Locale.ROOT);
            if (afterLower.contains(m) && !beforeLower.contains(m)) {
                check.getAccessMarkers().add(marker);
            }
        }

        return check;
    }

    /**
     * Pull identifier-like values out of a response body. Used to detect
     * "a new id appeared in the test response that wasn't in the original".
     * Matches both quoted-string values and numeric ids, so e.g.
     * {@code "id": 1234} is captured alongside {@code "id": "abc"}.
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
        Matcher n = SCALAR_FIELD.matcher(body);
        while (n.find()) {
            String key = n.group(1).toLowerCase(Locale.ROOT);
            String value = n.group(2);
            if (BUSINESS_ID_KEYS.contains(key) && !"null".equals(value)) {
                ids.add(value);
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
        Matcher n = SCALAR_FIELD.matcher(body);
        while (n.find()) {
            out.add(n.group(1));
        }
    }

    private static String firstValueOf(String body, String key) {
        if (body == null) return null;
        // Try quoted-string form first, then scalar form.
        Pattern pQ = Pattern.compile(
                "\"?\\b" + java.util.regex.Pattern.quote(key) + "\"?\\s*[:=]\\s*\"([^\"]+)\"");
        Matcher mQ = pQ.matcher(body);
        if (mQ.find()) return mQ.group(1);
        Pattern pS = Pattern.compile(
                "\"?\\b" + java.util.regex.Pattern.quote(key) + "\"?\\s*[:=]\\s*"
                        + "(-?\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?|true|false|null)\\b");
        Matcher mS = pS.matcher(body);
        return mS.find() ? mS.group(1) : null;
    }

    private static String safeBody(String body) {
        if (body == null) return null;
        if (body.length() <= MAX_BODY_BYTES) return body;
        return body.substring(0, MAX_BODY_BYTES);
    }

    // Suppress unused warning for URLDecoder import; this is here so the
    // scalar extraction path stays consistent if a future caller wants
    // to add percent-decoded value comparison.
    @SuppressWarnings("unused")
    private static String decode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return s;
        }
    }
}

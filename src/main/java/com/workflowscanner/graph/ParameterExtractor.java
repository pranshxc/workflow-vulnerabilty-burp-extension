package com.workflowscanner.graph;

import com.workflowscanner.classification.ValueKind;
import com.workflowscanner.data.CapturedRequest;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts parameters and interesting values from requests and responses.
 * Used by the graph builder for parameter reuse and response correlation detection.
 *
 * Extracts from requests:
 * - Query string parameters
 * - Form body parameters (application/x-www-form-urlencoded)
 * - JSON body fields (recursive)
 * - URL path segments
 *
 * Extracts from responses:
 * - JSON field values (recursive)
 * - Set-Cookie values
 * - HTML hidden form field values
 * - Location header (for redirects)
 */
public class ParameterExtractor {

    /** Minimum value length to consider "interesting" (avoids false positives on "1", "true", etc.) */
    public static final int MIN_VALUE_LENGTH = 4;

    /**
     * Pattern to match individual <input> blocks, extracting type, name, and value
     * from each block independently. Handles attribute reordering better than
     * separate name/value regex passes.
     */
    private static final Pattern INPUT_BLOCK_PATTERN =
            Pattern.compile("<input\\s[^>]*type=[\"']hidden[\"'][^>]*/?>",
                    Pattern.CASE_INSENSITIVE);

    private static final Pattern INPUT_TYPE_PATTERN =
            Pattern.compile("type=[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);

    private static final Pattern INPUT_NAME_PATTERN =
            Pattern.compile("name=[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);

    private static final Pattern INPUT_VALUE_PATTERN =
            Pattern.compile("value=[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);

    /**
     * Extract all parameters from a request.
     * Returns a map of param_name -> param_value.
     */
    public static Map<String, Object> extractRequestParams(CapturedRequest request) {
        Map<String, Object> params = new HashMap<>();

        // 1. Query parameters
        if (request.getQueryParams() != null) {
            params.putAll(request.getQueryParams());
        }

        // 2. Form body parameters
        String contentType = request.getContentType();
        String body = request.getRequestBody();
        if (body != null && !body.isEmpty()) {
            if (contentType != null && contentType.contains("application/x-www-form-urlencoded")) {
                params.putAll(parseFormBody(body));
            } else if (contentType != null && contentType.contains("application/json")) {
                params.putAll(parseJsonBody(body, "req."));
            } else {
                // Try JSON parsing anyway (some requests don't set content-type correctly)
                try {
                    if (body.trim().startsWith("{") || body.trim().startsWith("[")) {
                        params.putAll(parseJsonBody(body, "req."));
                    }
                } catch (Exception ignored) {}
            }
        }

        // 3. URL path segments (potential IDs)
        if (request.getPath() != null) {
            String[] segments = request.getPath().split("/");
            for (int i = 0; i < segments.length; i++) {
                String seg = segments[i];
                if (seg != null && !seg.isEmpty() && seg.length() >= MIN_VALUE_LENGTH) {
                    params.put("path_segment_" + i, seg);
                }
            }
        }

        // 4. Cookie values
        if (request.getCookies() != null) {
            for (String cookie : request.getCookies()) {
                int eqIdx = cookie.indexOf('=');
                if (eqIdx > 0) {
                    String name = cookie.substring(0, eqIdx).trim();
                    String value = cookie.substring(eqIdx + 1).trim();
                    if (value.length() >= MIN_VALUE_LENGTH) {
                        params.put("cookie." + name, value);
                    }
                }
            }
        }

        return params;
    }

    /**
     * Extract interesting values from a response.
     * Returns a map of key -> value for values that might be reused in subsequent requests.
     */
    public static Map<String, Object> extractResponseData(CapturedRequest request) {
        Map<String, Object> data = new HashMap<>();

        // 1. Location header (for redirect detection)
        String location = getHeaderValue(request.getResponseHeaders(), "Location");
        if (location != null) {
            data.put("Location", location);
        }

        // 2. Set-Cookie values
        List<String> setCookies = getHeaderValues(request.getResponseHeaders(), "Set-Cookie");
        if (setCookies != null) {
            for (String setCookie : setCookies) {
                int eqIdx = setCookie.indexOf('=');
                if (eqIdx > 0) {
                    String name = setCookie.substring(0, eqIdx).trim();
                    String value = setCookie.substring(eqIdx + 1);
                    // Remove attributes after semicolon
                    int semiIdx = value.indexOf(';');
                    if (semiIdx > 0) value = value.substring(0, semiIdx);
                    value = value.trim();
                    if (value.length() >= MIN_VALUE_LENGTH) {
                        data.put("set-cookie." + name, value);
                    }
                }
            }
        }

        // 3. JSON response body
        String responseBody = request.getResponseBody();
        if (responseBody != null && !responseBody.isEmpty()) {
            String mimeType = request.getMimeType();
            if ((mimeType != null && mimeType.contains("json"))
                    || responseBody.trim().startsWith("{") || responseBody.trim().startsWith("[")) {
                try {
                    data.putAll(parseJsonBody(responseBody, "resp."));
                } catch (Exception ignored) {}
            }

            // 4. HTML hidden form fields
            if (mimeType != null && mimeType.contains("html")) {
                data.putAll(extractHiddenFields(responseBody));
            }
        }

        return data;
    }

    /**
     * Get all "interesting" values from a map (values meeting minimum length and kind criteria).
     * Uses ValueKind classification to filter out session cookies, booleans, enums, etc.
     */
    public static Set<String> getInterestingValues(Map<String, Object> params) {
        Set<String> values = new HashSet<>();
        for (Map.Entry<String, Object> entry : params.entrySet()) {
            Object value = entry.getValue();
            if (value != null) {
                String strValue = value.toString();
                if (strValue.length() >= MIN_VALUE_LENGTH && !isCommonValue(strValue)) {
                    values.add(strValue);
                }
            }
        }
        return values;
    }

    /**
     * Check if a specific (name, value) pair should create a graph correlation edge.
     * Uses ValueKind classification to filter — only business IDs, security tokens,
     * money amounts, and emails produce edges. Session cookies, booleans, enums,
     * and static config values do not.
     */
    public static boolean isInterestingCorrelationValue(String name, String value) {
        if (name == null || value == null || value.length() < MIN_VALUE_LENGTH) return false;
        ValueKind kind = ValueKind.classify(name, value);
        return kind.isCorrelationRelevant();
    }

    // --- Internal Parsing Methods ---

    private static Map<String, String> parseFormBody(String body) {
        Map<String, String> params = new HashMap<>();
        String[] pairs = body.split("&");
        for (String pair : pairs) {
            int eqIdx = pair.indexOf('=');
            if (eqIdx > 0) {
                try {
                    String name = URLDecoder.decode(pair.substring(0, eqIdx), StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(pair.substring(eqIdx + 1), StandardCharsets.UTF_8);
                    params.put(name, value);
                } catch (Exception e) {
                    // Malformed param, skip
                }
            }
        }
        return params;
    }

    private static Map<String, Object> parseJsonBody(String body, String prefix) {
        Map<String, Object> params = new HashMap<>();
        try {
            JsonElement element = JsonParser.parseString(body);
            flattenJson(element, prefix, params, 0);
        } catch (Exception ignored) {
            // Not valid JSON
        }
        return params;
    }

    private static void flattenJson(JsonElement element, String prefix,
                                     Map<String, Object> result, int depth) {
        if (depth > 5) return; // Prevent deep recursion

        if (element.isJsonObject()) {
            JsonObject obj = element.getAsJsonObject();
            for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
                flattenJson(entry.getValue(), prefix + entry.getKey(), result, depth + 1);
            }
        } else if (element.isJsonArray()) {
            JsonArray arr = element.getAsJsonArray();
            for (int i = 0; i < Math.min(arr.size(), 20); i++) { // Cap array iteration
                flattenJson(arr.get(i), prefix + "[" + i + "]", result, depth + 1);
            }
        } else if (element.isJsonPrimitive()) {
            JsonPrimitive prim = element.getAsJsonPrimitive();
            if (prim.isString()) {
                result.put(prefix, prim.getAsString());
            } else if (prim.isNumber()) {
                result.put(prefix, prim.getAsString());
            }
        }
    }

    /**
     * Extract hidden form fields from HTML using per-input-block regex.
     * Handles attribute reordering better than separate name/value passes.
     * Each <input> block is matched independently, then name and value are
     * extracted from within that block.
     */
    private static Map<String, Object> extractHiddenFields(String html) {
        Map<String, Object> fields = new HashMap<>();
        Matcher blockMatcher = INPUT_BLOCK_PATTERN.matcher(html);

        while (blockMatcher.find()) {
            String inputBlock = blockMatcher.group();

            // Confirm type="hidden" (double-check)
            Matcher typeMatcher = INPUT_TYPE_PATTERN.matcher(inputBlock);
            if (!typeMatcher.find() || !"hidden".equalsIgnoreCase(typeMatcher.group(1))) continue;

            // Extract name
            Matcher nameMatcher = INPUT_NAME_PATTERN.matcher(inputBlock);
            String name = nameMatcher.find() ? nameMatcher.group(1) : null;

            // Extract value
            Matcher valueMatcher = INPUT_VALUE_PATTERN.matcher(inputBlock);
            String value = valueMatcher.find() ? valueMatcher.group(1) : null;

            if (name != null && value != null && value.length() >= MIN_VALUE_LENGTH) {
                fields.put("hidden." + name, value);
            }
        }
        return fields;
    }

    private static String getHeaderValue(Map<String, List<String>> headers, String name) {
        if (headers == null) return null;
        List<String> values = headers.get(name);
        if (values != null && !values.isEmpty()) return values.get(0);
        // Case-insensitive fallback
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name) && !entry.getValue().isEmpty()) {
                return entry.getValue().get(0);
            }
        }
        return null;
    }

    private static List<String> getHeaderValues(Map<String, List<String>> headers, String name) {
        if (headers == null) return null;
        List<String> values = headers.get(name);
        if (values != null) return values;
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name)) {
                return entry.getValue();
            }
        }
        return null;
    }

    /**
     * Check if a value is too common to be useful for correlation.
     */
    private static boolean isCommonValue(String value) {
        String lower = value.toLowerCase();
        return lower.equals("true") || lower.equals("false")
                || lower.equals("null") || lower.equals("none")
                || lower.equals("undefined") || lower.equals("text/html")
                || lower.equals("application/json") || lower.equals("utf-8");
    }
}

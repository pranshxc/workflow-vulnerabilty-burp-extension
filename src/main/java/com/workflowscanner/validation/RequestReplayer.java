package com.workflowscanner.validation;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpRequestResponse;

import com.workflowscanner.data.CapturedRequest;
import com.workflowscanner.graph.RequestNode;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;

import java.util.Map;
import java.util.Set;

/**
 * Replays HTTP requests through Burp's API with optional modifications.
 * Uses api.http().sendRequest() to respect upstream proxies, SSL settings, etc.
 *
 * <p><b>Auth-preserving skip mode (workflow rework):</b>
 * When freshSession=true, only workflow-state tokens (CSRF, step tokens, nonce, etc.)
 * are stripped — auth cookies and session cookies are preserved so step-skipping
 * tests work without breaking authentication.</p>
 */
public class RequestReplayer {

    /**
     * Headers to strip in freshSession mode.
     * Only workflow-state tokens are removed — auth/session cookies preserved.
     */
    private static final Set<String> WORKFLOW_STATE_HEADERS = Set.of(
            "x-csrf-token", "x-xsrf-token", "csrf-token", "csrf",
            "x-requested-with", "x-http-method-override");

    /**
     * Cookie name prefixes for workflow-state tokens (to strip in fresh session).
     */
    private static final Set<String> WORKFLOW_STATE_COOKIE_PREFIXES = Set.of(
            "csrf", "xsrf", "x-csrf", "x-xsrf", "nonce", "state", "step",
            "_csrf", "authenticity_token");

    private final MontoyaApi api;
    private final ExtensionLogger logger;

    public RequestReplayer(MontoyaApi api, ExtensionLogger logger) {
        this.api = api;
        this.logger = logger;
    }

    /**
     * Replay a request from a graph node, optionally with modifications.
     *
     * @param node          The original node to replay
     * @param modifications Parameter modifications (name -> new value), or null
     * @param freshSession  If true, strip ONLY workflow-state tokens (preserve auth).
     *                      This is different from "strip everything" — it allows
     *                      step-skipping tests to work without breaking auth.
     * @return The response, or null on failure
     */
    public ReplayResponse replay(RequestNode node, Map<String, String> modifications,
                                  boolean freshSession) {
        CapturedRequest captured = node.getRequest();
        if (captured == null || captured.getUrl() == null) {
            logger.log(LogCategory.ANALYSIS, LogLevel.WARN, "RequestReplayer",
                    "Cannot replay: node has no captured request data.");
            return null;
        }

        try {
            // Build the request
            String url = captured.getUrl();
            String method = captured.getMethod() != null ? captured.getMethod() : "GET";
            String body = captured.getRequestBody();

            // Apply modifications to body
            if (modifications != null && body != null) {
                for (Map.Entry<String, String> mod : modifications.entrySet()) {
                    body = applyModification(body, mod.getKey(), mod.getValue(),
                            captured.getContentType());
                }
            }

            // Apply modifications to URL query params
            if (modifications != null) {
                for (Map.Entry<String, String> mod : modifications.entrySet()) {
                    if (url.contains(mod.getKey() + "=")) {
                        url = url.replaceAll(
                                mod.getKey() + "=[^&]*",
                                mod.getKey() + "=" + mod.getValue());
                        // Also handle encoded variant
                        url = url.replaceAll(
                                mod.getKey() + "%3D[^&]*",
                                mod.getKey() + "%3D" + mod.getValue());
                    }
                }
            }

            // Build Burp HttpRequest
            HttpRequest request = HttpRequest.httpRequest(url);
            request = request.withMethod(method);

            // Add headers
            if (captured.getRequestHeaders() != null) {
                for (Map.Entry<String, java.util.List<String>> header :
                        captured.getRequestHeaders().entrySet()) {
                    String headerName = header.getKey();

                    // Skip pseudo-headers and connection headers
                    if (headerName.startsWith(":") || headerName.equalsIgnoreCase("Host")
                            || headerName.equalsIgnoreCase("Content-Length")) {
                        continue;
                    }

                    // Fresh session: strip only workflow-state tokens
                    if (freshSession) {
                        String lower = headerName.toLowerCase();

                        // Strip workflow-state / CSRF headers (but NOT auth/session)
                        if (WORKFLOW_STATE_HEADERS.contains(lower)) {
                            continue;
                        }

                        // Strip only workflow-state cookies (preserve session/auth)
                        if (lower.equals("cookie")) {
                            for (String value : header.getValue()) {
                                String filteredCookie = filterWorkflowCookies(value);
                                if (filteredCookie != null && !filteredCookie.isEmpty()) {
                                    request = request.withAddedHeader(headerName, filteredCookie);
                                }
                            }
                            continue; // Already handled all values
                        }
                    }

                    for (String value : header.getValue()) {
                        request = request.withAddedHeader(headerName, value);
                    }
                }
            }

            // Add body
            if (body != null && !body.isEmpty()) {
                request = request.withBody(body);
            }

            logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "RequestReplayer",
                    "Replaying: " + method + " " + url
                            + (freshSession ? " [auth-preserving skip mode]" : "")
                            + (modifications != null ? " [" + modifications.size() + " mods]" : ""));

            // Send through Burp
            HttpRequestResponse result = api.http().sendRequest(request);
            HttpResponse response = result.response();

            if (response == null) {
                logger.log(LogCategory.ANALYSIS, LogLevel.WARN, "RequestReplayer",
                        "No response received for replay.");
                return null;
            }

            ReplayResponse replayResponse = new ReplayResponse();
            replayResponse.statusCode = response.statusCode();
            try {
                replayResponse.body = response.bodyToString();
            } catch (Exception e) {
                replayResponse.body = "";
            }

            logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "RequestReplayer",
                    "Replay response: " + replayResponse.statusCode
                            + " (" + (replayResponse.body != null ? replayResponse.body.length() : 0) + " bytes)");

            return replayResponse;

        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "RequestReplayer",
                    "Replay failed.", e);
            return null;
        }
    }

    /**
     * Filter out workflow-state cookies from a Cookie header value.
     * Preserves auth/session cookies like JSESSIONID, connect.sid, etc.
     */
    private String filterWorkflowCookies(String cookieHeader) {
        if (cookieHeader == null || cookieHeader.isEmpty()) return "";
        StringBuilder filtered = new StringBuilder();
        String[] cookies = cookieHeader.split(";");
        for (String cookie : cookies) {
            String trimmed = cookie.trim();
            if (trimmed.isEmpty()) continue;

            // Check if this is a workflow-state cookie
            boolean isWorkflowState = false;
            String name = trimmed.contains("=") ? trimmed.substring(0, trimmed.indexOf('=')).trim() : trimmed;
            String lowerName = name.toLowerCase();

            for (String prefix : WORKFLOW_STATE_COOKIE_PREFIXES) {
                if (lowerName.startsWith(prefix)) {
                    isWorkflowState = true;
                    break;
                }
            }

            if (!isWorkflowState) {
                if (filtered.length() > 0) filtered.append("; ");
                filtered.append(trimmed);
            }
        }
        return filtered.toString();
    }

    /**
     * Apply a parameter modification to a request body.
     * Supports three body types: JSON, form-encoded, and fallback regex.
     */
    private String applyModification(String body, String paramName, String newValue,
                                      String contentType) {
        if (body == null) return null;

        String ct = contentType != null ? contentType.toLowerCase() : "";

        if (ct.contains("json")) {
            return applyJsonModification(body, paramName, newValue);
        } else if (ct.contains("x-www-form-urlencoded")) {
            return applyFormModification(body, paramName, newValue);
        } else {
            // Try JSON first (some requests don't set content-type correctly)
            String trimmed = body.trim();
            if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
                return applyJsonModification(body, paramName, newValue);
            }
            // Try form body
            if (body.contains(paramName + "=")) {
                return applyFormModification(body, paramName, newValue);
            }
            // Fallback: naive string replacement
            return body.replaceAll(paramName, newValue);
        }
    }

    /**
     * Apply a modification to a JSON body.
     * Handles: "key": "value", "key": 123, "key": ["value"], nested "path.to.key".
     */
    private String applyJsonModification(String body, String paramName, String newValue) {
        String modified = body;

        // Handle nested paths: "user.address.city" -> replace at the deepest level
        String[] pathParts = paramName.split("\\.");
        String key = pathParts[pathParts.length - 1];

        // Try quoted string value first: "key": "value"
        String pattern = "\"" + key + "\"\\s*:\\s*\"[^\"]*\"";
        String replacement = "\"" + key + "\": \"" + newValue + "\"";
        modified = modified.replaceAll(pattern, replacement);

        // If no match, try numeric value: "key": 123
        if (modified.equals(body)) {
            pattern = "\"" + key + "\"\\s*:\\s*[0-9.]+(?:[eE][+-]?\\d+)?";
            replacement = "\"" + key + "\": " + newValue;
            modified = modified.replaceAll(pattern, replacement);
        }

        // If no match, try boolean/null: "key": true/false/null
        if (modified.equals(body)) {
            pattern = "\"" + key + "\"\\s*:\\s*(?:true|false|null)";
            replacement = "\"" + key + "\": " + newValue;
            modified = modified.replaceAll(pattern, replacement);
        }

        // If no match, try array value: "key": ["value", ...]
        if (modified.equals(body)) {
            pattern = "\"" + key + "\"\\s*:\\s*\\[[^\\]]*\\]";
            replacement = "\"" + key + "\": [\"" + newValue + "\"]";
            modified = modified.replaceAll(pattern, replacement);
        }

        return modified;
    }

    /**
     * Apply a modification to a form-encoded body.
     * Handles: key=value, key=value&key2=value2, URL-encoded values.
     */
    private String applyFormModification(String body, String paramName, String newValue) {
        // Replace paramName=encodedValue or paramName=value
        String modified = body.replaceAll(
                "(?<=^|&)" + paramName + "=[^&]*",
                paramName + "=" + newValue);

        // Also try URL-encoded form (when already decoded)
        if (modified.equals(body)) {
            modified = body.replaceAll(
                    "(?<=^|&)" + java.net.URLEncoder.encode(paramName, java.nio.charset.StandardCharsets.UTF_8) + "=[^&]*",
                    java.net.URLEncoder.encode(paramName, java.nio.charset.StandardCharsets.UTF_8) + "=" + newValue);
        }

        return modified;
    }

    /**
     * Simple response container from a replay.
     */
    public static class ReplayResponse {
        public int statusCode;
        public String body;
    }
}

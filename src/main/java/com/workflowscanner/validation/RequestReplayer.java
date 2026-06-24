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

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Replays HTTP requests through Burp's API with optional modifications.
 * Uses api.http().sendRequest() to respect upstream proxies, SSL settings, etc.
 *
 * <p><b>Auth-preserving skip mode (workflow rework):</b>
 * When freshSession=true, only workflow-state tokens (CSRF, step tokens, nonce, etc.)
 * are stripped — auth cookies and session cookies are preserved so step-skipping
 * tests work without breaking authentication.</p>
 *
 * <p><b>Safer mutation (validation rework):</b>
 * Parameter names and replacement values are passed through
 * {@link Pattern#quote} and {@link Matcher#quoteReplacement} so a value
 * containing regex metacharacters (e.g. {@code $1}, {@code \}, {@code .})
 * cannot break the replacement. Each modification is tracked as a
 * {@link MutationResult} so the caller can verify the parameter was
 * actually present and changed before treating the replay as meaningful.
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
        return replay(node, modifications, freshSession, null);
    }

    /**
     * Replay a request with mutation tracking. When {@code mutationSink} is
     * non-null, each parameter modification is recorded as a
     * {@link MutationResult} in the sink so the caller can verify which
     * parameters were actually changed before interpreting the response.
     */
    public ReplayResponse replay(RequestNode node, Map<String, String> modifications,
                                  boolean freshSession, List<MutationResult> mutationSink) {
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
            String originalUrl = url;
            String originalBody = body;

            // Apply modifications to body and URL, tracking each one.
            if (modifications != null) {
                for (Map.Entry<String, String> mod : modifications.entrySet()) {
                    String paramName = mod.getKey();
                    String newValue = mod.getValue();

                    // Body modification first
                    if (body != null) {
                        MutationResult bodyResult = applyBodyMutationTracking(
                                body, paramName, newValue, captured.getContentType());
                        if (bodyResult != null) {
                            if (mutationSink != null) mutationSink.add(bodyResult);
                            if (bodyResult.isApplied()) {
                                body = replaceTracked(body, bodyResult, paramName, newValue);
                            }
                        }
                    }

                    // Then URL query mutation
                    if (url != null) {
                        MutationResult urlResult = applyQueryMutationTracking(url, paramName, newValue);
                        if (urlResult != null) {
                            if (mutationSink != null) mutationSink.add(urlResult);
                            if (urlResult.isApplied()) {
                                url = replaceTracked(url, urlResult, paramName, newValue);
                            }
                        }
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
     * Apply the actual string replacement that the corresponding
     * MutationResult reported as applied. Centralised here so the
     * "did the mutation happen?" check and the "now actually do it" step
     * use identical regexes and replacements.
     */
    private String replaceTracked(String source, MutationResult result,
                                   String paramName, String newValue) {
        // We re-run the same logic that produced the MutationResult.
        // Both must be kept in sync; this is a deliberate coupling so
        // an "applied" claim cannot be a lie.
        if (result.getLocation() == MutationResult.Location.QUERY) {
            String replaced = applyQueryReplacement(source, paramName, newValue,
                    result.getOldValue());
            return replaced != null ? replaced : source;
        }
        if (result.getLocation() == MutationResult.Location.JSON_BODY) {
            return applyJsonReplacement(source, paramName, newValue, result.getOldValue());
        }
        if (result.getLocation() == MutationResult.Location.FORM_BODY) {
            return applyFormReplacement(source, paramName, newValue, result.getOldValue());
        }
        return source;
    }

    /**
     * Inspect a request body to find a parameter and report whether the
     * mutation could be applied. Does NOT mutate the body itself; the
     * caller calls {@link #replaceTracked} with the same result to do
     * the actual replacement.
     */
    private MutationResult applyBodyMutationTracking(String body, String paramName,
                                                     String newValue, String contentType) {
        if (body == null) return null;

        String ct = contentType != null ? contentType.toLowerCase() : "";
        String trimmed = body.trim();

        if (ct.contains("json") || trimmed.startsWith("{") || trimmed.startsWith("[")) {
            return applyJsonMutationTracking(body, paramName, newValue);
        }
        if (ct.contains("x-www-form-urlencoded") || body.contains(paramName + "=")
                || body.contains(URLEncoder.encode(paramName, StandardCharsets.UTF_8) + "=")) {
            return applyFormMutationTracking(body, paramName, newValue);
        }
        return MutationResult.notApplied(MutationResult.Location.UNKNOWN, paramName,
                "no body type match (not JSON, not form)");
    }

    private MutationResult applyQueryMutationTracking(String url, String paramName, String newValue) {
        if (url == null) return null;
        int qIdx = url.indexOf('?');
        if (qIdx < 0) {
            return MutationResult.notApplied(MutationResult.Location.QUERY, paramName,
                    "URL has no query string");
        }
        String query = url.substring(qIdx + 1);
        String oldValue = findQueryValue(query, paramName);
        if (oldValue == null) {
            return MutationResult.notApplied(MutationResult.Location.QUERY, paramName,
                    "parameter not found in query string");
        }
        return MutationResult.applied(MutationResult.Location.QUERY, paramName, oldValue, newValue);
    }

    private MutationResult applyJsonMutationTracking(String body, String paramName, String newValue) {
        String key = paramName.contains(".")
                ? paramName.substring(paramName.lastIndexOf('.') + 1)
                : paramName;
        // Try matching a quoted-string value, a numeric value, a boolean/null, or an array
        String[] patterns = {
                "(\"" + Pattern.quote(key) + "\"\\s*:\\s*)\"[^\"]*\"",
                "(\"" + Pattern.quote(key) + "\"\\s*:\\s*)[0-9.]+(?:[eE][+-]?\\d+)?",
                "(\"" + Pattern.quote(key) + "\"\\s*:\\s*)(?:true|false|null)",
                "(\"" + Pattern.quote(key) + "\"\\s*:\\s*)\\[[^\\]]*\\]"
        };
        for (int i = 0; i < patterns.length; i++) {
            Matcher m = Pattern.compile(patterns[i]).matcher(body);
            if (m.find()) {
                String oldValue = m.group().substring(m.group(1).length());
                return MutationResult.applied(MutationResult.Location.JSON_BODY,
                        paramName, oldValue, newValue);
            }
        }
        return MutationResult.notApplied(MutationResult.Location.JSON_BODY, paramName,
                "key not found in JSON body");
    }

    private MutationResult applyFormMutationTracking(String body, String paramName, String newValue) {
        Pattern p = Pattern.compile("(?<=^|&)" + Pattern.quote(paramName) + "=([^&]*)");
        Matcher m = p.matcher(body);
        if (m.find()) {
            return MutationResult.applied(MutationResult.Location.FORM_BODY,
                    paramName, m.group(1), newValue);
        }
        String encoded = URLEncoder.encode(paramName, StandardCharsets.UTF_8);
        Pattern p2 = Pattern.compile("(?<=^|&)" + Pattern.quote(encoded) + "=([^&]*)");
        Matcher m2 = p2.matcher(body);
        if (m2.find()) {
            return MutationResult.applied(MutationResult.Location.FORM_BODY,
                    paramName, m2.group(1), newValue);
        }
        return MutationResult.notApplied(MutationResult.Location.FORM_BODY, paramName,
                "key not found in form body");
    }

    /**
     * Find the value of a parameter in a query string. Returns null when
     * the parameter is not present.
     */
    private String findQueryValue(String query, String paramName) {
        if (query == null) return null;
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            String name = eq >= 0 ? pair.substring(0, eq) : pair;
            if (name.equals(paramName)) {
                return eq >= 0 ? pair.substring(eq + 1) : "";
            }
        }
        return null;
    }

    /**
     * Apply a query mutation. Both the raw and the URL-encoded form of
     * the parameter name are matched, and the new value is URL-encoded so
     * the resulting URL is well-formed.
     */
    private String applyQueryReplacement(String url, String paramName, String newValue, String oldValue) {
        int qIdx = url.indexOf('?');
        if (qIdx < 0) return url;
        String prefix = url.substring(0, qIdx + 1);
        String query = url.substring(qIdx + 1);
        String encodedName = URLEncoder.encode(paramName, StandardCharsets.UTF_8);
        String encodedValue = URLEncoder.encode(newValue, StandardCharsets.UTF_8);

        Pattern p = Pattern.compile("(?<=[?&])(" + Pattern.quote(paramName) + ")=([^&]*)");
        Matcher m = p.matcher(query);
        if (m.find()) {
            query = m.replaceFirst(Matcher.quoteReplacement(m.group(1) + "=" + encodedValue));
        } else {
            Pattern p2 = Pattern.compile("(?<=[?&])(" + Pattern.quote(encodedName) + ")=([^&]*)");
            Matcher m2 = p2.matcher(query);
            if (m2.find()) {
                query = m2.replaceFirst(Matcher.quoteReplacement(m2.group(1) + "=" + encodedValue));
            }
        }
        return prefix + query;
    }

    /**
     * Apply a JSON mutation. Uses the same key discovery as the tracking
     * step, then performs the actual replacement with
     * {@link Matcher#quoteReplacement} so that regex metacharacters in
     * the new value cannot corrupt the body.
     */
    private String applyJsonReplacement(String body, String paramName, String newValue, String oldValue) {
        String key = paramName.contains(".")
                ? paramName.substring(paramName.lastIndexOf('.') + 1)
                : paramName;

        // String value
        {
            Pattern p = Pattern.compile("(\"" + Pattern.quote(key) + "\"\\s*:\\s*)\"[^\"]*\"");
            Matcher m = p.matcher(body);
            if (m.find()) {
                return m.replaceFirst(Matcher.quoteReplacement(
                        m.group(1) + "\"" + newValue.replace("\\", "\\\\").replace("\"", "\\\"") + "\""));
            }
        }
        // Numeric / boolean / null
        {
            Pattern p = Pattern.compile("(\"" + Pattern.quote(key) + "\"\\s*:\\s*)([0-9.]+(?:[eE][+-]?\\d+)?|true|false|null)");
            Matcher m = p.matcher(body);
            if (m.find()) {
                return m.replaceFirst(Matcher.quoteReplacement(m.group(1) + newValue));
            }
        }
        // Array
        {
            Pattern p = Pattern.compile("(\"" + Pattern.quote(key) + "\"\\s*:\\s*)\\[[^\\]]*\\]");
            Matcher m = p.matcher(body);
            if (m.find()) {
                return m.replaceFirst(Matcher.quoteReplacement(
                        m.group(1) + "[\"" + newValue.replace("\\", "\\\\").replace("\"", "\\\"") + "\"]"));
            }
        }
        return body;
    }

    /**
     * Apply a form mutation. Uses Pattern.quote / Matcher.quoteReplacement
     * to defend against metacharacters in either the parameter name or
     * the new value, and URL-encodes the new value.
     */
    private String applyFormReplacement(String body, String paramName, String newValue, String oldValue) {
        String encodedValue;
        try {
            encodedValue = java.net.URLEncoder.encode(newValue, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            encodedValue = newValue;
        }
        Pattern p = Pattern.compile("(?<=^|&)(" + Pattern.quote(paramName) + ")=[^&]*");
        Matcher m = p.matcher(body);
        if (m.find()) {
            return m.replaceFirst(Matcher.quoteReplacement(m.group(1) + "=" + encodedValue));
        }
        String encoded = java.net.URLEncoder.encode(paramName, java.nio.charset.StandardCharsets.UTF_8);
        Pattern p2 = Pattern.compile("(?<=^|&)(" + Pattern.quote(encoded) + ")=[^&]*");
        Matcher m2 = p2.matcher(body);
        if (m2.find()) {
            return m2.replaceFirst(Matcher.quoteReplacement(m2.group(1) + "=" + encodedValue));
        }
        return body;
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
     * Simple response container from a replay.
     */
    public static class ReplayResponse {
        public int statusCode;
        public String body;
    }
}

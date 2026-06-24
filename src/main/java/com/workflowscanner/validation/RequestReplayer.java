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

import java.net.URLDecoder;
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

    /**
     * Headers that should never be carried over to a fresh in-app
     * navigation. Burp sets Host and Content-Length automatically;
     * Content-Type, Transfer-Encoding and Connection don't apply to
     * a bodyless GET; Cache-Control and Pragma are per-request.
     */
    private static final Set<String> SKIPPED_FETCH_HEADERS = Set.of(
            "host", "content-length", "content-type", "transfer-encoding",
            "connection", "cache-control", "pragma", "upgrade",
            "expect", "trailer", "te", "if-none-match",
            "if-modified-since");

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
     * Issue a fresh GET to a URL through Burp. Used by the state-effect
     * validator to fetch a "fresh before" and "fresh after" baseline
     * around the state-changing replay. Auth/session cookies are
     * preserved (no workflow-state-token stripping) so the request
     * behaves like a normal in-app navigation.
     *
     * @param url Absolute URL to GET
     * @return The response, or null on failure
     */
    public ReplayResponse fetchGet(String url) {
        return fetchGet(url, null);
    }

    /**
     * Issue a fresh GET to a URL using the given context node as the
     * source of headers. The context's auth, session, accept, and
     * custom app headers (X-Org-ID, X-Tenant-ID, etc.) are copied so
     * the request looks like a normal in-app navigation under the same
     * user/tenant. Workflow-state headers (CSRF, nonce, step token)
     * and connection/transport headers are not copied.
     *
     * <p>This is the version the state-effect validator uses for its
     * fresh before/after snapshots, because real production apps
     * typically require Cookie + Authorization + tenant headers to
     * return the authenticated response we want to diff.
     *
     * @param url         Absolute URL to GET
     * @param contextNode Source of headers; may be null (no copying)
     * @return The response, or null on failure
     */
    public ReplayResponse fetchGet(String url, RequestNode contextNode) {
        if (url == null || url.isEmpty()) return null;
        com.workflowscanner.data.CapturedRequest captured =
                new com.workflowscanner.data.CapturedRequest();
        captured.setUrl(url);
        captured.setMethod("GET");

        if (contextNode != null && contextNode.getRequest() != null
                && contextNode.getRequest().getRequestHeaders() != null) {
            java.util.Map<String, java.util.List<String>> copied =
                    new java.util.HashMap<>();
            for (Map.Entry<String, java.util.List<String>> h :
                    contextNode.getRequest().getRequestHeaders().entrySet()) {
                String name = h.getKey();
                if (name == null) continue;
                String lower = name.toLowerCase();
                if (name.startsWith(":")) continue;       // HTTP/2 pseudo-headers
                if (SKIPPED_FETCH_HEADERS.contains(lower)) continue;
                if (WORKFLOW_STATE_HEADERS.contains(lower)) continue;
                // Defensive copy so the original headers map is not aliased.
                copied.put(name, new java.util.ArrayList<>(h.getValue()));
            }
            captured.setRequestHeaders(copied);
        }

        RequestNode node = new RequestNode(captured, 0);
        node.setUrl(url);
        node.setMethod("GET");
        node.setPath("/");
        return replay(node, null, false);
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
     * use identical parsing/replacement.
     *
     * <p><b>Reliability (validation rework follow-up):</b> the helper
     * compares the post-replacement string to the source; if nothing
     * changed, the replacement is treated as a no-op and the source is
     * returned unchanged. This prevents the
     * "tracking said applied but replacement silently failed" class of
     * false positives.
     */
    private String replaceTracked(String source, MutationResult result,
                                   String paramName, String newValue) {
        String replaced;
        if (result.getLocation() == MutationResult.Location.QUERY) {
            replaced = applyQueryReplacement(source, paramName, newValue);
        } else if (result.getLocation() == MutationResult.Location.JSON_BODY) {
            replaced = applyJsonReplacement(source, paramName, newValue);
        } else if (result.getLocation() == MutationResult.Location.FORM_BODY) {
            replaced = applyFormReplacement(source, paramName, newValue);
        } else {
            return source;
        }
        // The applied flag now means the source actually changed.
        // If replacement produced the same string, treat it as a no-op.
        if (replaced == null || replaced.equals(source)) {
            result.markNotEffectivelyApplied();
            return source;
        }
        return replaced;
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
        String prefix = url.substring(0, qIdx + 1);
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
        if (body == null) return null;
        String[] pairs = body.split("&", -1);
        for (String pair : pairs) {
            int eq = pair.indexOf('=');
            String name = eq >= 0 ? pair.substring(0, eq) : pair;
            if (paramNameMatches(name, paramName)) {
                String oldValue = eq >= 0 ? pair.substring(eq + 1) : "";
                return MutationResult.applied(MutationResult.Location.FORM_BODY,
                        paramName, oldValue, newValue);
            }
        }
        return MutationResult.notApplied(MutationResult.Location.FORM_BODY, paramName,
                "key not found in form body");
    }

    /**
     * Find the value of a parameter in a query string. Returns null when
     * the parameter is not present. Matches the raw, percent-encoded,
     * and percent-decoded forms of the parameter name.
     */
    private String findQueryValue(String query, String paramName) {
        if (query == null) return null;
        for (String pair : query.split("&", -1)) {
            int eq = pair.indexOf('=');
            String name = eq >= 0 ? pair.substring(0, eq) : pair;
            if (paramNameMatches(name, paramName)) {
                return eq >= 0 ? pair.substring(eq + 1) : "";
            }
        }
        return null;
    }

    /**
     * True when the given parameter name (as it appears in a query
     * string or form body) matches the target parameter name. Handles
     * the three practical encodings: raw, percent-encoded, and
     * percent-decoded. Decoding covers cases like
     * {@code user%20id} → {@code user id} or {@code user+id} → {@code user id}.
     */
    private boolean paramNameMatches(String nameInRequest, String paramName) {
        if (nameInRequest == null) return false;
        if (nameInRequest.equals(paramName)) return true;
        String encodedName = URLEncoder.encode(paramName, StandardCharsets.UTF_8);
        if (nameInRequest.equals(encodedName)) return true;
        try {
            String decoded = URLDecoder.decode(nameInRequest, StandardCharsets.UTF_8);
            if (decoded.equals(paramName)) return true;
        } catch (Exception ignore) {
            // Malformed percent-encoding — fall through to false.
        }
        return false;
    }

    /**
     * Apply a query mutation by splitting the query on {@code &} and
     * rebuilding it with the new value. No regex is used for either the
     * match or the rebuild, so the first parameter and parameters whose
     * names contain special characters are both handled correctly. The
     * new value is URL-encoded.
     */
    private String applyQueryReplacement(String url, String paramName, String newValue) {
        int qIdx = url.indexOf('?');
        if (qIdx < 0) return url;
        String prefix = url.substring(0, qIdx + 1);
        String query = url.substring(qIdx + 1);
        String encodedName = URLEncoder.encode(paramName, StandardCharsets.UTF_8);
        String encodedValue;
        try {
            encodedValue = URLEncoder.encode(newValue, StandardCharsets.UTF_8);
        } catch (Exception e) {
            encodedValue = newValue;
        }

        String[] pairs = query.split("&", -1);
        StringBuilder out = new StringBuilder(query.length() + 32);
        boolean replaced = false;
        for (int i = 0; i < pairs.length; i++) {
            String pair = pairs[i];
            int eq = pair.indexOf('=');
            String name = eq >= 0 ? pair.substring(0, eq) : pair;
            if (i > 0) out.append('&');
            if (!replaced && paramNameMatches(name, paramName)) {
                out.append(encodedName).append('=').append(encodedValue);
                replaced = true;
            } else {
                out.append(pair);
            }
        }
        if (!replaced) return url;
        return prefix + out.toString();
    }

    /**
     * Apply a JSON mutation. Uses the same key discovery as the tracking
     * step, then performs the actual replacement with
     * {@link Matcher#quoteReplacement} so that regex metacharacters in
     * the new value cannot corrupt the body.
     */
    private String applyJsonReplacement(String body, String paramName, String newValue) {
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
     * Apply a form mutation by splitting the body on {@code &} and
     * rebuilding it with the new value. No regex is used; the new value
     * is URL-encoded. Matches raw, percent-encoded, and percent-decoded
     * names via {@link #paramNameMatches}.
     */
    private String applyFormReplacement(String body, String paramName, String newValue) {
        String encodedName = URLEncoder.encode(paramName, StandardCharsets.UTF_8);
        String encodedValue;
        try {
            encodedValue = URLEncoder.encode(newValue, StandardCharsets.UTF_8);
        } catch (Exception e) {
            encodedValue = newValue;
        }

        String[] pairs = body.split("&", -1);
        StringBuilder out = new StringBuilder(body.length() + 32);
        boolean replaced = false;
        for (int i = 0; i < pairs.length; i++) {
            String pair = pairs[i];
            int eq = pair.indexOf('=');
            String name = eq >= 0 ? pair.substring(0, eq) : pair;
            if (i > 0) out.append('&');
            if (!replaced && paramNameMatches(name, paramName)) {
                out.append(encodedName).append('=').append(encodedValue);
                replaced = true;
            } else {
                out.append(pair);
            }
        }
        return replaced ? out.toString() : body;
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

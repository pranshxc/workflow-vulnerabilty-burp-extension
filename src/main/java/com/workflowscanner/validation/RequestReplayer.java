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

/**
 * Replays HTTP requests through Burp's API with optional modifications.
 * Uses api.http().sendRequest() to respect upstream proxies, SSL settings, etc.
 */
public class RequestReplayer {

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
     * @param freshSession  If true, strip cookies and auth headers
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
                    }
                }
            }

            // Build Burp HttpRequest
            HttpRequest request = HttpRequest.httpRequest(url);
            request = request.withMethod(method);

            // Add headers (optionally stripping auth for fresh session)
            if (captured.getRequestHeaders() != null) {
                for (Map.Entry<String, java.util.List<String>> header :
                        captured.getRequestHeaders().entrySet()) {
                    String headerName = header.getKey();

                    // Skip pseudo-headers and connection headers
                    if (headerName.startsWith(":") || headerName.equalsIgnoreCase("Host")
                            || headerName.equalsIgnoreCase("Content-Length")) {
                        continue;
                    }

                    // Fresh session: strip auth-related headers
                    if (freshSession) {
                        String lower = headerName.toLowerCase();
                        if (lower.equals("cookie") || lower.equals("authorization")
                                || lower.startsWith("x-csrf") || lower.startsWith("x-xsrf")) {
                            continue;
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
                            + (freshSession ? " [fresh session]" : "")
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
     * Apply a parameter modification to a request body.
     */
    private String applyModification(String body, String paramName, String newValue,
                                      String contentType) {
        if (body == null) return null;

        if (contentType != null && contentType.contains("json")) {
            // JSON body: replace "paramName": "oldValue" with "paramName": "newValue"
            String pattern = "\"" + paramName + "\"\\s*:\\s*\"[^\"]*\"";
            String replacement = "\"" + paramName + "\": \"" + newValue + "\"";
            String modified = body.replaceAll(pattern, replacement);
            // Also try numeric values
            if (modified.equals(body)) {
                pattern = "\"" + paramName + "\"\\s*:\\s*[0-9.]+";
                replacement = "\"" + paramName + "\": " + newValue;
                modified = body.replaceAll(pattern, replacement);
            }
            return modified;
        } else {
            // Form body: replace paramName=oldValue with paramName=newValue
            return body.replaceAll(
                    paramName + "=[^&]*",
                    paramName + "=" + newValue);
        }
    }

    /**
     * Simple response container from a replay.
     */
    public static class ReplayResponse {
        public int statusCode;
        public String body;
    }
}

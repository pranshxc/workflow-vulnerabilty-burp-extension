package com.workflowscanner.data;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Converts Montoya API HTTP objects into the internal CapturedRequest model.
 * Extracts all headers, parameters, cookies, body content with no redaction.
 */
public class RequestConverter {

    /**
     * Convert a live proxy HttpResponseReceived into a CapturedRequest.
     */
    public static CapturedRequest fromHttpResponse(HttpResponseReceived responseReceived,
                                                    CapturedRequest.Source source) {
        CapturedRequest captured = new CapturedRequest();
        captured.setSource(source);

        try {
            HttpRequest request = responseReceived.initiatingRequest();
            HttpResponse response = responseReceived;

            populateFromRequest(captured, request);
            populateFromResponse(captured, response);
        } catch (Exception e) {
            // Partial capture is better than no capture
        }

        return captured;
    }

    /**
     * Convert a ProxyHttpRequestResponse (from proxy history) into a CapturedRequest.
     */
    public static CapturedRequest fromProxyHistory(ProxyHttpRequestResponse proxyItem,
                                                    CapturedRequest.Source source) {
        CapturedRequest captured = new CapturedRequest();
        captured.setSource(source);

        try {
            HttpRequest request = proxyItem.request();
            populateFromRequest(captured, request);

            HttpResponse response = proxyItem.response();
            if (response != null) {
                populateFromResponse(captured, response);
            }
        } catch (Exception e) {
            // Partial capture is better than no capture
        }

        return captured;
    }

    /**
     * Convert a generic HttpRequest + HttpResponse pair into a CapturedRequest.
     * Used for context menu selections.
     */
    public static CapturedRequest fromRequestResponse(HttpRequest request, HttpResponse response,
                                                       CapturedRequest.Source source) {
        CapturedRequest captured = new CapturedRequest();
        captured.setSource(source);

        try {
            populateFromRequest(captured, request);
            if (response != null) {
                populateFromResponse(captured, response);
            }
        } catch (Exception e) {
            // Partial capture is better than no capture
        }

        return captured;
    }

    // --- Internal Extraction Methods ---

    private static void populateFromRequest(CapturedRequest captured, HttpRequest request) {
        if (request == null) return;

        // Method
        captured.setMethod(request.method());

        // URL
        captured.setUrl(request.url());

        // Host and path
        try {
            String url = request.url();
            if (url != null) {
                // Extract host from URL
                String host = extractHost(url);
                captured.setHost(host);

                // Extract path
                String path = extractPath(url);
                captured.setPath(path);
            }
        } catch (Exception e) {
            // Best effort
        }

        // Headers
        Map<String, List<String>> headers = extractHeaders(request.headers());
        captured.setRequestHeaders(headers);

        // Content-Type
        String contentType = getFirstHeaderValue(headers, "Content-Type");
        captured.setContentType(contentType);

        // Referrer (handle both spellings)
        String referrer = getFirstHeaderValue(headers, "Referer");
        if (referrer == null) {
            referrer = getFirstHeaderValue(headers, "Referrer");
        }
        captured.setReferrer(referrer);

        // Cookies
        List<String> cookies = new ArrayList<>();
        List<String> cookieHeaders = headers.get("Cookie");
        if (cookieHeaders != null) {
            for (String cookieHeader : cookieHeaders) {
                // Split individual cookies
                String[] parts = cookieHeader.split(";");
                for (String part : parts) {
                    String trimmed = part.trim();
                    if (!trimmed.isEmpty()) {
                        cookies.add(trimmed);
                    }
                }
            }
        }
        captured.setCookies(cookies);

        // Query parameters
        Map<String, String> queryParams = new HashMap<>();
        try {
            for (HttpParameter param : request.parameters()) {
                if (param.type() == HttpParameterType.URL) {
                    queryParams.put(param.name(), param.value());
                }
            }
        } catch (Exception e) {
            // Some requests may not have parseable params
        }
        captured.setQueryParams(queryParams);

        // Request body (raw, no redaction)
        try {
            if (request.body() != null) {
                captured.setRequestBody(request.bodyToString());
            }
        } catch (Exception e) {
            // Body may not be available
        }
    }

    private static void populateFromResponse(CapturedRequest captured, HttpResponse response) {
        if (response == null) return;

        // Status code
        captured.setStatusCode(response.statusCode());

        // Response headers
        Map<String, List<String>> headers = extractHeaders(response.headers());
        captured.setResponseHeaders(headers);

        // MIME type
        String contentType = getFirstHeaderValue(headers, "Content-Type");
        if (contentType != null) {
            // Extract MIME type (before semicolon)
            int semicolonIdx = contentType.indexOf(';');
            captured.setMimeType(semicolonIdx > 0 ? contentType.substring(0, semicolonIdx).trim() : contentType.trim());
        }

        // Response body (raw, no redaction)
        try {
            if (response.body() != null) {
                captured.setResponseBody(response.bodyToString());
            }
        } catch (Exception e) {
            // Body may not be available
        }
    }

    /**
     * Extract headers from Montoya API header list into a multi-value map.
     */
    private static Map<String, List<String>> extractHeaders(List<HttpHeader> headerList) {
        Map<String, List<String>> headers = new HashMap<>();
        if (headerList == null) return headers;

        for (HttpHeader header : headerList) {
            try {
                String name = header.name();
                String value = header.value();
                headers.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
            } catch (Exception e) {
                // Skip malformed headers
            }
        }
        return headers;
    }

    /**
     * Get the first value for a header name (case-insensitive).
     */
    private static String getFirstHeaderValue(Map<String, List<String>> headers, String name) {
        // Try exact match first
        List<String> values = headers.get(name);
        if (values != null && !values.isEmpty()) {
            return values.get(0);
        }
        // Case-insensitive fallback
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name) && !entry.getValue().isEmpty()) {
                return entry.getValue().get(0);
            }
        }
        return null;
    }

    /**
     * Extract hostname from a URL string using java.net.URI.
     */
    public static String extractHost(String url) {
        if (url == null || url.isEmpty()) return "";
        try {
            // Ensure URL has a protocol for URI parsing
            String normalizedUrl = url;
            if (!normalizedUrl.contains("://")) {
                normalizedUrl = "http://" + normalizedUrl;
            }
            URI uri = new URI(normalizedUrl);
            String host = uri.getHost();
            return host != null ? host : "";
        } catch (URISyntaxException e) {
            return "";
        }
    }

    /**
     * Extract path from a URL string using java.net.URI.
     */
    public static String extractPath(String url) {
        if (url == null || url.isEmpty()) return "/";
        try {
            String normalizedUrl = url;
            if (!normalizedUrl.contains("://")) {
                normalizedUrl = "http://" + normalizedUrl;
            }
            URI uri = new URI(normalizedUrl);
            String path = uri.getRawPath();
            return path != null && !path.isEmpty() ? path : "/";
        } catch (URISyntaxException e) {
            return "/";
        }
    }
}

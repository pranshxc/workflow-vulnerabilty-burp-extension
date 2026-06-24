package com.workflowscanner.classification;

import com.workflowscanner.data.CapturedRequest;

import java.util.HashSet;
import java.util.Set;

/**
 * Classifies HTTP requests by intent before they enter the graph.
 * Uses deterministic rules only — no LLM calls.
 *
 * Rules are evaluated in priority order (first match wins).
 */
public class RequestClassifier {

    private final EndpointNormalizer endpointNormalizer;

    public RequestClassifier() {
        this.endpointNormalizer = new EndpointNormalizer();
    }

    /**
     * Classify a captured request by its intent.
     */
    public RequestClassification classify(CapturedRequest request) {
        if (request == null) return RequestClassification.noise(RequestIntent.UNKNOWN, "Null request");

        String method = request.getMethod() != null ? request.getMethod().toUpperCase() : "GET";
        String path = request.getPath() != null ? request.getPath() : "/";
        String host = request.getHost();
        String contentType = request.getContentType();
        String mimeType = request.getMimeType();
        int statusCode = request.getStatusCode();

        Set<String> headerNames = request.getRequestHeaders() != null
                ? request.getRequestHeaders().keySet()
                : new HashSet<>();

        // Priority 1: CORS preflight
        if (StaticNoiseRules.isCorsPreflight(method, headerNames)) {
            return RequestClassification.noise(RequestIntent.PREFLIGHT,
                    "CORS preflight OPTIONS request");
        }

        // Priority 2: Source maps (always noise)
        if (StaticNoiseRules.isSourceMap(path)) {
            return RequestClassification.noise(RequestIntent.STATIC_ASSET,
                    "JavaScript source map file");
        }

        // Priority 3: Health checks and monitoring
        if (StaticNoiseRules.isHealthCheckPath(path)) {
            return RequestClassification.noise(RequestIntent.HEALTHCHECK,
                    "Health check / monitoring endpoint");
        }

        // Priority 4: Third-party domains
        if (StaticNoiseRules.isThirdPartyDomain(host)) {
            return RequestClassification.noise(RequestIntent.THIRD_PARTY,
                    "Third-party domain: " + host);
        }

        // Priority 5: Telemetry and analytics
        if (StaticNoiseRules.isTelemetryPath(path)) {
            return RequestClassification.noise(RequestIntent.TELEMETRY_ANALYTICS,
                    "Analytics/telemetry endpoint");
        }

        // Priority 6: Static assets
        if (StaticNoiseRules.isStaticExtension(path)) {
            if (StaticNoiseRules.isJavaScriptFile(path)) {
                // JS files: flag but keep for potential endpoint discovery
                return RequestClassification.background(RequestIntent.STATIC_ASSET,
                        "JavaScript file (flagged, not chained)");
            }
            return RequestClassification.noise(RequestIntent.STATIC_ASSET,
                    "Static asset file");
        }

        // Priority 7: Auth context reads (e.g. /api/me)
        // These are not workflow steps but carry user context for the ApplicationModel
        if (StaticNoiseRules.isContextReadPath(path)) {
            if (StaticNoiseRules.isJsonResponse(mimeType)) {
                return RequestClassification.background(RequestIntent.CONTEXT_READ,
                        "Auth context read (retained for ApplicationModel)");
            }
            return RequestClassification.background(RequestIntent.CONTEXT_READ,
                    "Auth context read (non-JSON, retained)");
        }

        // Priority 8: Background polling
        if (StaticNoiseRules.isPollingPath(path)) {
            return RequestClassification.background(RequestIntent.BACKGROUND_POLLING,
                    "Background polling endpoint");
        }

        // Priority 9: Authentication paths
        if (BusinessKeywordRules.isAuthPath(path)) {
            EndpointKey key = endpointNormalizer.normalize(request);
            return RequestClassification.relevant(RequestIntent.AUTHENTICATION, 8.0,
                    "Authentication endpoint", key);
        }

        // Priority 10: Business paths with state-changing methods
        int businessScore = BusinessKeywordRules.scorePath(path);
        boolean isStateChanging = BusinessKeywordRules.isStateChanging(method);
        boolean isFinancial = BusinessKeywordRules.isFinancialPath(path);
        boolean hasBody = request.getRequestBody() != null && !request.getRequestBody().isEmpty();

        if (isStateChanging && businessScore >= 2) {
            EndpointKey key = endpointNormalizer.normalize(request);
            RequestIntent intent = isFinancial ? RequestIntent.BUSINESS_ACTION : RequestIntent.WORKFLOW_STATE;
            return RequestClassification.relevant(intent, businessScore + 3.0,
                    method + " with business keywords (score=" + businessScore + ")", key);
        }

        if (hasBody && businessScore >= 3) {
            EndpointKey key = endpointNormalizer.normalize(request);
            return RequestClassification.relevant(RequestIntent.BUSINESS_ACTION, businessScore + 2.0,
                    "Request body with business keywords", key);
        }

        // Priority 10: Financial endpoints regardless of method
        if (isFinancial) {
            EndpointKey key = endpointNormalizer.normalize(request);
            return RequestClassification.relevant(RequestIntent.BUSINESS_READ, businessScore + 2.0,
                    "Financial endpoint", key);
        }

        // Priority 11: Business reads (GET with business nouns + JSON response)
        if ("GET".equals(method) && businessScore >= 3
                && StaticNoiseRules.isJsonResponse(mimeType)) {
            EndpointKey key = endpointNormalizer.normalize(request);
            return RequestClassification.relevant(RequestIntent.BUSINESS_READ, businessScore,
                    "Business read API", key);
        }

        // Priority 12: HTML page loads with business context
        if (businessScore >= 2 && StaticNoiseRules.isHtmlResponse(mimeType)) {
            EndpointKey key = endpointNormalizer.normalize(request);
            return RequestClassification.relevant(RequestIntent.UNKNOWN, businessScore,
                    "Business page load", key);
        }

        // Priority 13: Fallback for unknown requests
        EndpointKey key = endpointNormalizer.normalize(request);
        if (businessScore > 0 || hasBody || isStateChanging) {
            return RequestClassification.unknown("Has business signals but low confidence", key);
        }

        // Priority 14: Trivial GET with no business signals — suppress
        return RequestClassification.noise(RequestIntent.UNKNOWN,
                "Trivial request with no business signals");
    }

    public EndpointNormalizer getEndpointNormalizer() {
        return endpointNormalizer;
    }
}

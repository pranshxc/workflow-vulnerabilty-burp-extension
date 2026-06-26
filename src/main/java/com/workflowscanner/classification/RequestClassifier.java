package com.workflowscanner.classification;

import com.workflowscanner.data.CapturedRequest;

import java.util.HashSet;
import java.util.Set;

/**
 * Classifies HTTP requests by intent before they enter the graph.
 * Uses deterministic rules only — no LLM calls.
 *
 * <p>Rules are evaluated in priority order (first match wins). The
 * classifier is universal — it works for any web target by relying
 * on {@link NoiseRulesConfig} and {@link PrivateContextDetector}
 * rather than target-specific keyword lists.
 */
public class RequestClassifier {

    private final EndpointNormalizer endpointNormalizer;
    private final StaticNoiseRules noiseRules;
    private final PrivateContextDetector privateContextDetector;
    private final NoiseRulesConfig noiseConfig;

    public RequestClassifier() {
        this(NoiseRulesConfig.withDefaults());
    }

    public RequestClassifier(NoiseRulesConfig config) {
        NoiseRulesConfig cfg = config != null ? config : NoiseRulesConfig.withDefaults();
        this.noiseConfig = cfg;
        this.endpointNormalizer = new EndpointNormalizer();
        this.noiseRules = new StaticNoiseRules(cfg);
        this.privateContextDetector = new PrivateContextDetector(cfg);
    }

    /**
     * Classify a captured request by its intent.
     */
    public RequestClassification classify(CapturedRequest request) {
        if (request == null) {
            return RequestClassification.noise(RequestIntent.UNKNOWN, "Null request");
        }

        String method = request.getMethod() != null ? request.getMethod().toUpperCase() : "GET";
        String path = request.getPath() != null ? request.getPath() : "/";
        String host = request.getHost();
        String contentType = request.getContentType();
        String mimeType = request.getMimeType();

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
        if (noiseRules.isHealthCheckPath(path)) {
            return RequestClassification.noise(RequestIntent.HEALTHCHECK,
                    "Health check / monitoring endpoint");
        }

        // Priority 4: Third-party / observability / feature-flag hosts
        if (noiseRules.isThirdPartyDomain(host)) {
            return RequestClassification.noise(RequestIntent.THIRD_PARTY,
                    "Third-party / observability host: " + host);
        }

        // Priority 5: Telemetry and analytics (path-based)
        if (noiseRules.isTelemetryPath(path)) {
            return RequestClassification.noise(RequestIntent.TELEMETRY_ANALYTICS,
                    "Analytics / telemetry endpoint");
        }

        // Priority 5b: Feature-flag / config endpoints
        if (noiseRules.isFeatureFlagPath(path)) {
            return RequestClassification.noise(RequestIntent.FEATURE_FLAG_CONFIG,
                    "Feature-flag / config endpoint");
        }

        // Priority 6: Static assets
        if (noiseRules.isStaticExtension(path)) {
            if (StaticNoiseRules.isJavaScriptFile(path)) {
                return RequestClassification.background(RequestIntent.STATIC_ASSET,
                        "JavaScript file (flagged, not chained)");
            }
            return RequestClassification.noise(RequestIntent.STATIC_ASSET,
                    "Static asset file");
        }

        // Priority 7: Auth context reads (e.g. /api/me) — method-aware.
        // Only safe GET/HEAD on context-read paths are context reads.
        // POST/PUT/PATCH/DELETE fall through to the business classifier.
        if (noiseRules.isContextReadPath(path, method)) {
            if (StaticNoiseRules.isJsonResponse(mimeType)) {
                return RequestClassification.background(RequestIntent.CONTEXT_READ,
                        "Auth context read (retained for ApplicationModel)");
            }
            return RequestClassification.background(RequestIntent.CONTEXT_READ,
                    "Auth context read (non-JSON, retained)");
        }

        // Priority 8: Background polling
        if (noiseRules.isPollingPath(path)) {
            return RequestClassification.background(RequestIntent.BACKGROUND_POLLING,
                    "Background polling endpoint");
        }

        // Priority 8.5: Public-resource pre-check (UNIVERSAL).
        //
        // A GET/HEAD whose path matches a public-resource pattern AND
        // whose request does NOT carry private context (Authorization,
        // session cookie, private path, /me, /account, etc.) is a
        // public-data lookup. It must never become a workflow candidate.
        //
        // The check is method-aware (GET/HEAD only) so that POST
        // mutations on the same paths (e.g. POST /api/articles) are
        // NOT misclassified.
        if (isPublicResourceRequest(request, method, path)) {
            return RequestClassification.background(RequestIntent.PUBLIC_DATA_LOOKUP,
                    "Public-data lookup (no auth/private context)");
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

        // Priority 10.5: Auth-bound requests get a base score.
        //
        // The universal principle: "if these exist, read-only
        // endpoints can be very important." A request that carries
        // private context (Authorization header, session cookie,
        // private path, /me, /account, etc.) is acting on behalf of
        // an authenticated user, so the classifier treats it as
        // business-relevant even when the path has no business
        // keywords (e.g. GET /api/products/12345 with auth).
        if (privateContextDetector.hasPrivateContext(request)) {
            EndpointKey key = endpointNormalizer.normalize(request);
            if (isStateChanging) {
                return RequestClassification.relevant(RequestIntent.BUSINESS_ACTION, 5.0,
                        "Auth-bound state-changing request", key);
            }
            if ("GET".equals(method) || "HEAD".equals(method)) {
                if (StaticNoiseRules.isJsonResponse(mimeType)) {
                    return RequestClassification.relevant(RequestIntent.BUSINESS_READ, 3.0,
                            "Auth-bound read", key);
                }
            }
        }

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

        // Priority 10b: Financial endpoints regardless of method
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
            // === Phase-1 / "if you implement only one thing" ===
            // Unknown authenticated state-changing flows are structurally
            // interesting even when no keyword matches. They get a
            // meaningful business score (4.0) so they survive the
            // analysis-threshold filter and the LLM gets a chance to
            // evaluate them. The gate still suppresses unconfirmed
            // findings by default; the user can opt in via
            // reportUnconfirmedFindings=true.
            //
            // Without this, an authenticated POST /api/mandates/123/action
            // or PATCH /api/x29/process with no business keyword would
            // be classified as UNKNOWN at score=0.5 and die in the
            // threshold filter — a worst-case false negative.
            boolean authBoundUnknown = isStateChanging
                    && privateContextDetector.hasPrivateContext(request);
            if (authBoundUnknown) {
                return new RequestClassification(
                        RequestIntent.UNKNOWN, 4.0, 0, true, false,
                        "Unknown authenticated state-changing flow (structurally interesting)", key);
            }
            return RequestClassification.unknown("Has business signals but low confidence", key);
        }

        // Priority 14: Trivial GET with no business signals — suppress
        return RequestClassification.noise(RequestIntent.UNKNOWN,
                "Trivial request with no business signals");
    }

    /**
     * Universal public-resource detection.
     *
     * <p>Returns true when the request path matches a configured
     * public-resource pattern AND the request itself does not carry
     * private context. Method is restricted to safe reads (GET/HEAD)
     * so that mutations on the same paths are not misclassified.
     *
     * <p>Examples that match (suppressed as public lookup):
     * <ul>
     *   <li>{@code GET /v1/price/BTC} — public market data, no auth</li>
     *   <li>{@code GET /api/balance/0xABC...} — public blockchain lookup, no auth</li>
     *   <li>{@code GET /api/products/123} — public catalog item, no auth</li>
     *   <li>{@code GET /blog/posts/hello-world} — public content, no auth</li>
     *   <li>{@code GET /api/wallet/0x...} — public wallet, no auth</li>
     * </ul>
     *
     * <p>Examples that do NOT match (treated as business requests):
     * <ul>
     *   <li>{@code GET /api/users/me/balance} — has /me → private</li>
     *   <li>{@code GET /api/account/orders} — has /account → private</li>
     *   <li>{@code GET /api/products/123} with {@code Authorization: Bearer ...} → private</li>
     *   <li>{@code POST /api/products} — POST → not a lookup</li>
     *   <li>{@code GET /api/users/123} — has /users → private</li>
     * </ul>
     */
    private boolean isPublicResourceRequest(CapturedRequest request, String method, String path) {
        if (path == null) return false;
        String m = method == null ? "GET" : method.toUpperCase();
        if (!"GET".equals(m) && !"HEAD".equals(m)) return false;

        // Step 1: path must match a public-resource pattern.
        if (!noiseRules.isPublicResourcePath(path)) return false;

        // Step 2: the request must NOT carry private context.
        if (privateContextDetector.hasPrivateContext(request)) return false;

        return true;
    }

    public EndpointNormalizer getEndpointNormalizer() {
        return endpointNormalizer;
    }

    public NoiseRulesConfig getNoiseConfig() {
        return noiseConfig;
    }
}

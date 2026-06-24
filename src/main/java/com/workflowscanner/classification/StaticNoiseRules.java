package com.workflowscanner.classification;

import java.util.Set;

/**
 * Static rules for identifying noise requests (static assets, telemetry, preflights, etc.).
 * All methods are deterministic — no LLM calls.
 */
public class StaticNoiseRules {

    // File extensions that indicate static assets
    private static final Set<String> STATIC_EXTENSIONS = Set.of(
            ".css", ".js", ".jsx", ".ts", ".tsx", ".map", ".png", ".jpg", ".jpeg",
            ".gif", ".svg", ".ico", ".webp", ".avif", ".woff", ".woff2", ".ttf",
            ".eot", ".otf", ".pdf", ".doc", ".docx", ".mp4", ".mp3", ".webm",
            ".ogg", ".wav", ".flac", ".zip", ".gz", ".tar", ".rar", ".7z",
            ".exe", ".dmg", ".apk", ".deb", ".rpm", ".wasm");

    // File extensions that are static but may be worth partial processing (JS for endpoint discovery)
    private static final Set<String> PARTIAL_STATIC_EXTENSIONS = Set.of(".js", ".jsx", ".ts", ".tsx", ".map");

    // Path/domain keywords for analytics and telemetry
    private static final Set<String> TELEMETRY_PATH_KEYWORDS = Set.of(
            "analytics", "telemetry", "metrics", "beacon", "collect",
            "sentry", "datadog", "segment", "amplitude", "mixpanel",
            "hotjar", "google-analytics", "gtm", "gtag", "ga.js",
            "fbevents", "pixel", "track", "tracking", "logger",
            "log_event", "monitoring", "stats", "count", "impression",
            "pageview", "page_view", "visit", "activity", "rum");

    // Path patterns for health checks and monitoring
    private static final Set<String> HEALTH_CHECK_PATHS = Set.of(
            "/health", "/healthz", "/ready", "/readyz", "/live", "/livez",
            "/ping", "/pong", "/status", "/_ah/health",
            "/actuator/health", "/actuator/info",
            "/__lb", "/lbcheck", "/elb-status", "/nginx_status");

    // Background polling path keywords
    private static final Set<String> POLLING_PATH_KEYWORDS = Set.of(
            "notifications", "notification", "messages/unread", "unread-count",
            "unread_count", "heartbeat", "poll", "events", "feature-flags",
            "feature_flags", "flags", "config", "configuration",
            "/api/me", "/api/user", "/api/v1/me", "/api/v1/user",
            "session/refresh", "token/refresh", "keepalive", "keep-alive",
            "presence", "online", "typing", "sse", "websocket");

    // Third-party analytics/telemetry domains (partial match)
    private static final Set<String> THIRD_PARTY_DOMAINS = Set.of(
            "google-analytics.com", "googletagmanager.com", "doubleclick.net",
            "facebook.com", "fbsbx.com", "hotjar.com", "sentry.io",
            "datadoghq.com", "mixpanel.com", "amplitude.com", "segment.io",
            "segment.com", "fullstory.com", "crazyegg.com", "optimizely.com",
            "appdynamics.com", "newrelic.com", "nr-data.net");

    // CORS preflight headers
    private static final String ACCESS_CONTROL_REQUEST_METHOD = "Access-Control-Request-Method";
    private static final String ACCESS_CONTROL_REQUEST_HEADERS = "Access-Control-Request-Headers";

    /**
     * Check if a file path has a static asset extension.
     * Specifically excludes JS maps from static classification.
     */
    public static boolean isStaticExtension(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase();
        for (String ext : STATIC_EXTENSIONS) {
            if (lower.endsWith(ext)) return true;
        }
        return false;
    }

    /**
     * Check if a file is JS (useful for endpoint discovery but not workflow chaining).
     */
    public static boolean isJavaScriptFile(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase();
        return lower.endsWith(".js") || lower.endsWith(".jsx");
    }

    /**
     * Check if a file is a source map (always drop).
     */
    public static boolean isSourceMap(String path) {
        if (path == null) return false;
        return path.toLowerCase().endsWith(".map");
    }

    /**
     * Check if a path contains telemetry/analytics keywords.
     */
    public static boolean isTelemetryPath(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase();
        for (String keyword : TELEMETRY_PATH_KEYWORDS) {
            if (lower.contains(keyword)) return true;
        }
        return false;
    }

    /**
     * Check if a path is a health check endpoint.
     */
    public static boolean isHealthCheckPath(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase();
        for (String hcPath : HEALTH_CHECK_PATHS) {
            if (lower.equals(hcPath) || lower.startsWith(hcPath + "/") || lower.startsWith(hcPath + "?")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if a path matches polling patterns.
     */
    public static boolean isPollingPath(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase();
        for (String keyword : POLLING_PATH_KEYWORDS) {
            if (lower.contains(keyword)) return true;
        }
        return false;
    }

    /**
     * Check if a host is a known third-party tracking/analytics domain.
     */
    public static boolean isThirdPartyDomain(String host) {
        if (host == null) return false;
        String lower = host.toLowerCase();
        for (String domain : THIRD_PARTY_DOMAINS) {
            if (lower.contains(domain)) return true;
        }
        return false;
    }

    /**
     * Check if a request is a CORS preflight (OPTIONS with CORS headers).
     */
    public static boolean isCorsPreflight(String method, Set<String> headerNames) {
        if (!"OPTIONS".equalsIgnoreCase(method)) return false;
        if (headerNames == null) return false;
        return headerNames.contains(ACCESS_CONTROL_REQUEST_METHOD)
                || headerNames.contains(ACCESS_CONTROL_REQUEST_HEADERS);
    }

    /**
     * Check if a response MIME type indicates JSON (likely API).
     */
    public static boolean isJsonResponse(String mimeType) {
        return mimeType != null && (mimeType.contains("json")
                || mimeType.contains("application/json"));
    }

    /**
     * Check if a response MIME type indicates HTML (likely page load).
     */
    public static boolean isHtmlResponse(String mimeType) {
        return mimeType != null && mimeType.contains("html");
    }
}

package com.workflowscanner.classification;

import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Universal static rules for identifying noise requests (static
 * assets, telemetry, preflights, health checks, public-resource
 * paths, etc.). All methods are deterministic — no LLM calls.
 *
 * <p>Patterns are read from a {@link NoiseRulesConfig}; defaults are
 * universal across web targets. To override for a specific target,
 * pass a customised config to the constructor. To match the
 * historical / pre-refactor behaviour for a single test, instantiate
 * a default-constructed {@link NoiseRulesConfig} explicitly.
 */
public class StaticNoiseRules {

    private final NoiseRulesConfig config;

    // File extensions that indicate static assets. Universal across
    // web frameworks — the file extension alone is enough.
    private static final Set<String> STATIC_EXTENSIONS = Set.of(
            ".css", ".js", ".jsx", ".ts", ".tsx", ".map", ".png", ".jpg", ".jpeg",
            ".gif", ".svg", ".ico", ".webp", ".avif", ".woff", ".woff2", ".ttf",
            ".eot", ".otf", ".pdf", ".doc", ".docx", ".mp4", ".mp3", ".webm",
            ".ogg", ".wav", ".flac", ".zip", ".gz", ".tar", ".rar", ".7z",
            ".exe", ".dmg", ".apk", ".deb", ".rpm", ".wasm");

    // File extensions that are static but may be worth partial
    // processing (JS for endpoint discovery).
    private static final Set<String> PARTIAL_STATIC_EXTENSIONS = Set.of(".js", ".jsx", ".ts", ".tsx", ".map");

    // CORS preflight headers
    private static final String ACCESS_CONTROL_REQUEST_METHOD = "Access-Control-Request-Method";
    private static final String ACCESS_CONTROL_REQUEST_HEADERS = "Access-Control-Request-Headers";

    public StaticNoiseRules() {
        this(NoiseRulesConfig.withDefaults());
    }

    public StaticNoiseRules(NoiseRulesConfig config) {
        this.config = config != null ? config : NoiseRulesConfig.withDefaults();
    }

    public NoiseRulesConfig getConfig() {
        return config;
    }

    /**
     * Check if a file path has a static asset extension.
     * Specifically excludes JS maps from static classification.
     */
    public boolean isStaticExtension(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        for (String ext : STATIC_EXTENSIONS) {
            if (lower.endsWith(ext)) return true;
        }
        return false;
    }

    public static boolean isStaticExtensionStatic(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        for (String ext : STATIC_EXTENSIONS) {
            if (lower.endsWith(ext)) return true;
        }
        return false;
    }

    /**
     * Check if a file is JS (useful for endpoint discovery but not
     * workflow chaining).
     */
    public static boolean isJavaScriptFile(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        return lower.endsWith(".js") || lower.endsWith(".jsx");
    }

    /**
     * Check if a file is a source map (always drop).
     */
    public static boolean isSourceMap(String path) {
        if (path == null) return false;
        return path.toLowerCase(Locale.ROOT).endsWith(".map");
    }

    /**
     * Check if a path contains telemetry/analytics keywords.
     */
    public boolean isTelemetryPath(String path) {
        return pathContainsAny(path, config.getTelemetryPathPatterns());
    }

    /** Backward-compatible static accessor using default config. */
    public static boolean isTelemetryPathStatic(String path) {
        return pathContainsAnyStatic(path, NoiseRulesConfig.withDefaults().getTelemetryPathPatterns());
    }

    /**
     * Check if a path is a health check endpoint.
     */
    public boolean isHealthCheckPath(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        for (String hcPath : config.getHealthCheckPaths()) {
            if (lower.equals(hcPath) || lower.startsWith(hcPath + "/") || lower.startsWith(hcPath + "?")) {
                return true;
            }
        }
        return false;
    }

    /** Backward-compatible static accessor using default config. */
    public static boolean isHealthCheckPathStatic(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        for (String hcPath : NoiseRulesConfig.withDefaults().getHealthCheckPaths()) {
            if (lower.equals(hcPath) || lower.startsWith(hcPath + "/") || lower.startsWith(hcPath + "?")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if a path matches polling patterns.
     */
    public boolean isPollingPath(String path) {
        return pathContainsAny(path, config.getPollingPathPatterns());
    }

    /** Backward-compatible static accessor using default config. */
    public static boolean isPollingPathStatic(String path) {
        return pathContainsAnyStatic(path, NoiseRulesConfig.withDefaults().getPollingPathPatterns());
    }

    /**
     * Universal public-resource path check.
     *
     * <p>Returns true if the path matches a configured public-resource
     * pattern (e.g. {@code /price/}, {@code /products/},
     * {@code /blog/posts/}, {@code /balance/}). This is a path-only
     * check — it does NOT inspect the request body, headers, or any
     * private-context signals. Use
     * {@link com.workflowscanner.classification.PrivateContextDetector}
     * to decide whether the chain has private context.
     */
    public boolean isPublicResourcePath(String path) {
        return pathContainsAny(path, config.getPublicResourcePathPatterns());
    }

    /** Backward-compatible static accessor using default config. */
    public static boolean isPublicResourcePathStatic(String path) {
        return pathContainsAnyStatic(path, NoiseRulesConfig.withDefaults().getPublicResourcePathPatterns());
    }

    /**
     * Check if a path matches a feature-flag / config pattern.
     */
    public boolean isFeatureFlagPath(String path) {
        return pathContainsAny(path, config.getFeatureFlagPathPatterns());
    }

    /** Backward-compatible static accessor using default config. */
    public static boolean isFeatureFlagPathStatic(String path) {
        return pathContainsAnyStatic(path, NoiseRulesConfig.withDefaults().getFeatureFlagPathPatterns());
    }

    /**
     * True if the given cookie name is an infrastructure / anti-bot /
     * tracking cookie. Used by RelationshipDetector to suppress
     * {@code PARAM_REUSE} / {@code RESPONSE_CORRELATION} edges on
     * anti-bot cookies (Cloudflare, PerimeterX), tracking cookies
     * (Google Analytics, Amplitude, Mixpanel), and infrastructure
     * cookies (AWS ELB, JSESSIONID).
     *
     * <p>Match semantics: a cookie name matches if it equals the
     * pattern or starts with the pattern (so {@code _ga} matches
     * {@code _ga}, {@code _ga_XYZ}, etc.).
     */
    public boolean isInfrastructureOrTrackingCookie(String cookieName) {
        if (cookieName == null) return false;
        String lower = cookieName.toLowerCase(Locale.ROOT);
        for (String pattern : config.getInfrastructureCookieNames()) {
            if (pattern == null) continue;
            String pl = pattern.toLowerCase(Locale.ROOT);
            if (lower.equals(pl) || lower.startsWith(pl)) return true;
        }
        return false;
    }

    /** Backward-compatible static accessor using default config. */
    public static boolean isInfrastructureOrTrackingCookieStatic(String cookieName) {
        if (cookieName == null) return false;
        String lower = cookieName.toLowerCase(Locale.ROOT);
        for (String pattern : NoiseRulesConfig.withDefaults().getInfrastructureCookieNames()) {
            if (pattern == null) continue;
            String pl = pattern.toLowerCase(Locale.ROOT);
            if (lower.equals(pl) || lower.startsWith(pl)) return true;
        }
        return false;
    }

    /**
     * Check if a path matches context-read patterns (e.g. /api/me,
     * /api/user). These are not workflow steps but carry auth/user
     * context for the ApplicationModel.
     */
    public boolean isContextReadPath(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        for (String cp : config.getContextReadPaths()) {
            if (lower.equals(cp) || lower.startsWith(cp + "?")) {
                return true;
            }
        }
        return false;
    }

    /** Backward-compatible static accessor using default config. */
    public static boolean isContextReadPathStatic(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        for (String cp : NoiseRulesConfig.withDefaults().getContextReadPaths()) {
            if (lower.equals(cp) || lower.startsWith(cp + "?")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Method-aware context read check. Only safe methods (GET/HEAD)
     * are treated as context reads. POST/PUT/PATCH/DELETE to the
     * same paths are real workflow actions and must NOT be
     * suppressed.
     */
    public boolean isContextReadPath(String path, String method) {
        if (!isContextReadPath(path)) return false;
        if (method == null) return true;
        String m = method.trim().toUpperCase(Locale.ROOT);
        return "GET".equals(m) || "HEAD".equals(m);
    }

    /**
     * Check if a host is a known third-party tracking/analytics
     * domain or telemetry vendor.
     */
    public boolean isThirdPartyDomain(String host) {
        if (host == null) return false;
        String lower = host.toLowerCase(Locale.ROOT);
        for (String domain : config.getTelemetryHostPatterns()) {
            if (lower.contains(domain)) return true;
        }
        return false;
    }

    /** Backward-compatible static accessor using default config. */
    public static boolean isThirdPartyDomainStatic(String host) {
        if (host == null) return false;
        String lower = host.toLowerCase(Locale.ROOT);
        for (String domain : NoiseRulesConfig.withDefaults().getTelemetryHostPatterns()) {
            if (lower.contains(domain)) return true;
        }
        return false;
    }

    /**
     * Check if a request is a CORS preflight (OPTIONS with CORS
     * headers).
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

    // ---------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------

    private static boolean pathContainsAny(String path, List<String> patterns) {
        if (path == null || patterns == null) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        for (String p : patterns) {
            if (p == null) continue;
            String pl = p.toLowerCase(Locale.ROOT);
            if (lower.contains(pl)) return true;
        }
        return false;
    }

    private static boolean pathContainsAnyStatic(String path, List<String> patterns) {
        return pathContainsAny(path, patterns);
    }
}

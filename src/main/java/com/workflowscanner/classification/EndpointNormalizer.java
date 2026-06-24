package com.workflowscanner.classification;

import com.workflowscanner.data.CapturedRequest;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Normalizes URLs by replacing dynamic path segments (object IDs, tokens) with
 * type-based templates. Two requests to different resources of the same type
 * produce the same normalized path.
 *
 * Examples:
 *   /api/users/123       -> /api/users/{int}
 *   /api/users/abc-def   -> /api/users/{uuid}
 *   /api/orders/6f7a9d   -> /api/orders/{hex24}
 *   /api/files/550e8400-e29b-41d4-a716-446655440000 -> /api/files/{uuid}
 *   /posts/2024/01/post-title -> /posts/{int}/{int}/{slug}
 */
public class EndpointNormalizer {

    // Pattern for UUIDs
    private static final Pattern UUID_PATTERN =
            Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                    Pattern.CASE_INSENSITIVE);

    // Pattern for hex strings (8+ hex chars)
    private static final Pattern HEX_PATTERN =
            Pattern.compile("^[0-9a-f]{8,}$", Pattern.CASE_INSENSITIVE);

    // Pattern for numeric IDs
    private static final Pattern NUMERIC_PATTERN = Pattern.compile("^\\d{3,}$");

    // Pattern for base64-like tokens (alphanumeric + underscore/dash, 20+ chars)
    private static final Pattern TOKEN_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{20,}$");

    // Pattern for slugs (lowercase words with hyphens)
    private static final Pattern SLUG_PATTERN = Pattern.compile("^[a-z0-9]+(-[a-z0-9]+)*$");

    /**
     * Normalize a captured request into an EndpointKey.
     */
    public EndpointKey normalize(CapturedRequest request) {
        if (request == null) return null;
        String path = request.getPath();
        if (path == null || path.isEmpty()) path = "/";

        String normalizedPath = normalizePath(path);
        Set<String> paramNames = request.getQueryParams() != null
                ? request.getQueryParams().keySet()
                : new HashSet<>();

        return new EndpointKey(
                request.getMethod(),
                request.getHost(),
                normalizedPath,
                paramNames
        );
    }

    /**
     * Normalize a URL path by replacing dynamic segments with type templates.
     */
    public static String normalizePath(String path) {
        if (path == null || path.isEmpty()) return "/";

        String[] segments = path.split("/");
        StringBuilder result = new StringBuilder();

        for (String segment : segments) {
            if (segment.isEmpty()) continue;

            String replacement = classifySegment(segment);
            if (replacement != null) {
                result.append("/").append(replacement);
            } else {
                result.append("/").append(segment);
            }
        }

        if (result.length() == 0) return "/";
        return result.toString();
    }

    /**
     * Classify a single path segment. Returns a template placeholder if it
     * looks like an ID/token, or null if it's a static segment name.
     */
    private static String classifySegment(String segment) {
        if (segment == null || segment.isEmpty()) return null;

        // UUID
        if (UUID_PATTERN.matcher(segment).matches()) return "{uuid}";

        // Numeric ID (3+ digits)
        if (NUMERIC_PATTERN.matcher(segment).matches()) return "{int}";

        // Long hex token (8+ hex chars)
        if (HEX_PATTERN.matcher(segment).matches()) return "{hex}";

        // Long alphanumeric token (20+ chars)
        if (TOKEN_PATTERN.matcher(segment).matches()) return "{token}";

        // Slug pattern and not a known static keyword
        if (SLUG_PATTERN.matcher(segment).matches() && segment.length() > 12
                && !isStaticKeyword(segment)) return "{slug}";

        return null; // Static segment, keep as-is
    }

    // Known short path segments that should never be normalized away
    private static boolean isStaticKeyword(String segment) {
        String lower = segment.toLowerCase();
        return lower.equals("admin") || lower.equals("api") || lower.equals("v1")
                || lower.equals("v2") || lower.equals("v3") || lower.equals("rest")
                || lower.equals("graphql") || lower.equals("static") || lower.equals("assets")
                || lower.equals("public") || lower.equals("private") || lower.equals("download")
                || lower.equals("upload") || lower.equals("search") || lower.equals("login")
                || lower.equals("logout") || lower.equals("signin") || lower.equals("signup")
                || lower.equals("register") || lower.equals("settings") || lower.equals("profile")
                || lower.equals("dashboard") || lower.equals("home") || lower.equals("index")
                || lower.equals("health") || lower.equals("status") || lower.equals("ping");
    }
}

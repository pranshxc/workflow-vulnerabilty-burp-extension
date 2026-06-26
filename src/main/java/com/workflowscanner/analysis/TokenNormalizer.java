package com.workflowscanner.analysis;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Token normalizer for the target vocabulary learner.
 *
 * <p>Goals:
 * <ul>
 *   <li>Extract meaningful words from path segments, parameter
 *       names, and JSON keys.</li>
 *   <li>Handle camelCase, snake_case, kebab-case uniformly.</li>
 *   <li>Strip common suffixes (_id, Id, _number, No) and numeric
 *       segments.</li>
 *   <li>Skip stop words and infra tokens so the vocabulary does
 *       not learn "api", "v1", "metrics", etc.</li>
 * </ul>
 *
 * <p>Simple rules — no NLP library. The output is a list of
 * normalized, lower-case, de-duplicated terms.
 */
public final class TokenNormalizer {

    /** Infra / boring tokens that should never be learned. */
    private static final Set<String> STOP_WORDS = new LinkedHashSet<>(Arrays.asList(
            "api", "apis", "v1", "v2", "v3", "v4",
            "get", "set", "list", "data", "info", "config",
            "static", "assets", "asset", "js", "css", "img",
            "image", "images", "file", "files", "public",
            "null", "true", "false", "page", "pages",
            "size", "limit", "offset", "sort", "filter", "q",
            "json", "xml", "html", "txt", "log", "logs",
            "new", "old", "tmp", "temp", "test", "tests",
            "http", "https", "ws", "wss", "url"
    ));

    /** Infra / observability tokens. */
    private static final Set<String> INFRA_TOKENS = new LinkedHashSet<>(Arrays.asList(
            "metrics", "collect", "telemetry", "feature", "features",
            "flags", "sentry", "analytics", "tracking", "track",
            "monitoring", "health", "ping", "pong", "ready",
            "readyz", "livez", "version", "status", "alive",
            "faro", "unleash", "amplitude", "mixpanel", "segment",
            "datadog", "prometheus", "grafana", "otel", "loggly"
    ));

    /** Suffixes to strip from the end of a token. */
    private static final String[] ID_SUFFIXES = {
            "_id", "id", "_ids", "ids",
            "_number", "number", "_no", "no",
            "_code", "code", "_key", "key",
            "_uuid", "uuid", "_guid", "guid",
            "_token", "token", "_hash", "hash"
    };

    /** Plurals to singularize (very basic). */
    private static final String[] PLURAL_SUFFIXES = {"ies", "es", "s"};

    private TokenNormalizer() {}

    /**
     * Normalize an input string into a list of clean tokens.
     * Applies camel/snake/kebab splitting, ID suffix stripping,
     * singularization, and stop-word/infra filtering.
     */
    public static List<String> normalize(String input) {
        if (input == null || input.isEmpty()) return List.of();
        List<String> out = new ArrayList<>();
        // Step 1: split on non-alphanumeric boundaries
        for (String raw : splitBoundaries(input)) {
            if (raw.isEmpty()) continue;
            // Step 2: split camelCase / PascalCase
            for (String part : splitCamelCase(raw)) {
                if (part.isEmpty()) continue;
                String lower = part.toLowerCase(Locale.ROOT);
                if (lower.isEmpty()) continue;
                if (STOP_WORDS.contains(lower)) continue;
                if (INFRA_TOKENS.contains(lower)) continue;
                // Step 3: strip numeric-only tokens
                if (isNumeric(lower)) continue;
                // Step 4: strip ID suffixes
                String stripped = stripIdSuffix(lower);
                if (STOP_WORDS.contains(stripped)) continue;
                if (INFRA_TOKENS.contains(stripped)) continue;
                // Step 5: singularize
                String singular = singularize(stripped);
                if (singular.length() < 2) continue;
                if (STOP_WORDS.contains(singular)) continue;
                out.add(singular);
            }
        }
        // Deduplicate, preserve insertion order
        return new ArrayList<>(new LinkedHashSet<>(out));
    }

    /**
     * Convenience: extract path-segment tokens from a URL path.
     * Skips the leading slash and empty segments.
     */
    public static List<String> normalizePath(String path) {
        if (path == null) return List.of();
        List<String> out = new ArrayList<>();
        for (String seg : path.split("/")) {
            if (seg.isEmpty()) continue;
            if (isNumeric(seg)) continue;
            out.addAll(normalize(seg));
        }
        return out;
    }

    /** Last segment of a path, normalized. */
    public static String lastPathSegment(String path) {
        if (path == null) return null;
        String[] segs = path.split("/");
        for (int i = segs.length - 1; i >= 0; i--) {
            if (!segs[i].isEmpty() && !isNumeric(segs[i])) {
                List<String> norm = normalize(segs[i]);
                return norm.isEmpty() ? null : norm.get(0);
            }
        }
        return null;
    }

    static String[] splitBoundaries(String input) {
        // Split on /, -, _, ., space, and any non-alphanumeric
        return input.split("[\\s\\-_.:/\\\\|]+");
    }

    static String[] splitCamelCase(String input) {
        // Insert a space before every uppercase letter that follows
        // a lowercase letter or digit, then split.
        // "userId" -> "user Id", "APIKey" -> "API Key", "v2Beta" -> "v2 Beta"
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (i > 0 && Character.isUpperCase(c)) {
                char prev = input.charAt(i - 1);
                if (Character.isLowerCase(prev) || Character.isDigit(prev)) {
                    sb.append(' ');
                }
            }
            sb.append(c);
        }
        return sb.toString().split("\\s+");
    }

    static String stripIdSuffix(String token) {
        for (String suf : ID_SUFFIXES) {
            if (token.length() > suf.length() && token.endsWith(suf)) {
                String head = token.substring(0, token.length() - suf.length());
                if (head.length() >= 2) return head;
            }
        }
        return token;
    }

    static String singularize(String token) {
        if (token.length() < 4) return token;
        // "categories" -> "category"
        if (token.endsWith("ies") && !token.endsWith("eies")) {
            return token.substring(0, token.length() - 3) + "y";
        }
        // Sibilant plurals: "addresses" -> "address", "boxes" -> "box",
        // "batches" -> "batch", "licenses" -> "license".
        // Strip "es" only when preceded by a sibilant.
        if (token.endsWith("ches") || token.endsWith("shes")
                || token.endsWith("xes") || token.endsWith("zes")
                || token.endsWith("ses") || token.endsWith("sses")) {
            return token.substring(0, token.length() - 2);
        }
        // "-ies" handled above. "-es" preceded by a non-sibilant
        // letter is a false plural — e.g. "mandates" is not the
        // plural of "mandate" (which is "mandate"+"s" = "mandates",
        // not "mandate"+"es"). Leave these alone and just strip
        // the trailing "s" if present.
        if (token.endsWith("es") && !token.endsWith("ees") && !token.endsWith("oes")) {
            // "cases" is "case"+"s", not "cas"+"es". Strip just "s".
            if (token.length() >= 5) {
                return token.substring(0, token.length() - 1);
            }
            return token;
        }
        if (token.endsWith("s") && !token.endsWith("ss") && !token.endsWith("us")) {
            return token.substring(0, token.length() - 1);
        }
        return token;
    }

    static boolean isNumeric(String s) {
        if (s.isEmpty()) return false;
        for (int i = 0; i < s.length(); i++) {
            if (!Character.isDigit(s.charAt(i))) return false;
        }
        return true;
    }
}

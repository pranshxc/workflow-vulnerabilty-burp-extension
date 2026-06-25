package com.workflowscanner.classification;

import com.workflowscanner.data.CapturedRequest;
import com.workflowscanner.graph.RequestNode;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Detects whether a chain of requests carries <b>private / user-bound
 * context</b>. The detector is universal — it works for any target by
 * inspecting:
 *
 * <ul>
 *   <li><b>Request path</b> — any path matching
 *       {@link NoiseRulesConfig#getPrivateResourcePathPatterns()} indicates
 *       user-bound access (e.g. {@code /me}, {@code /account},
 *       {@code /admin}, {@code /billing}).</li>
 *   <li><b>Request headers</b> — presence of an auth/identity header
 *       (Authorization, Cookie, X-Auth-Token, etc.) indicates the
 *       request is acting on behalf of an authenticated user.</li>
 *   <li><b>Response body</b> — appearance of a private field name
 *       (email, phone, role, api_key, etc.) indicates the response
 *       carries user-specific data.</li>
 *   <li><b>Classification intent</b> — a step classified as
 *       {@link RequestIntent#AUTHENTICATION} or
 *       {@link RequestIntent#CONTEXT_READ} is itself a private-context
 *       signal.</li>
 * </ul>
 *
 * <p>This is the single, generic replacement for the
 * "blockchain / public-data" detection that was hard-coded for the
 * 1inch dataset. It must be called <b>before</b> the public-resource
 * classifier so that a request like
 * {@code /api/users/me/balance} is not misclassified as a public
 * lookup.
 */
public class PrivateContextDetector {

    private final NoiseRulesConfig config;

    public PrivateContextDetector(NoiseRulesConfig config) {
        this.config = config != null ? config : NoiseRulesConfig.withDefaults();
    }

    /**
     * Return true if the request itself carries private / user-bound
     * context. Inspects path, request headers, response body, and
     * classification intent.
     */
    public boolean hasPrivateContext(CapturedRequest req) {
        if (req == null) return false;
        if (pathMatches(req.getPath(), config.getPrivateResourcePathPatterns())) return true;
        if (pathMatches(req.getUrl(), config.getPrivateResourcePathPatterns())) return true;
        if (hasPrivateHeader(req.getRequestHeaders())) return true;
        if (hasPrivateResponseField(req.getResponseBody())) return true;
        return false;
    }

    /**
     * Return true if the request-node (post-classification) carries
     * private / user-bound context. Identical logic to
     * {@link #hasPrivateContext(CapturedRequest)} plus an intent check.
     */
    public boolean hasPrivateContext(RequestNode node) {
        if (node == null) return false;
        if (node.getClassification() != null) {
            RequestIntent intent = node.getClassification().getIntent();
            if (intent == RequestIntent.AUTHENTICATION
                    || intent == RequestIntent.CONTEXT_READ) {
                return true;
            }
        }
        if (pathMatches(node.getPath(), config.getPrivateResourcePathPatterns())) return true;
        if (pathMatches(node.getUrl(), config.getPrivateResourcePathPatterns())) return true;
        if (hasPrivateHeader(node.getRequestHeaders())) return true;
        if (hasPrivateResponseField(node.getResponseBody())) return true;
        return false;
    }

    /**
     * Return true if <b>any</b> step in the chain carries private
     * context. This is the canonical check used by the reportability
     * gate and the analysis engine.
     */
    public boolean chainHasPrivateContext(List<RequestNode> steps) {
        if (steps == null || steps.isEmpty()) return false;
        for (RequestNode n : steps) {
            if (hasPrivateContext(n)) return true;
        }
        return false;
    }

    /**
     * Convenience for the gate: returns the first step in the chain
     * that exhibits private context, or null if none do. Used for
     * logging.
     */
    public RequestNode findPrivateContextStep(List<RequestNode> steps) {
        if (steps == null) return null;
        for (RequestNode n : steps) {
            if (hasPrivateContext(n)) return n;
        }
        return null;
    }

    // ---------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------

    private static boolean pathMatches(String path, List<String> patterns) {
        if (path == null || patterns == null) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        for (String p : patterns) {
            if (p == null) continue;
            String pl = p.toLowerCase(Locale.ROOT);
            if (lower.contains(pl)) return true;
        }
        return false;
    }

    private boolean hasPrivateHeader(Map<String, List<String>> headers) {
        if (headers == null || headers.isEmpty()) return false;
        Set<String> lowered = config.getPrivateRequestHeaders().stream()
                .map(s -> s.toLowerCase(Locale.ROOT))
                .collect(java.util.stream.Collectors.toSet());
        for (String name : headers.keySet()) {
            if (name == null) continue;
            String lname = name.toLowerCase(Locale.ROOT);
            if (!lowered.contains(lname)) continue;

            List<String> values = headers.get(name);
            if (values == null || values.isEmpty()) return true;
            String v = String.join(";", values);

            if ("cookie".equals(lname)) {
                // Cookie header: parse into individual cookies and
                // require at least one NON-tracking cookie to be
                // present. Anti-bot / tracking cookies alone do NOT
                // count as private context.
                if (cookieHeaderHasAuthContext(v)) return true;
            } else {
                // Authorization / X-Auth-Token / etc — any non-empty
                // value is sufficient.
                return true;
            }
        }
        return false;
    }

    /**
     * True if the Cookie header value contains at least one cookie
     * whose name is NOT in the anti-bot / tracking
     * {@link NoiseRulesConfig#getInfrastructureCookieNames()} list.
     *
     * <p>The check is per-cookie, not per-header: a header like
     * {@code Cookie: __cf_bm=abc; session=xyz} is auth-bound because
     * the {@code session} cookie is present. A header like
     * {@code Cookie: __cf_bm=abc; _ga=GA1.2.123} is NOT
     * auth-bound because both cookies are anti-bot/tracking.
     *
     * <p>If a cookie name matches an entry in
     * {@link NoiseRulesConfig#getAuthSessionCookieNames()} (e.g.
     * {@code session}, {@code JSESSIONID}, {@code PHPSESSID},
     * {@code connect.sid}, {@code auth}, {@code token}, {@code jwt}),
     * the header is auth-bound.
     *
     * <p>Unknown cookies that don't match either list are treated
     * as potentially auth-bound (most apps ship a session cookie
     * the heuristic doesn't know about).
     */
    private boolean cookieHeaderHasAuthContext(String cookieValue) {
        if (cookieValue == null || cookieValue.isEmpty()) return false;
        String[] cookies = cookieValue.split(";");
        boolean sawAtLeastOneCookie = false;
        for (String raw : cookies) {
            String trimmed = raw.trim();
            if (trimmed.isEmpty()) continue;
            sawAtLeastOneCookie = true;
            int eq = trimmed.indexOf('=');
            String name = eq < 0 ? trimmed : trimmed.substring(0, eq);
            String lname = name.toLowerCase(Locale.ROOT);
            if (lname.isEmpty()) continue;
            // Anti-bot / tracking cookie — does NOT make header
            // auth-bound, but it does not block other cookies
            // from making it auth-bound.
            if (matchesAnyPrefix(lname, config.getInfrastructureCookieNames())) {
                continue;
            }
            // Session-like / auth-like cookie → header is auth-bound.
            if (matchesAnyPrefix(lname, config.getAuthSessionCookieNames())) {
                return true;
            }
            // Unknown cookie — treat as potentially auth-bound.
            // Most apps ship at least one session cookie; better
            // to over-report private context than to miss a real
            // authenticated request.
            return true;
        }
        return false;
    }

    private static boolean matchesAnyPrefix(String name, List<String> patterns) {
        if (name == null || patterns == null) return false;
        for (String p : patterns) {
            if (p == null) continue;
            String pl = p.toLowerCase(Locale.ROOT);
            if (name.equals(pl) || name.startsWith(pl)) return true;
        }
        return false;
    }

    private boolean hasPrivateResponseField(String body) {
        if (body == null || body.isEmpty()) return false;
        String lower = body.toLowerCase(Locale.ROOT);
        for (String field : config.getPrivateResponseFields()) {
            if (field == null) continue;
            String fl = field.toLowerCase(Locale.ROOT);
            // Match "field": or "field": or "field=" or "<field>" in JSON
            // or key=value in form data. A simple substring check is
            // enough for detection purposes (we are not parsing the
            // JSON, just looking for the field name).
            if (lower.contains("\"" + fl + "\"")
                    || lower.contains(fl + "=")
                    || lower.contains(fl + ":")) {
                return true;
            }
        }
        return false;
    }
}

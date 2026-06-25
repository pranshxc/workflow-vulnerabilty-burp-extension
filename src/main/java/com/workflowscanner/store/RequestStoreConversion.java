package com.workflowscanner.store;

import com.workflowscanner.classification.EndpointKey;
import com.workflowscanner.classification.RequestClassification;
import com.workflowscanner.classification.RequestIntent;
import com.workflowscanner.data.CapturedRequest;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Bridges the in-process {@link CapturedRequest} pipeline model to the
 * on-disk {@link RequestStore} model.
 *
 * <p>The store needs a compact {@link RequestSummary} and (optionally)
 * the full {@link RawHttp}. This helper builds both from a single
 * {@code CapturedRequest} plus its classification, without keeping
 * the heavy data on the heap any longer than needed.
 *
 * <p>Used by {@code GraphBuilder.processRequest} for every request,
 * including suppressed ones: the store is the canonical record; the
 * hot in-memory graph is a working view.
 */
public final class RequestStoreConversion {

    // Same auth cookie names the WorkflowSessionizer uses, kept
    // here so the store can derive a stable session identity
    // without round-tripping through the in-memory graph.
    private static final List<String> AUTH_COOKIE_NAMES = List.of(
            "session", "sessionid", "sid", "phpsessid", "jsessionid",
            "connect.sid", "_auth", "auth", "access_token", "refresh_token",
            "rememberme", "remember_me", "xsrf-token", "x-csrf-token",
            "__cfduid", "cfid", "cftoken");

    private RequestStoreConversion() {}

    /**
     * Build a {@link RequestSummary} from a captured request and its
     * classification. The id, timestamp, method, host, path, status,
     * and workflow-relevance flag are copied directly. The intent
     * and endpoint key are taken from the classification. The
     * session key is derived here (host + auth-cookie-hash +
     * referrer-family) so streaming consumers can group requests
     * by session without re-parsing headers.
     */
    public static RequestSummary summaryOf(CapturedRequest request,
                                           RequestClassification classification) {
        long ts = request.getTimestamp();
        String method = request.getMethod();
        String host = request.getHost();
        String path = request.getPath();
        int status = request.getStatusCode();
        boolean relevant = classification != null && classification.isWorkflowRelevant();
        boolean hasRaw = request.getRequestBody() != null
                || request.getResponseBody() != null
                || !request.getRequestHeaders().isEmpty()
                || !request.getResponseHeaders().isEmpty();
        String endpointKeyStr = null;
        if (classification != null && classification.getEndpointKey() != null) {
            endpointKeyStr = endpointKeyToString(classification.getEndpointKey());
        }
        String intentStr = null;
        if (classification != null && classification.getIntent() != null) {
            intentStr = classification.getIntent().name();
        }
        String sessionKey = buildSessionKey(request);
        long size = approxSize(request);
        return new RequestSummary(
                request.getId(),
                ts,
                method,
                host,
                path,
                status,
                relevant,
                hasRaw,
                endpointKeyStr,
                sessionKey,
                intentStr,
                size);
    }

    /**
     * Build a {@link RawHttp} from a captured request. Returns null
     * if the captured request has neither headers nor bodies — the
     * caller is free to pass null in that case.
     */
    public static RawHttp rawOf(CapturedRequest request) {
        if (request == null) return null;
        if (!hasAnyPayload(request)) return null;
        return new RawHttp(
                request.getRequestHeaders(),
                request.getRequestBody(),
                request.getResponseHeaders(),
                request.getResponseBody(),
                request.getMimeType(),
                joinList(request.getCookies(), "; "),
                joinQueryParams(request.getQueryParams()),
                request.getReferrer());
    }

    /**
     * Derive a compact session key. The key groups together
     * requests from the same host with the same auth cookie hash
     * and the same referrer family. This matches the
     * {@code WorkflowSessionizer} grouping so the store-level
     * session key is consistent with the in-memory one.
     */
    static String buildSessionKey(CapturedRequest request) {
        if (request == null) return null;
        String host = request.getHost() != null ? request.getHost().toLowerCase() : "";
        String authHash = authCookieHash(request);
        String referrerFamily = referrerFamily(request.getReferrer());
        // Concatenate as "host|authHash|refFamily" so a streaming
        // consumer can split or substring-search it.
        return host + "|" + authHash + "|" + referrerFamily;
    }

    private static String authCookieHash(CapturedRequest request) {
        Map<String, List<String>> headers = request.getRequestHeaders();
        if (headers == null || headers.isEmpty()) return "";
        // Parse Cookie header to a name->value map.
        Map<String, String> cookies = new LinkedHashMap<>();
        List<String> cookieH = headers.get("Cookie");
        if (cookieH == null) cookieH = headers.get("cookie");
        if (cookieH != null) {
            for (String header : cookieH) {
                if (header == null) continue;
                for (String pair : header.split(";")) {
                    int eq = pair.indexOf('=');
                    if (eq < 0) continue;
                    String name = pair.substring(0, eq).trim();
                    String value = pair.substring(eq + 1).trim();
                    if (!name.isEmpty()) cookies.put(name, value);
                }
            }
        }
        StringBuilder auth = new StringBuilder();
        for (String name : AUTH_COOKIE_NAMES) {
            String v = cookies.get(name);
            if (v != null && !v.isEmpty()) {
                if (auth.length() > 0) auth.append('|');
                auth.append(name).append('=').append(v);
            }
        }
        // Also include Authorization Bearer tokens and X-Auth-Token
        // so APIs that use header-based auth still get a stable
        // session key.
        List<String> authH = headers.get("Authorization");
        if (authH == null) authH = headers.get("authorization");
        if (authH != null) {
            for (String h : authH) {
                if (h != null && h.startsWith("Bearer ")) {
                    if (auth.length() > 0) auth.append('|');
                    auth.append("Bearer=").append(h.substring(7));
                }
            }
        }
        List<String> xAuth = headers.get("X-Auth-Token");
        if (xAuth == null) xAuth = headers.get("x-auth-token");
        if (xAuth != null && !xAuth.isEmpty() && xAuth.get(0) != null) {
            if (auth.length() > 0) auth.append('|');
            auth.append("X-Auth-Token=").append(xAuth.get(0));
        }
        if (auth.length() == 0) return "";   // anonymous
        return sha256Hex(auth.toString());
    }

    private static String referrerFamily(String referrer) {
        if (referrer == null || referrer.isEmpty()) return "";
        try {
            java.net.URI uri = java.net.URI.create(referrer);
            String path = uri.getRawPath();
            if (path == null || path.isEmpty() || path.equals("/")) return "/";
            String[] segments = path.split("/");
            StringBuilder family = new StringBuilder();
            int count = 0;
            for (String seg : segments) {
                if (!seg.isEmpty()) {
                    family.append('/').append(seg.toLowerCase());
                    if (++count >= 3) break;
                }
            }
            return family.toString();
        } catch (IllegalArgumentException e) {
            return "";
        }
    }

    private static boolean hasAnyPayload(CapturedRequest r) {
        return (r.getRequestHeaders() != null && !r.getRequestHeaders().isEmpty())
                || (r.getResponseHeaders() != null && !r.getResponseHeaders().isEmpty())
                || notEmpty(r.getRequestBody())
                || notEmpty(r.getResponseBody())
                || notEmpty(r.getReferrer())
                || (r.getCookies() != null && !r.getCookies().isEmpty())
                || (r.getQueryParams() != null && !r.getQueryParams().isEmpty());
    }

    private static boolean notEmpty(String s) { return s != null && !s.isEmpty(); }

    private static long approxSize(CapturedRequest r) {
        long n = 0;
        if (r.getRequestBody() != null) n += r.getRequestBody().length();
        if (r.getResponseBody() != null) n += r.getResponseBody().length();
        if (r.getRequestHeaders() != null) {
            for (Map.Entry<String, List<String>> e : r.getRequestHeaders().entrySet()) {
                n += e.getKey().length();
                for (String v : e.getValue()) n += v.length();
            }
        }
        if (r.getResponseHeaders() != null) {
            for (Map.Entry<String, List<String>> e : r.getResponseHeaders().entrySet()) {
                n += e.getKey().length();
                for (String v : e.getValue()) n += v.length();
            }
        }
        return n;
    }

    private static String joinList(List<String> list, String sep) {
        if (list == null || list.isEmpty()) return null;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) sb.append(sep);
            sb.append(list.get(i));
        }
        return sb.toString();
    }

    private static String joinQueryParams(Map<String, String> q) {
        if (q == null || q.isEmpty()) return null;
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (Map.Entry<String, String> e : q.entrySet()) {
            if (!first) sb.append('&');
            first = false;
            sb.append(e.getKey());
            if (e.getValue() != null) {
                sb.append('=');
                sb.append(e.getValue());
            }
        }
        return sb.toString();
    }

    private static String endpointKeyToString(EndpointKey ek) {
        if (ek == null) return null;
        return ek.getMethod() + " " + ek.getHost() + ek.getNormalizedPath();
    }

    private static String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            return Integer.toHexString(input.hashCode());
        }
    }
}

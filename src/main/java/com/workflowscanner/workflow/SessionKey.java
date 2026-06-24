package com.workflowscanner.workflow;

import java.util.Objects;

/**
 * Groups requests by session for workflow detection.
 * Segments by host + auth cookie hash + top-level referrer path,
 * so requests from different users or different page contexts
 * produce different session keys.
 */
public class SessionKey {
    private final String host;
    private final String authCookieHash; // SHA-256 of session cookie values (or empty string if none)
    private final String referrerPath;   // Top-level referrer path for segmentation

    public SessionKey(String host, String authCookieHash, String referrerPath) {
        this.host = host != null ? host.toLowerCase() : "";
        this.authCookieHash = authCookieHash != null ? authCookieHash : "";
        this.referrerPath = referrerPath != null ? referrerPath : "";
    }

    public String getHost() { return host; }
    public String getAuthCookieHash() { return authCookieHash; }
    public String getReferrerPath() { return referrerPath; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SessionKey that = (SessionKey) o;
        return host.equals(that.host) && authCookieHash.equals(that.authCookieHash)
                && referrerPath.equals(that.referrerPath);
    }

    @Override
    public int hashCode() {
        return Objects.hash(host, authCookieHash, referrerPath);
    }

    @Override
    public String toString() {
        return host + "|" + (authCookieHash.isEmpty() ? "anon" : authCookieHash.substring(0, 8))
                + "|" + referrerPath;
    }
}

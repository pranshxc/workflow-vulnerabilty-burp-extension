package com.workflowscanner.classification;

import java.util.Objects;
import java.util.Set;

/**
 * Canonical identity for an API endpoint, with normalized path template.
 * Two requests to different object IDs (e.g. /api/users/123 and /api/users/456)
 * produce the same EndpointKey: GET, /api/users/{id}.
 */
public class EndpointKey {
    private final String method;
    private final String host;
    private final String normalizedPath;
    private final Set<String> queryParamNames;

    public EndpointKey(String method, String host, String normalizedPath, Set<String> queryParamNames) {
        this.method = method != null ? method.toUpperCase() : "GET";
        this.host = host != null ? host.toLowerCase() : "";
        this.normalizedPath = normalizedPath != null ? normalizedPath : "";
        this.queryParamNames = queryParamNames != null ? queryParamNames : Set.of();
    }

    public String getMethod() { return method; }
    public String getHost() { return host; }
    public String getNormalizedPath() { return normalizedPath; }
    public Set<String> getQueryParamNames() { return queryParamNames; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EndpointKey that = (EndpointKey) o;
        return method.equals(that.method) && host.equals(that.host)
                && normalizedPath.equals(that.normalizedPath);
    }

    @Override
    public int hashCode() {
        return Objects.hash(method, host, normalizedPath);
    }

    @Override
    public String toString() {
        return method + " " + host + normalizedPath;
    }
}

package com.workflowscanner.data;

import com.workflowscanner.config.ExtensionConfig;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Applies scope filter patterns from configuration.
 * Supports glob patterns (e.g., *.example.com, *.example.*).
 * Converts globs to regex at load time for performance.
 * Thread-safe: can be reloaded when config changes.
 */
public class ScopeFilter {

    private volatile List<Pattern> compiledPatterns;
    private volatile List<String> rawPatterns;

    public ScopeFilter(ExtensionConfig config) {
        reload(config);
    }

    /**
     * Reload patterns from config. Called when scope filter settings change.
     */
    public void reload(ExtensionConfig config) {
        List<String> patterns = config.getScopeFilterPatterns();
        List<Pattern> compiled = new ArrayList<>();
        List<String> raw = new ArrayList<>();

        if (patterns != null) {
            for (String glob : patterns) {
                if (glob != null && !glob.trim().isEmpty()) {
                    compiled.add(globToRegex(glob.trim()));
                    raw.add(glob.trim());
                }
            }
        }

        this.compiledPatterns = Collections.unmodifiableList(compiled);
        this.rawPatterns = Collections.unmodifiableList(raw);
    }

    /**
     * Check if a hostname matches any scope filter pattern.
     * If no patterns are configured, everything is in scope.
     */
    public boolean isInScope(String hostname) {
        List<Pattern> patterns = this.compiledPatterns;
        if (patterns.isEmpty()) {
            return true; // No filters = everything in scope
        }
        if (hostname == null || hostname.isEmpty()) {
            return false;
        }
        for (Pattern pattern : patterns) {
            if (pattern.matcher(hostname).matches()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if a full URL is in scope (extracts hostname and checks).
     */
    public boolean isUrlInScope(String url) {
        if (url == null) return false;
        String host = RequestConverter.extractHost(url);
        return isInScope(host);
    }

    /**
     * Count how many of the given hostnames match the scope filter.
     */
    public int countMatching(List<String> hostnames) {
        int count = 0;
        for (String host : hostnames) {
            if (isInScope(host)) count++;
        }
        return count;
    }

    /**
     * Convert a glob pattern to a compiled regex Pattern.
     * Supports: * (any chars), ? (single char)
     */
    static Pattern globToRegex(String glob) {
        StringBuilder regex = new StringBuilder("^(?i)");
        for (int i = 0; i < glob.length(); i++) {
            char c = glob.charAt(i);
            switch (c) {
                case '*': regex.append(".*"); break;
                case '?': regex.append('.'); break;
                case '.': regex.append("\\."); break;
                case '\\': regex.append("\\\\"); break;
                case '(': regex.append("\\("); break;
                case ')': regex.append("\\)"); break;
                case '[': regex.append("\\["); break;
                case ']': regex.append("\\]"); break;
                case '{': regex.append("\\{"); break;
                case '}': regex.append("\\}"); break;
                case '+': regex.append("\\+"); break;
                case '^': regex.append("\\^"); break;
                case '$': regex.append("\\$"); break;
                case '|': regex.append("\\|"); break;
                default: regex.append(c); break;
            }
        }
        regex.append('$');
        return Pattern.compile(regex.toString());
    }

    public int getPatternCount() {
        return compiledPatterns.size();
    }

    public List<String> getRawPatterns() {
        return rawPatterns;
    }
}

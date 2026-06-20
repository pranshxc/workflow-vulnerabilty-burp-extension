package com.workflowscanner.logging;

/**
 * Log levels for the extension's logging subsystem.
 *
 * Levels (ascending severity):
 * - DEBUG: Verbose internal state
 * - INFO:  Normal operations
 * - WARN:  Recoverable issues
 * - ERROR: Failures requiring attention
 */
public enum LogLevel {
    DEBUG(0, "DEBUG"),
    INFO(1, "INFO"),
    WARN(2, "WARN"),
    ERROR(3, "ERROR");

    private final int severity;
    private final String label;

    LogLevel(int severity, String label) {
        this.severity = severity;
        this.label = label;
    }

    public int getSeverity() {
        return severity;
    }

    public String getLabel() {
        return label;
    }

    /**
     * Check if this level is at least as severe as the given level.
     */
    public boolean isAtLeast(LogLevel other) {
        return this.severity >= other.severity;
    }

    /**
     * Parse a log level from string, case-insensitive. Returns INFO if unrecognized.
     */
    public static LogLevel fromString(String s) {
        if (s == null) return INFO;
        try {
            return valueOf(s.toUpperCase());
        } catch (IllegalArgumentException e) {
            return INFO;
        }
    }
}

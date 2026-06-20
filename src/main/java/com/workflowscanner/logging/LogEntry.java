package com.workflowscanner.logging;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * A single log entry with timestamp, category, level, source, message, and optional detail.
 * Captures the originating thread name for debugging concurrent operations.
 * Timestamps use millisecond precision.
 *
 * Format:
 * [TIMESTAMP] [CATEGORY] [LEVEL] [SOURCE] MESSAGE
 * --- DETAIL (optional, multi-line) ---
 */
public class LogEntry {

    private static final DateTimeFormatter FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")
                    .withZone(ZoneId.systemDefault());

    private final long timestamp;
    private final LogCategory category;
    private final LogLevel level;
    private final String source;
    private final String message;
    private final String detail;
    private final String threadName;
    private final long sequenceNumber;

    private static volatile long globalSequence = 0;

    public LogEntry(LogCategory category, LogLevel level, String source, String message, String detail) {
        this.timestamp = System.currentTimeMillis();
        this.category = category;
        this.level = level;
        this.source = source;
        this.message = message;
        this.detail = detail;
        this.threadName = Thread.currentThread().getName();
        synchronized (LogEntry.class) {
            this.sequenceNumber = globalSequence++;
        }
    }

    // --- Getters ---

    public long getTimestamp() { return timestamp; }
    public LogCategory getCategory() { return category; }
    public LogLevel getLevel() { return level; }
    public String getSource() { return source; }
    public String getMessage() { return message; }
    public String getDetail() { return detail; }
    public String getThreadName() { return threadName; }
    public long getSequenceNumber() { return sequenceNumber; }
    public boolean hasDetail() { return detail != null && !detail.isEmpty(); }

    public String getFormattedTimestamp() {
        return FORMATTER.format(Instant.ofEpochMilli(timestamp));
    }

    /**
     * Check if this entry matches a text search query.
     * Searches across message, detail, source, and category.
     */
    public boolean matchesSearch(String query) {
        if (query == null || query.isEmpty()) return true;
        String lowerQuery = query.toLowerCase();
        if (message != null && message.toLowerCase().contains(lowerQuery)) return true;
        if (detail != null && detail.toLowerCase().contains(lowerQuery)) return true;
        if (source != null && source.toLowerCase().contains(lowerQuery)) return true;
        if (category.name().toLowerCase().contains(lowerQuery)) return true;
        if (category.getShortName().toLowerCase().contains(lowerQuery)) return true;
        return false;
    }

    /**
     * Format as a single-line summary (for log list display).
     */
    public String toSummaryString() {
        return String.format("[%s] [%s] [%s] [%s] %s",
                getFormattedTimestamp(),
                category.getShortName(),
                level.name(),
                source,
                message);
    }

    /**
     * Format as full string with detail block.
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append('[').append(getFormattedTimestamp()).append("] ");
        sb.append('[').append(category.getShortName()).append("] ");
        sb.append('[').append(level.name()).append("] ");
        sb.append('[').append(source).append("] ");
        sb.append(message);
        if (hasDetail()) {
            sb.append("\n--- DETAIL ---\n");
            sb.append(detail);
            sb.append("\n--- END ---");
        }
        return sb.toString();
    }

    /**
     * Serialize to JSON string for export.
     */
    public String toJson() {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        sb.append("\"seq\":").append(sequenceNumber).append(',');
        sb.append("\"timestamp\":").append(timestamp).append(',');
        sb.append("\"time\":\"").append(escapeJson(getFormattedTimestamp())).append("\",");
        sb.append("\"category\":\"").append(category.name()).append("\",");
        sb.append("\"level\":\"").append(level.name()).append("\",");
        sb.append("\"source\":\"").append(escapeJson(source)).append("\",");
        sb.append("\"thread\":\"").append(escapeJson(threadName)).append("\",");
        sb.append("\"message\":\"").append(escapeJson(message)).append('"');
        if (hasDetail()) {
            sb.append(",\"detail\":\"").append(escapeJson(detail)).append('"');
        }
        sb.append('}');
        return sb.toString();
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}

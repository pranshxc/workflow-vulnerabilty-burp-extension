package com.workflowscanner.logging;

import burp.api.montoya.MontoyaApi;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Consumer;

/**
 * Centralized, thread-safe logging subsystem for the extension.
 *
 * Features:
 * - In-memory ring buffer (configurable size, default 10,000 entries) for UI display
 * - Async file-based logging via BlockingQueue + dedicated writer thread
 * - No redaction: everything raw, as specified
 * - Thread-safe: multiple Burp threads log concurrently
 * - Non-blocking: logging never blocks the calling thread
 * - Filterable by category, level, and text search
 * - Live tail streaming for UI updates
 * - Export to file (plain text and JSON)
 *
 * Singleton pattern for global access across all subsystems.
 */
public class ExtensionLogger {

    private static final ExtensionLogger INSTANCE = new ExtensionLogger();
    private static final String LOG_FILE_NAME = "workflow-scanner.log";

    // --- Core State ---
    private MontoyaApi api;
    private LogEntry[] ringBuffer;
    private int head = 0;
    private int size = 0;
    private int capacity = 10000;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private volatile boolean initialized = false;

    // --- Async File Writer ---
    private final BlockingQueue<LogEntry> fileWriteQueue = new LinkedBlockingQueue<>(50000);
    private volatile Thread fileWriterThread;
    private volatile boolean fileLoggingEnabled = false;
    private volatile String logFileDirectory;
    private volatile BufferedWriter fileWriter;

    // --- Listeners (for UI live tail) ---
    private final CopyOnWriteArrayList<Consumer<LogEntry>> listeners = new CopyOnWriteArrayList<>();

    // --- Statistics ---
    private final AtomicLong totalEntriesLogged = new AtomicLong(0);
    private final AtomicLong totalEntriesDropped = new AtomicLong(0);

    private ExtensionLogger() {}

    public static ExtensionLogger getInstance() {
        return INSTANCE;
    }

    // ========================================================================
    // Initialization
    // ========================================================================

    /**
     * Initialize with Burp API reference using default buffer capacity.
     */
    public void initialize(MontoyaApi api) {
        initialize(api, 10000, false, null);
    }

    /**
     * Initialize with custom buffer capacity and file logging settings.
     */
    public void initialize(MontoyaApi api, int bufferCapacity, boolean enableFileLogging, String logDirectory) {
        this.api = api;
        this.capacity = Math.max(100, bufferCapacity);

        lock.writeLock().lock();
        try {
            this.ringBuffer = new LogEntry[this.capacity];
            this.head = 0;
            this.size = 0;
        } finally {
            lock.writeLock().unlock();
        }

        // Configure file logging
        if (enableFileLogging && logDirectory != null && !logDirectory.isEmpty()) {
            enableFileLogging(logDirectory);
        }

        this.initialized = true;
    }

    /**
     * Reconfigure from ExtensionConfig values. Called when config changes.
     */
    public void reconfigure(int bufferCapacity, boolean enableFileLogging, String logDirectory) {
        // Resize ring buffer if capacity changed
        if (bufferCapacity != this.capacity && bufferCapacity >= 100) {
            resizeBuffer(bufferCapacity);
        }

        // Toggle file logging
        if (enableFileLogging && logDirectory != null && !logDirectory.isEmpty()) {
            if (!this.fileLoggingEnabled || !logDirectory.equals(this.logFileDirectory)) {
                disableFileLogging();
                enableFileLogging(logDirectory);
            }
        } else {
            disableFileLogging();
        }
    }

    // ========================================================================
    // Logging Methods
    // ========================================================================

    /**
     * Log a message with no detail.
     */
    public void log(LogCategory category, LogLevel level, String source, String message) {
        log(category, level, source, message, (String) null);
    }

    /**
     * Log a message with a throwable (full stack trace captured).
     */
    public void log(LogCategory category, LogLevel level, String source, String message, Throwable throwable) {
        StringWriter sw = new StringWriter();
        throwable.printStackTrace(new PrintWriter(sw));
        log(category, level, source, message, sw.toString());
    }

    /**
     * Log a message with optional detail string.
     * This is the core logging method. It:
     * 1. Creates the LogEntry
     * 2. Adds to ring buffer (thread-safe)
     * 3. Enqueues for async file write (non-blocking)
     * 4. Forwards to Burp output (INFO+ only)
     * 5. Notifies listeners (for UI live tail)
     */
    public void log(LogCategory category, LogLevel level, String source, String message, String detail) {
        LogEntry entry = new LogEntry(category, level, source, message, detail);
        totalEntriesLogged.incrementAndGet();

        // 1. Add to ring buffer
        addToRingBuffer(entry);

        // 2. Enqueue for async file write (non-blocking)
        if (fileLoggingEnabled) {
            if (!fileWriteQueue.offer(entry)) {
                totalEntriesDropped.incrementAndGet();
            }
        }

        // 3. Forward to Burp output (INFO+ only to avoid flooding)
        if (api != null && level.isAtLeast(LogLevel.INFO)) {
            try {
                api.logging().logToOutput(entry.toSummaryString());
            } catch (Exception ignored) {
                // Don't let logging failures cascade
            }
        }

        // 4. Notify listeners (for UI live tail)
        for (Consumer<LogEntry> listener : listeners) {
            try {
                listener.accept(entry);
            } catch (Exception ignored) {
                // Don't let listener failures cascade
            }
        }
    }

    // ========================================================================
    // Ring Buffer Operations
    // ========================================================================

    private void addToRingBuffer(LogEntry entry) {
        lock.writeLock().lock();
        try {
            if (ringBuffer == null) {
                ringBuffer = new LogEntry[capacity];
            }
            ringBuffer[head] = entry;
            head = (head + 1) % capacity;
            if (size < capacity) {
                size++;
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    private void resizeBuffer(int newCapacity) {
        lock.writeLock().lock();
        try {
            List<LogEntry> existing = getAllEntriesInternal();
            this.capacity = newCapacity;
            this.ringBuffer = new LogEntry[newCapacity];
            this.head = 0;
            this.size = 0;

            // Re-add entries (keep most recent if they exceed new capacity)
            int start = Math.max(0, existing.size() - newCapacity);
            for (int i = start; i < existing.size(); i++) {
                ringBuffer[head] = existing.get(i);
                head = (head + 1) % capacity;
                size++;
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    // ========================================================================
    // Query / Retrieval API
    // ========================================================================

    /**
     * Get log entries with full filtering support.
     *
     * @param categories Set of categories to include (null = all)
     * @param minLevel   Minimum log level (null = all)
     * @param searchText Free-text search across message, detail, source (null = no filter)
     * @param limit      Max entries to return (0 = unlimited)
     * @param offset     Number of matching entries to skip
     * @return Filtered list of log entries, oldest first
     */
    public List<LogEntry> getEntries(Set<LogCategory> categories, LogLevel minLevel,
                                     String searchText, int limit, int offset) {
        List<LogEntry> result = new ArrayList<>();
        lock.readLock().lock();
        try {
            int count = 0;
            int skipped = 0;
            for (int i = 0; i < size; i++) {
                int idx = (head - size + i + capacity) % capacity;
                LogEntry entry = ringBuffer[idx];
                if (entry == null) continue;

                // Category filter
                if (categories != null && !categories.isEmpty()
                        && !categories.contains(entry.getCategory())) continue;

                // Level filter
                if (minLevel != null && !entry.getLevel().isAtLeast(minLevel)) continue;

                // Text search filter
                if (searchText != null && !searchText.isEmpty()
                        && !entry.matchesSearch(searchText)) continue;

                if (skipped < offset) {
                    skipped++;
                    continue;
                }
                result.add(entry);
                count++;
                if (limit > 0 && count >= limit) break;
            }
        } finally {
            lock.readLock().unlock();
        }
        return result;
    }

    /**
     * Simplified query: filter by single category and level.
     */
    public List<LogEntry> getEntries(LogCategory category, LogLevel minLevel, int limit, int offset) {
        Set<LogCategory> cats = category != null ? EnumSet.of(category) : null;
        return getEntries(cats, minLevel, null, limit, offset);
    }

    /**
     * Get all entries (no filter).
     */
    public List<LogEntry> getAllEntries() {
        return getEntries((Set<LogCategory>) null, null, null, 0, 0);
    }

    /**
     * Internal: get all entries without going through the public API (used during resize).
     */
    private List<LogEntry> getAllEntriesInternal() {
        List<LogEntry> result = new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            int idx = (head - size + i + capacity) % capacity;
            LogEntry entry = ringBuffer[idx];
            if (entry != null) {
                result.add(entry);
            }
        }
        return result;
    }

    /**
     * Get count of entries matching the given filters.
     */
    public int getFilteredCount(Set<LogCategory> categories, LogLevel minLevel, String searchText) {
        int count = 0;
        lock.readLock().lock();
        try {
            for (int i = 0; i < size; i++) {
                int idx = (head - size + i + capacity) % capacity;
                LogEntry entry = ringBuffer[idx];
                if (entry == null) continue;
                if (categories != null && !categories.isEmpty()
                        && !categories.contains(entry.getCategory())) continue;
                if (minLevel != null && !entry.getLevel().isAtLeast(minLevel)) continue;
                if (searchText != null && !searchText.isEmpty()
                        && !entry.matchesSearch(searchText)) continue;
                count++;
            }
        } finally {
            lock.readLock().unlock();
        }
        return count;
    }

    /**
     * Get current total entry count in the ring buffer.
     */
    public int getEntryCount() {
        lock.readLock().lock();
        try {
            return size;
        } finally {
            lock.readLock().unlock();
        }
    }

    // ========================================================================
    // Live Tail / Streaming API
    // ========================================================================

    /**
     * Register a listener for live log streaming (UI live tail).
     * The listener is called on the logging thread, so UI updates
     * should use SwingUtilities.invokeLater().
     */
    public void addListener(Consumer<LogEntry> listener) {
        listeners.add(listener);
    }

    /**
     * Remove a live tail listener.
     */
    public void removeListener(Consumer<LogEntry> listener) {
        listeners.remove(listener);
    }

    /**
     * Get the number of active listeners.
     */
    public int getListenerCount() {
        return listeners.size();
    }

    // ========================================================================
    // Export API
    // ========================================================================

    /**
     * Export log entries to a file in plain text format.
     *
     * @param filePath   Path to the output file
     * @param categories Category filter (null = all)
     * @param minLevel   Level filter (null = all)
     * @param searchText Text search filter (null = no filter)
     * @return Number of entries exported
     * @throws IOException if file writing fails
     */
    public int exportToFile(String filePath, Set<LogCategory> categories,
                            LogLevel minLevel, String searchText) throws IOException {
        List<LogEntry> entries = getEntries(categories, minLevel, searchText, 0, 0);
        Path path = Paths.get(filePath);
        try (BufferedWriter writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
            writer.write("# Workflow Vulnerability Scanner - Log Export");
            writer.newLine();
            writer.write("# Entries: " + entries.size());
            writer.newLine();
            writer.write("# Exported: " + java.time.Instant.now().toString());
            writer.newLine();
            writer.write("# " + "=".repeat(70));
            writer.newLine();
            writer.newLine();

            for (LogEntry entry : entries) {
                writer.write(entry.toString());
                writer.newLine();
            }
        }
        return entries.size();
    }

    /**
     * Export log entries to a file in JSON format (one JSON object per line).
     *
     * @param filePath   Path to the output file
     * @param categories Category filter (null = all)
     * @param minLevel   Level filter (null = all)
     * @param searchText Text search filter (null = no filter)
     * @return Number of entries exported
     * @throws IOException if file writing fails
     */
    public int exportToJsonFile(String filePath, Set<LogCategory> categories,
                                LogLevel minLevel, String searchText) throws IOException {
        List<LogEntry> entries = getEntries(categories, minLevel, searchText, 0, 0);
        Path path = Paths.get(filePath);
        try (BufferedWriter writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
            writer.write('[');
            writer.newLine();
            for (int i = 0; i < entries.size(); i++) {
                writer.write("  ");
                writer.write(entries.get(i).toJson());
                if (i < entries.size() - 1) {
                    writer.write(',');
                }
                writer.newLine();
            }
            writer.write(']');
            writer.newLine();
        }
        return entries.size();
    }

    // ========================================================================
    // File Logging (Async)
    // ========================================================================

    /**
     * Enable file-based logging to the specified directory.
     * Starts a dedicated writer thread that drains the write queue.
     */
    public void enableFileLogging(String directory) {
        if (directory == null || directory.isEmpty()) return;

        this.logFileDirectory = directory;

        try {
            // Ensure directory exists
            File dir = new File(directory);
            if (!dir.exists()) {
                dir.mkdirs();
            }

            File logFile = new File(dir, LOG_FILE_NAME);
            this.fileWriter = new BufferedWriter(new FileWriter(logFile, true)); // append mode
            this.fileLoggingEnabled = true;

            // Start async writer thread
            this.fileWriterThread = new Thread(this::fileWriterLoop, "WorkflowScanner-LogWriter");
            this.fileWriterThread.setDaemon(true);
            this.fileWriterThread.start();

            log(LogCategory.CONFIG, LogLevel.INFO, "ExtensionLogger",
                    "File logging enabled: " + logFile.getAbsolutePath());
        } catch (IOException e) {
            this.fileLoggingEnabled = false;
            if (api != null) {
                api.logging().logToOutput("[ERROR] Failed to enable file logging: " + e.getMessage());
            }
        }
    }

    /**
     * Disable file-based logging and stop the writer thread.
     */
    public void disableFileLogging() {
        this.fileLoggingEnabled = false;

        if (fileWriterThread != null) {
            fileWriterThread.interrupt();
            try {
                fileWriterThread.join(2000);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            fileWriterThread = null;
        }

        if (fileWriter != null) {
            try {
                fileWriter.flush();
                fileWriter.close();
            } catch (IOException ignored) {}
            fileWriter = null;
        }

        fileWriteQueue.clear();
    }

    /**
     * Async file writer loop. Runs on a dedicated daemon thread.
     * Drains the write queue and writes entries to the log file.
     * Uses batching for efficiency.
     */
    private void fileWriterLoop() {
        List<LogEntry> batch = new ArrayList<>(100);
        while (fileLoggingEnabled || !fileWriteQueue.isEmpty()) {
            try {
                // Block waiting for first entry
                LogEntry entry = fileWriteQueue.poll(500, TimeUnit.MILLISECONDS);
                if (entry == null) continue;

                batch.clear();
                batch.add(entry);

                // Drain additional available entries (batch write)
                fileWriteQueue.drainTo(batch, 99);

                // Write batch to file
                if (fileWriter != null) {
                    for (LogEntry e : batch) {
                        fileWriter.write(e.toString());
                        fileWriter.newLine();
                    }
                    fileWriter.flush();
                }
            } catch (InterruptedException e) {
                // Shutting down - drain remaining entries
                drainRemainingToFile();
                break;
            } catch (IOException e) {
                // File write error - disable to prevent infinite error loop
                if (api != null) {
                    try {
                        api.logging().logToOutput("[ERROR] Log file write failed: " + e.getMessage());
                    } catch (Exception ignored) {}
                }
                break;
            }
        }
    }

    /**
     * Drain any remaining entries from the queue to the file on shutdown.
     */
    private void drainRemainingToFile() {
        if (fileWriter == null) return;
        List<LogEntry> remaining = new ArrayList<>();
        fileWriteQueue.drainTo(remaining);
        try {
            for (LogEntry e : remaining) {
                fileWriter.write(e.toString());
                fileWriter.newLine();
            }
            fileWriter.flush();
        } catch (IOException ignored) {}
    }

    public boolean isFileLoggingEnabled() {
        return fileLoggingEnabled;
    }

    public String getLogFileDirectory() {
        return logFileDirectory;
    }

    // ========================================================================
    // Buffer Management
    // ========================================================================

    /**
     * Clear the in-memory ring buffer.
     */
    public void clear() {
        lock.writeLock().lock();
        try {
            ringBuffer = new LogEntry[capacity];
            head = 0;
            size = 0;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Flush pending file writes.
     */
    public void flush() {
        if (fileWriter != null) {
            try {
                // Give the writer thread a moment to drain
                Thread.sleep(100);
                fileWriter.flush();
            } catch (Exception ignored) {}
        }
    }

    /**
     * Shutdown the logging subsystem.
     * Disables file logging, clears listeners, flushes everything.
     */
    public void shutdown() {
        disableFileLogging();
        listeners.clear();
        initialized = false;
    }

    // ========================================================================
    // Statistics
    // ========================================================================

    /**
     * Get logging statistics for monitoring.
     */
    public LogStats getStats() {
        lock.readLock().lock();
        try {
            return new LogStats(
                    size,
                    capacity,
                    totalEntriesLogged.get(),
                    totalEntriesDropped.get(),
                    fileLoggingEnabled,
                    fileWriteQueue.size(),
                    listeners.size()
            );
        } finally {
            lock.readLock().unlock();
        }
    }

    public boolean isInitialized() {
        return initialized;
    }

    public int getCapacity() {
        return capacity;
    }

    // ========================================================================
    // Stats Record
    // ========================================================================

    /**
     * Snapshot of logging subsystem statistics.
     */
    public static class LogStats {
        public final int bufferSize;
        public final int bufferCapacity;
        public final long totalLogged;
        public final long totalDropped;
        public final boolean fileLoggingActive;
        public final int fileQueuePending;
        public final int activeListeners;

        public LogStats(int bufferSize, int bufferCapacity, long totalLogged, long totalDropped,
                        boolean fileLoggingActive, int fileQueuePending, int activeListeners) {
            this.bufferSize = bufferSize;
            this.bufferCapacity = bufferCapacity;
            this.totalLogged = totalLogged;
            this.totalDropped = totalDropped;
            this.fileLoggingActive = fileLoggingActive;
            this.fileQueuePending = fileQueuePending;
            this.activeListeners = activeListeners;
        }

        @Override
        public String toString() {
            return String.format("Buffer: %d/%d, Total: %d, Dropped: %d, File: %s, Queue: %d, Listeners: %d",
                    bufferSize, bufferCapacity, totalLogged, totalDropped,
                    fileLoggingActive ? "ON" : "OFF", fileQueuePending, activeListeners);
        }
    }
}

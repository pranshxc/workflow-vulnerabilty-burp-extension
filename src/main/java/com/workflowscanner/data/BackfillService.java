package com.workflowscanner.data;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import com.workflowscanner.config.ExtensionConfig;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Handles backfilling requests from Burp's proxy history.
 *
 * Features:
 * - Runs in a background thread to avoid freezing the UI
 * - Configurable limit (max requests to backfill)
 * - Configurable scope (apply scope filter to historical requests)
 * - Progress reporting for UI consumption
 * - Deduplication against already-ingested requests
 * - Cancel support with clean shutdown
 */
public class BackfillService {

    private final MontoyaApi api;
    private final RequestPipeline pipeline;
    private final ExtensionConfig config;
    private final ExtensionLogger logger;
    private final ScopeFilter scopeFilter;

    private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "WorkflowScanner-Backfill");
        t.setDaemon(true);
        return t;
    });

    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean cancelled = new AtomicBoolean(false);
    private final AtomicInteger progress = new AtomicInteger(0);
    private final AtomicInteger total = new AtomicInteger(0);
    private final AtomicInteger ingested = new AtomicInteger(0);
    private final AtomicInteger skippedScope = new AtomicInteger(0);
    private final AtomicInteger skippedDedup = new AtomicInteger(0);

    public BackfillService(MontoyaApi api, RequestPipeline pipeline,
                           ExtensionConfig config, ExtensionLogger logger) {
        this.api = api;
        this.pipeline = pipeline;
        this.config = config;
        this.logger = logger;
        this.scopeFilter = new ScopeFilter(config);
    }

    /**
     * Start the backfill process in a background thread.
     * No-op if already running.
     */
    public void start() {
        if (running.get()) {
            logger.log(LogCategory.BACKFILL, LogLevel.WARN, "BackfillService",
                    "Backfill already running, ignoring start request.");
            return;
        }

        // Reset state
        cancelled.set(false);
        progress.set(0);
        total.set(0);
        ingested.set(0);
        skippedScope.set(0);
        skippedDedup.set(0);

        executor.submit(this::runBackfill);
    }

    /**
     * Cancel the running backfill.
     */
    public void cancel() {
        if (running.get()) {
            cancelled.set(true);
            logger.log(LogCategory.BACKFILL, LogLevel.INFO, "BackfillService",
                    "Backfill cancellation requested.");
        }
    }

    /**
     * The main backfill loop. Runs on a background thread.
     */
    private void runBackfill() {
        running.set(true);
        long startTime = System.currentTimeMillis();

        logger.log(LogCategory.BACKFILL, LogLevel.INFO, "BackfillService",
                "Starting backfill. Limit: " + config.getBackfillLimit()
                        + ", Scope: " + (config.isBackfillInScopeOnly() ? "in-scope only" : "all"));

        try {
            // Get proxy history from Burp
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            int historySize = history.size();
            int limit = config.getBackfillLimit();

            // Process from most recent backwards, up to the limit
            int startIdx = Math.max(0, historySize - limit);
            int itemsToProcess = historySize - startIdx;
            total.set(itemsToProcess);

            logger.log(LogCategory.BACKFILL, LogLevel.INFO, "BackfillService",
                    "Proxy history contains " + historySize + " items. Processing "
                            + itemsToProcess + " (from index " + startIdx + ").");

            for (int i = startIdx; i < historySize; i++) {
                if (cancelled.get()) {
                    logger.log(LogCategory.BACKFILL, LogLevel.INFO, "BackfillService",
                            "Backfill cancelled at " + progress.get() + "/" + total.get());
                    break;
                }

                try {
                    ProxyHttpRequestResponse proxyItem = history.get(i);

                    // Convert to internal model
                    CapturedRequest captured = RequestConverter.fromProxyHistory(
                            proxyItem, CapturedRequest.Source.BACKFILL);

                    // Scope filter (if configured)
                    if (config.isBackfillInScopeOnly() && !scopeFilter.isInScope(captured.getHost())) {
                        skippedScope.incrementAndGet();
                        progress.incrementAndGet();
                        continue;
                    }

                    captured.setInScope(true);

                    // Deduplication check
                    if (pipeline.hasBeenSeen(captured.getDeduplicationKey())) {
                        skippedDedup.incrementAndGet();
                        progress.incrementAndGet();
                        continue;
                    }

                    // Submit to pipeline
                    boolean submitted = pipeline.submit(captured);
                    if (submitted) {
                        ingested.incrementAndGet();
                    }
                } catch (Exception e) {
                    logger.log(LogCategory.ERROR, LogLevel.WARN, "BackfillService",
                            "Error processing history item " + i + ".", e);
                }

                progress.incrementAndGet();

                // Log progress every 100 items
                if (progress.get() % 100 == 0) {
                    logger.log(LogCategory.BACKFILL, LogLevel.INFO, "BackfillService",
                            "Backfill progress: " + progress.get() + "/" + total.get()
                                    + " (ingested: " + ingested.get() + ")");
                }
            }

            long duration = System.currentTimeMillis() - startTime;
            logger.log(LogCategory.BACKFILL, LogLevel.INFO, "BackfillService",
                    "Backfill complete. Duration: " + duration + "ms"
                            + ", Processed: " + progress.get() + "/" + total.get()
                            + ", Ingested: " + ingested.get()
                            + ", Skipped (scope): " + skippedScope.get()
                            + ", Skipped (dedup): " + skippedDedup.get());

        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "BackfillService",
                    "Backfill failed with error.", e);
        } finally {
            running.set(false);
        }
    }

    /**
     * Shutdown the backfill service and release the thread pool.
     */
    public void shutdown() {
        cancel();
        executor.shutdownNow();
    }

    // --- Status Accessors (for UI) ---

    public boolean isRunning() { return running.get(); }
    public boolean isCancelled() { return cancelled.get(); }
    public int getProgress() { return progress.get(); }
    public int getTotal() { return total.get(); }
    public int getIngested() { return ingested.get(); }
    public int getSkippedScope() { return skippedScope.get(); }
    public int getSkippedDedup() { return skippedDedup.get(); }

    /**
     * Get a human-readable status string for UI display.
     */
    public String getStatusText() {
        if (!running.get()) {
            if (total.get() == 0) return "Idle";
            if (cancelled.get()) return "Cancelled at " + progress.get() + "/" + total.get();
            return "Complete: " + ingested.get() + " ingested";
        }
        return "Backfilling: " + progress.get() + "/" + total.get()
                + " (" + ingested.get() + " ingested)";
    }
}

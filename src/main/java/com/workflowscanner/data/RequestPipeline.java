package com.workflowscanner.data;

import com.workflowscanner.config.ExtensionConfig;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * Thread-safe request pipeline that all data sources feed into.
 * Consumed by the Graph Builder downstream.
 * Uses a bounded blocking queue with configurable capacity.
 * Supports deduplication and listener notification.
 */
public class RequestPipeline {

    private final LinkedBlockingQueue<CapturedRequest> queue;
    private final ExtensionLogger logger;
    private volatile boolean running = true;

    // Deduplication: track seen dedup keys to avoid re-processing
    private final Set<String> seenDedupKeys = ConcurrentHashMap.newKeySet();
    private static final int MAX_DEDUP_KEYS = 50000;

    // Listeners for pipeline events (e.g., graph builder)
    private final CopyOnWriteArrayList<Consumer<CapturedRequest>> listeners = new CopyOnWriteArrayList<>();

    // Statistics
    private final AtomicLong totalSubmitted = new AtomicLong(0);
    private final AtomicLong totalDeduplicated = new AtomicLong(0);
    private final AtomicLong totalDropped = new AtomicLong(0);

    public RequestPipeline(ExtensionConfig config, ExtensionLogger logger) {
        this.queue = new LinkedBlockingQueue<>(config.getPipelineQueueCapacity());
        this.logger = logger;
    }

    /**
     * Submit a request to the pipeline. Non-blocking.
     * Returns false if the request was deduplicated or the pipeline is shut down.
     */
    public boolean submit(CapturedRequest request) {
        if (!running) return false;
        if (request == null) return false;

        // Deduplication check
        String dedupKey = request.getDeduplicationKey();
        if (!seenDedupKeys.add(dedupKey)) {
            totalDeduplicated.incrementAndGet();
            logger.log(LogCategory.EXTENSION, LogLevel.DEBUG, "RequestPipeline",
                    "Deduplicated request: " + request.getMethod() + " " + request.getUrl());
            return false;
        }

        // Prevent unbounded growth of dedup set
        if (seenDedupKeys.size() > MAX_DEDUP_KEYS) {
            seenDedupKeys.clear();
            logger.log(LogCategory.EXTENSION, LogLevel.DEBUG, "RequestPipeline",
                    "Dedup cache cleared (exceeded " + MAX_DEDUP_KEYS + " entries).");
        }

        totalSubmitted.incrementAndGet();

        boolean added = queue.offer(request);
        if (!added) {
            // Queue full - drop oldest and retry
            queue.poll();
            added = queue.offer(request);
            if (added) {
                totalDropped.incrementAndGet();
                logger.log(LogCategory.EXTENSION, LogLevel.WARN, "RequestPipeline",
                        "Queue full, dropped oldest request to make room.");
            }
        }

        // Notify listeners
        if (added) {
            for (Consumer<CapturedRequest> listener : listeners) {
                try {
                    listener.accept(request);
                } catch (Exception e) {
                    logger.log(LogCategory.ERROR, LogLevel.ERROR, "RequestPipeline",
                            "Listener error.", e);
                }
            }
        }

        return added;
    }

    /**
     * Take the next request from the pipeline. Blocks until available or timeout.
     */
    public CapturedRequest take(long timeoutMs) throws InterruptedException {
        return queue.poll(timeoutMs, TimeUnit.MILLISECONDS);
    }

    /**
     * Check if a dedup key has already been seen.
     */
    public boolean hasBeenSeen(String dedupKey) {
        return seenDedupKeys.contains(dedupKey);
    }

    /**
     * Register a listener for new requests entering the pipeline.
     */
    public void addListener(Consumer<CapturedRequest> listener) {
        listeners.add(listener);
    }

    /**
     * Remove a pipeline listener.
     */
    public void removeListener(Consumer<CapturedRequest> listener) {
        listeners.remove(listener);
    }

    /**
     * Get current queue size.
     */
    public int size() {
        return queue.size();
    }

    /**
     * Check if pipeline is empty.
     */
    public boolean isEmpty() {
        return queue.isEmpty();
    }

    /**
     * Shutdown the pipeline.
     */
    public void shutdown() {
        running = false;
        queue.clear();
        listeners.clear();
    }

    public boolean isRunning() {
        return running;
    }

    public long getTotalSubmitted() { return totalSubmitted.get(); }
    public long getTotalDeduplicated() { return totalDeduplicated.get(); }
    public long getTotalDropped() { return totalDropped.get(); }
}

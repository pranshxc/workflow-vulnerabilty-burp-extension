package com.workflowscanner.store;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Disk-backed request store. The canonical home for full backfill
 * data.
 *
 * <p><b>Purpose:</b> the in-memory {@code RequestGraph} cannot hold
 * 1.6M+ requests without exhausting Burp's heap. This interface
 * defines the minimal contract for a store that can:
 *
 * <ul>
 *   <li>Persist a compact {@link RequestSummary} plus the full
 *       {@link RawHttp} for every backfilled request.</li>
 *   <li>Look up by request id (used when the UI opens a candidate
 *       and needs the raw request/response bodies).</li>
 *   <li>Stream summaries in timestamp order (used by the streaming
 *       workflow detector and edge rebuild job).</li>
 *   <li>Stream only workflow-relevant summaries (used by the
 *       candidate builder to skip the noise).</li>
 * </ul>
 *
 * <p><b>Implementations:</b> the planned implementations are
 * H2/MVStore (recommended), JSONL + small index files, or an
 * in-memory stub for tests. The interface is deliberately small
 * so the eventual H2 implementation can be swapped in without
 * changing the call sites.
 *
 * <p><b>Lifecycle:</b> the store is opened once at extension
 * startup, used by the backfill pipeline and live traffic, and
 * closed at shutdown. The path on disk is user-configurable.
 */
public interface RequestStore {

    /**
     * Persist a request summary and its raw HTTP. The {@code raw}
     * may be null when the caller wants to record only metadata
     * (e.g. for endpoints where raw data is not yet captured).
     */
    void put(RequestSummary summary, RawHttp raw);

    /**
     * Read the compact summary for a request, or empty if unknown.
     */
    Optional<RequestSummary> getSummary(String requestId);

    /**
     * Read the full raw HTTP for a request, or empty if unknown
     * or never persisted.
     */
    Optional<RawHttp> getRaw(String requestId);

    /**
     * Stream every persisted summary in timestamp-ascending order.
     * The stream must be closed by the caller; backing resources
     * (cursors, file handles) are released on close.
     */
    Stream<RequestSummary> streamAll();

    /**
     * Stream only summaries whose classification is workflow-relevant.
     * Skipping the noise at the SQL level is much faster than
     * filtering in Java.
     */
    Stream<RequestSummary> streamWorkflowRelevant();

    /**
     * Total number of stored summaries. O(1) for most backends.
     */
    long countAll();

    /**
     * Number of stored summaries that are workflow-relevant. O(1)
     * for most backends.
     */
    long countWorkflowRelevant();

    /**
     * Number of stored requests that have a non-null raw HTTP
     * payload persisted. O(1) for most backends.
     */
    long countWithRaw();

    /**
     * Approximate disk usage in bytes (sum of raw body + summary
     * records). Implementations may return {@code 0} if they
     * cannot cheaply compute it.
     */
    long diskBytes();

    /**
     * Find all stored summaries for a given host, optionally
     * restricted to a time window. Used for host-scoped UI filters.
     */
    List<RequestSummary> findByHost(String host, long from, long to);

    /**
     * Drop everything. Used by "Clear Graph Data" / "Reset".
     */
    void clear();

    /**
     * Release any open resources. After close, the store is
     * unusable.
     */
    void close();
}

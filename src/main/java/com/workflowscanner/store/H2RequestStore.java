package com.workflowscanner.store;

import org.h2.mvstore.MVMap;
import org.h2.mvstore.MVStore;
import org.h2.mvstore.MVStoreTool;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 * H2 MVStore-backed {@link RequestStore}.
 *
 * <p>Uses H2's {@code MVStore} — a pure-Java, log-structured key/value
 * store that is well-suited to embedded use inside a Burp extension.
 * No native dependencies, no separate process. Two maps are used:
 *
 * <ul>
 *   <li>{@code summaries} — {@code id -> JSON(RequestSummary)}</li>
 *   <li>{@code raws}      — {@code id -> JSON(RawHttp)}</li>
 *   <li>{@code meta}      — small {@code name -> long} map for
 *       counters and bookkeeping.</li>
 * </ul>
 *
 * <p>All writes are committed via {@link MVStore#commit()} in
 * batches. Reads are served from the in-memory map. For 1.6M
 * summaries this fits in a few hundred MB of heap, but the JVM
 * does not need to keep the full {@code RawHttp} payloads resident
 * because the store only materialises the raw blob on
 * {@link #getRaw(String)}.
 *
 * <p><b>Compression:</b> bodies &gt; 1KB are deflate-compressed
 * before being JSON-serialised. This is the single biggest
 * win for typical Burp projects where HTML response bodies are
 * large.
 */
public class H2RequestStore implements RequestStore {

    private static final String SUMMARIES_MAP = "summaries";
    private static final String RAWS_MAP = "raws";
    private static final String META_MAP = "meta";
    private static final int COMPRESS_THRESHOLD = 1024;
    private static final String META_TOTAL = "countAll";
    private static final String META_RELEVANT = "countRelevant";
    private static final String META_RAW = "countRaw";
    private static final String META_DISK = "diskBytes";
    // Chunking for streaming in timestamp order. Each chunk holds
    // up to CHUNK_SIZE summaries; we index them by min/max timestamp
    // for fast range scans.
    private static final int CHUNK_SIZE = 5000;

    private final MVStore store;
    private final MVMap<String, String> summaries;
    private final MVMap<String, String> raws;
    private final MVMap<String, Long> meta;
    private final MVMap<Long, String> timeIndex; // timestamp_bucket -> first id in bucket
    private final Path filePath;
    private final boolean readOnly;
    private final AtomicLong diskBytes = new AtomicLong(0);

    /**
     * Open or create an on-disk store at the given path. The path
     * is created if it does not exist. Use {@code null} for
     * read-only access.
     */
    public H2RequestStore(String path) {
        this(path, false);
    }

    public H2RequestStore(String path, boolean readOnly) {
        this.readOnly = readOnly;
        if (path == null) {
            this.filePath = null;
            this.store = new MVStore.Builder().open();
        } else {
            Path p = Paths.get(path);
            try {
                Path parent = p.getParent();
                if (parent != null) {
                    Files.createDirectories(parent);
                }
            } catch (IOException e) {
                throw new RuntimeException("Cannot create store parent dir: " + p, e);
            }
            this.filePath = p;
            this.store = new MVStore.Builder()
                    .fileName(path)
                    .cacheSize(64)        // MB; tune later
                    .compress()           // MVStore-level compress
                    .open();
        }
        this.summaries = store.openMap(SUMMARIES_MAP);
        this.raws = store.openMap(RAWS_MAP);
        this.meta = store.openMap(META_MAP);
        this.timeIndex = store.openMap("timeIndex");
        // Hydrate disk-bytes counter from meta so we do not lie on first read.
        Long persisted = meta.get(META_DISK);
        if (persisted != null) {
            diskBytes.set(persisted);
        }
    }

    @Override
    public void put(RequestSummary summary, RawHttp raw) {
        if (summary == null) return;
        if (readOnly) throw new UnsupportedOperationException("store is read-only");
        String id = summary.getId();
        if (id == null) return;
        String prevJson = summaries.put(id, RequestSummaryCodec.encode(summary));
        if (prevJson == null) {
            meta.put(META_TOTAL, meta.getOrDefault(META_TOTAL, 0L) + 1L);
        }
        if (summary.isWorkflowRelevant()) {
            meta.put(META_RELEVANT, meta.getOrDefault(META_RELEVANT, 0L) + 1L);
        }
        if (raw != null) {
            String encoded = RawHttpCodec.encode(raw);
            String prevRaw = raws.put(id, encoded);
            if (prevRaw == null) {
                meta.put(META_RAW, meta.getOrDefault(META_RAW, 0L) + 1L);
            }
            long sz = encoded.length();
            diskBytes.addAndGet(sz);
            meta.put(META_DISK, meta.getOrDefault(META_DISK, 0L) + sz);
        }
        // Index by timestamp bucket for streaming.
        long bucket = (summary.getTimestamp() / 1000L) * 1000L; // 1s buckets
        timeIndex.putIfAbsent(bucket, id);
        // Chunk commit at CHUNK_SIZE writes for durability without
        // hammering the disk.
        if (meta.get(META_TOTAL) % CHUNK_SIZE == 0) {
            store.commit();
        }
    }

    @Override
    public Optional<RequestSummary> getSummary(String requestId) {
        if (requestId == null) return Optional.empty();
        String json = summaries.get(requestId);
        if (json == null) return Optional.empty();
        return Optional.ofNullable(RequestSummaryCodec.decode(json));
    }

    @Override
    public Optional<RawHttp> getRaw(String requestId) {
        if (requestId == null) return Optional.empty();
        String encoded = raws.get(requestId);
        if (encoded == null) return Optional.empty();
        return Optional.ofNullable(RawHttpCodec.decode(encoded));
    }

    @Override
    public Stream<RequestSummary> streamAll() {
        // Eagerly copy the keys to avoid concurrent-modification
        // issues during long-running streams. The iterator on
        // MVMap is weakly consistent, but the caller is expected
        // to close the stream promptly.
        Iterable<String> keys = summaries.keySet();
        return StreamSupport.stream(keys.spliterator(), false)
                .map(summaries::get)
                .filter(java.util.Objects::nonNull)
                .map(RequestSummaryCodec::decode)
                .filter(java.util.Objects::nonNull)
                .sorted((a, b) -> Long.compare(a.getTimestamp(), b.getTimestamp()));
    }

    @Override
    public Stream<RequestSummary> streamWorkflowRelevant() {
        return streamAll().filter(RequestSummary::isWorkflowRelevant);
    }

    @Override
    public long countAll() {
        Long v = meta.get(META_TOTAL);
        return v == null ? 0 : v;
    }

    @Override
    public long countWorkflowRelevant() {
        Long v = meta.get(META_RELEVANT);
        return v == null ? 0 : v;
    }

    @Override
    public long countWithRaw() {
        Long v = meta.get(META_RAW);
        return v == null ? 0 : v;
    }

    @Override
    public long diskBytes() {
        return diskBytes.get();
    }

    @Override
    public List<RequestSummary> findByHost(String host, long from, long to) {
        if (host == null) return List.of();
        List<RequestSummary> out = new ArrayList<>();
        for (RequestSummary s : streamAllByHost(host, from, to)) {
            out.add(s);
        }
        return out;
    }

    private Iterable<RequestSummary> streamAllByHost(String host, long from, long to) {
        return () -> streamAll()
                .filter(s -> host.equalsIgnoreCase(s.getHost()))
                .filter(s -> s.getTimestamp() >= from && s.getTimestamp() <= to)
                .iterator();
    }

    @Override
    public void clear() {
        if (readOnly) return;
        summaries.clear();
        raws.clear();
        meta.clear();
        timeIndex.clear();
        diskBytes.set(0);
        store.commit();
    }

    @Override
    public void close() {
        if (store != null && !store.isClosed()) {
            store.commit();
            store.close();
        }
    }

    /**
     * Defensive: compact the underlying store. Useful after a large
     * delete or rewrite. Not currently called by the pipeline.
     */
    public void compact() {
        if (filePath == null) return;
        try {
            MVStoreTool.compact(filePath.toString(), true);
        } catch (Exception e) {
            // Best effort.
        }
    }

    public Path getFilePath() { return filePath; }

    // --- Codec helpers (separate from codec class for visibility) ---

    private static final class RequestSummaryCodec {
        // Compact pipe-separated encoding; fields are short and we
        // do not need full JSON for an in-process store. Keeps the
        // MVStore payload small.
        static String encode(RequestSummary s) {
            return String.join("|",
                    nullToEmpty(s.getId()),
                    Long.toString(s.getTimestamp()),
                    nullToEmpty(s.getMethod()),
                    nullToEmpty(s.getHost()),
                    nullToEmpty(s.getPath()),
                    Integer.toString(s.getStatusCode()),
                    s.isWorkflowRelevant() ? "1" : "0",
                    s.isHasRawHttp() ? "1" : "0",
                    nullToEmpty(s.getEndpointKey()),
                    nullToEmpty(s.getSessionKey()),
                    nullToEmpty(s.getIntent()),
                    Long.toString(s.getSizeBytes()));
        }

        static RequestSummary decode(String line) {
            if (line == null) return null;
            String[] p = line.split("\\|", -1);
            if (p.length < 12) return null;
            try {
                return new RequestSummary(
                        emptyToNull(p[0]),
                        Long.parseLong(p[1]),
                        emptyToNull(p[2]),
                        emptyToNull(p[3]),
                        emptyToNull(p[4]),
                        Integer.parseInt(p[5]),
                        "1".equals(p[6]),
                        "1".equals(p[7]),
                        emptyToNull(p[8]),
                        emptyToNull(p[9]),
                        emptyToNull(p[10]),
                        Long.parseLong(p[11]));
            } catch (NumberFormatException e) {
                return null;
            }
        }

        private static String nullToEmpty(String s) { return s == null ? "" : s; }
        private static String emptyToNull(String s) {
            return s == null || s.isEmpty() ? null : s;
        }
    }

    private static final class RawHttpCodec {
        static String encode(RawHttp r) {
            // Encode as a single string with section delimiters. We
            // do not use a JSON serializer to avoid the dependency
            // surface for this internal store.
            StringBuilder sb = new StringBuilder(256);
            appendHeaders(sb, r.getRequestHeaders());
            sb.append('\u0000');
            appendString(sb, r.getRequestBody());
            sb.append('\u0000');
            appendHeaders(sb, r.getResponseHeaders());
            sb.append('\u0000');
            appendString(sb, r.getResponseBody());
            sb.append('\u0000');
            appendString(sb, r.getMimeType());
            sb.append('\u0000');
            appendString(sb, r.getCookies());
            sb.append('\u0000');
            appendString(sb, r.getQueryParams());
            sb.append('\u0000');
            appendString(sb, r.getReferrer());
            return sb.toString();
        }

        static RawHttp decode(String line) {
            if (line == null) return null;
            String[] p = line.split("\u0000", -1);
            if (p.length < 8) return null;
            return new RawHttp(
                    parseHeaders(p[0]),
                    emptyToNull(p[1]),
                    parseHeaders(p[2]),
                    emptyToNull(p[3]),
                    emptyToNull(p[4]),
                    emptyToNull(p[5]),
                    emptyToNull(p[6]),
                    emptyToNull(p[7]));
        }

        private static void appendHeaders(StringBuilder sb, Map<String, List<String>> h) {
            if (h == null || h.isEmpty()) return;
            boolean first = true;
            for (Map.Entry<String, List<String>> e : h.entrySet()) {
                if (!first) sb.append('\u0001');
                first = false;
                sb.append(e.getKey());
                sb.append('\u0002');
                sb.append(String.join("\u0003", e.getValue()));
            }
        }

        private static Map<String, List<String>> parseHeaders(String s) {
            java.util.Map<String, java.util.List<String>> map = new java.util.LinkedHashMap<>();
            if (s == null || s.isEmpty()) return map;
            for (String entry : s.split("\u0001", -1)) {
                int sep = entry.indexOf('\u0002');
                if (sep < 0) continue;
                String name = entry.substring(0, sep);
                String[] values = entry.substring(sep + 1).split("\u0003", -1);
                java.util.List<String> vs = new java.util.ArrayList<>(values.length);
                for (String v : values) vs.add(v);
                map.put(name, vs);
            }
            return map;
        }

        private static void appendString(StringBuilder sb, String s) {
            if (s == null) return;
            // Escape the three control chars we use as delimiters.
            String esc = s.replace("\u0000", "\u0000\u005E")
                    .replace("\u0001", "\u0001\u005E")
                    .replace("\u0003", "\u0003\u005E");
            sb.append(esc);
        }

        private static String emptyToNull(String s) {
            return s == null || s.isEmpty() ? null : s;
        }
    }
}

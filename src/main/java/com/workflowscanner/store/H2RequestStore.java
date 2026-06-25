package com.workflowscanner.store;

import org.h2.mvstore.MVMap;
import org.h2.mvstore.MVStore;
import org.h2.mvstore.MVStoreTool;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
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
 * store well-suited to embedded use inside a Burp extension. No native
 * dependencies, no separate process. The store keeps four maps:
 *
 * <ul>
 *   <li>{@code summaries}        — {@code id -> compact(RequestSummary)}</li>
 *   <li>{@code raws}             — {@code id -> compact(RawHttp)}</li>
 *   <li>{@code meta}             — small {@code name -> long} map for counters</li>
 *   <li>{@code timeIndex}        — {@code timestamp|id -> id} for streaming
 *       in timestamp order without sorting in Java.</li>
 * </ul>
 *
 * <p>Summaries and raws are encoded with {@link Base64} over a small
 * delimiter protocol so delimiter collisions in user-controlled
 * strings (paths, headers, bodies, cookies) cannot corrupt the
 * decode.
 *
 * <p>Counter deltas are computed against the previous summary
 * (and previous raw length) so re-puts do not overcount.
 */
public class H2RequestStore implements RequestStore {

    private static final String SUMMARIES_MAP = "summaries";
    private static final String RAWS_MAP = "raws";
    private static final String META_MAP = "meta";
    private static final String TIME_INDEX_MAP = "timeIndex";

    private static final String META_TOTAL = "countAll";
    private static final String META_RELEVANT = "countRelevant";
    private static final String META_RAW = "countRaw";
    private static final String META_DISK = "diskBytes";

    // Batched commit at this many writes for durability without
    // hammering the disk.
    private static final int CHUNK_SIZE = 5000;

    // Section index for length-prefixed payload.
    private static final int SEC_REQ_HDR = 0;
    private static final int SEC_REQ_BODY = 1;
    private static final int SEC_RES_HDR = 2;
    private static final int SEC_RES_BODY = 3;
    private static final int SEC_MIME = 4;
    private static final int SEC_COOKIES = 5;
    private static final int SEC_QUERY = 6;
    private static final int SEC_REFERRER = 7;
    private static final int SECTION_COUNT = 8;

    private final MVStore store;
    private final MVMap<String, String> summaries;
    private final MVMap<String, String> raws;
    private final MVMap<String, Long> meta;
    private final MVMap<String, String> timeIndex; // "<padded-timestamp>|<id>" -> id
    private final Path filePath;
    private final boolean readOnly;
    private final AtomicLong diskBytes = new AtomicLong(0);

    /**
     * Open or create an on-disk store at the given path. The path
     * is created if it does not exist. Pass {@code null} for
     * in-memory mode (tests).
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
        this.timeIndex = store.openMap(TIME_INDEX_MAP);
        // Hydrate the disk-bytes counter from meta so we do not lie
        // on first read after a process restart.
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

        // --- Summary: delta counters against the previous value ---
        String prevEncodedSummary = summaries.get(id);
        RequestSummary prev = prevEncodedSummary == null
                ? null
                : RequestSummaryCodec.decode(prevEncodedSummary);
        String newEncodedSummary = RequestSummaryCodec.encode(summary);
        summaries.put(id, newEncodedSummary);

        if (prev == null) {
            meta.put(META_TOTAL, meta.getOrDefault(META_TOTAL, 0L) + 1L);
        }
        // Delta workflow-relevant: only +1 on transitions, -1 on
        // transitions back, 0 if it stays the same.
        boolean wasRelevant = prev != null && prev.isWorkflowRelevant();
        if (summary.isWorkflowRelevant() && !wasRelevant) {
            meta.put(META_RELEVANT, meta.getOrDefault(META_RELEVANT, 0L) + 1L);
        } else if (!summary.isWorkflowRelevant() && wasRelevant) {
            meta.put(META_RELEVANT, Math.max(0L, meta.getOrDefault(META_RELEVANT, 0L) - 1L));
        }

        // --- Raw: delta disk bytes against the previous raw ---
        if (raw != null) {
            String newEncodedRaw = RawHttpCodec.encode(raw);
            String prevEncodedRaw = raws.put(id, newEncodedRaw);
            if (prevEncodedRaw == null) {
                meta.put(META_RAW, meta.getOrDefault(META_RAW, 0L) + 1L);
            }
            long prevLen = prevEncodedRaw == null ? 0 : prevEncodedRaw.length();
            long newLen = newEncodedRaw.length();
            long delta = newLen - prevLen;
            if (delta != 0) {
                diskBytes.addAndGet(delta);
                long newDisk = meta.getOrDefault(META_DISK, 0L) + delta;
                if (newDisk < 0) newDisk = 0;
                meta.put(META_DISK, newDisk);
            }
        }

        // --- Time index: composite key so we can stream in
        // timestamp order without sorting in Java. ---
        String timeKey = timeKey(summary.getTimestamp(), id);
        timeIndex.put(timeKey, id);

        // Batched commit at CHUNK_SIZE writes for durability
        // without hammering the disk.
        if (meta.getOrDefault(META_TOTAL, 0L) % CHUNK_SIZE == 0) {
            store.commit();
        }
    }

    @Override
    public Optional<RequestSummary> getSummary(String requestId) {
        if (requestId == null) return Optional.empty();
        String encoded = summaries.get(requestId);
        if (encoded == null) return Optional.empty();
        return Optional.ofNullable(RequestSummaryCodec.decode(encoded));
    }

    @Override
    public Optional<RawHttp> getRaw(String requestId) {
        if (requestId == null) return Optional.empty();
        String encoded = raws.get(requestId);
        if (encoded == null) return Optional.empty();
        return Optional.ofNullable(RawHttpCodec.decode(encoded));
    }

    /**
     * Stream summaries in timestamp-ascending order. Uses the
     * {@code timeIndex} which is already sorted, so no in-memory
     * sort is required and the stream can be evaluated lazily.
     */
    @Override
    public Stream<RequestSummary> streamAll() {
        Iterable<String> keys = timeIndex.keySet();
        return StreamSupport.stream(keys.spliterator(), false)
                .map(timeIndex::get)
                .filter(java.util.Objects::nonNull)
                .map(summaries::get)
                .filter(java.util.Objects::nonNull)
                .map(RequestSummaryCodec::decode)
                .filter(java.util.Objects::nonNull);
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
        try (Stream<RequestSummary> all = streamAll()) {
            for (java.util.Iterator<RequestSummary> it = all.iterator(); it.hasNext();) {
                RequestSummary s = it.next();
                if (from > 0 && s.getTimestamp() < from) continue;
                if (to > 0 && s.getTimestamp() > to) continue;
                if (host.equalsIgnoreCase(s.getHost())) out.add(s);
            }
        }
        return out;
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

    // --- Codec helpers ---
    //
    // Both codecs wrap their payload in Base64-URL so any byte the
    // user can put in a header, body, cookie, or query string is
    // safe to decode. The internal delimiter bytes below
    // (0x00..0x08) only ever appear inside the base64-decoded
    // payload, never in the stored record.

    private static String timeKey(long ts, String id) {
        // 20-digit zero-padded timestamp + "|" + id, lexicographic
        // order matches numeric timestamp order.
        return String.format("%020d|%s", ts, id);
    }

    private static final class RequestSummaryCodec {
        // Each user-controlled string field is base64-URL encoded
        // individually before joining with "|". This way the join
        // delimiter ("|") can never appear inside a field, and
        // the split on decode is exact. The numeric and boolean
        // fields are written as their string forms (no pipes,
        // no base64 needed).
        static String encode(RequestSummary s) {
            StringBuilder sb = new StringBuilder(256);
            b64Append(sb, s.getId());            sb.append('|');
            sb.append(s.getTimestamp());         sb.append('|');
            b64Append(sb, s.getMethod());        sb.append('|');
            b64Append(sb, s.getHost());          sb.append('|');
            b64Append(sb, s.getPath());          sb.append('|');
            sb.append(s.getStatusCode());        sb.append('|');
            sb.append(s.isWorkflowRelevant() ? 1 : 0);  sb.append('|');
            sb.append(s.isHasRawHttp() ? 1 : 0); sb.append('|');
            b64Append(sb, s.getEndpointKey());   sb.append('|');
            b64Append(sb, s.getSessionKey());    sb.append('|');
            b64Append(sb, s.getIntent());        sb.append('|');
            sb.append(s.getSizeBytes());
            return sb.toString();
        }

        static RequestSummary decode(String line) {
            if (line == null || line.isEmpty()) return null;
            String[] p = line.split("\\|", -1);
            if (p.length < 12) return null;
            try {
                return new RequestSummary(
                        b64Decode(p[0]),
                        Long.parseLong(p[1]),
                        b64Decode(p[2]),
                        b64Decode(p[3]),
                        b64Decode(p[4]),
                        Integer.parseInt(p[5]),
                        p[6].length() == 1 && p[6].charAt(0) == '1',
                        p[7].length() == 1 && p[7].charAt(0) == '1',
                        b64Decode(p[8]),
                        b64Decode(p[9]),
                        b64Decode(p[10]),
                        Long.parseLong(p[11]));
            } catch (NumberFormatException e) {
                return null;
            }
        }

        private static void b64Append(StringBuilder sb, String s) {
            if (s == null) return;
            // length-prefixed so an empty string and a missing
            // field are still distinguishable on decode.
            sb.append(s.length()).append(':');
            sb.append(Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(s.getBytes(StandardCharsets.UTF_8)));
        }

        private static String b64Decode(String s) {
            if (s == null || s.isEmpty()) return null;
            int colon = s.indexOf(':');
            if (colon < 0) return null;
            int declaredLen;
            try {
                declaredLen = Integer.parseInt(s.substring(0, colon));
            } catch (NumberFormatException e) {
                return null;
            }
            String token = s.substring(colon + 1);
            byte[] bytes;
            try {
                bytes = Base64.getUrlDecoder().decode(token);
            } catch (IllegalArgumentException e) {
                return null;
            }
            if (bytes.length != declaredLen) return null;
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

    private static final class RawHttpCodec {
        // Length-prefixed sections wrapped in base64. The outer
        // base64 wrapper is what makes this safe for arbitrary
        // user content — section boundaries depend on a 4-byte
        // length prefix, never on a delimiter character that user
        // content could match.
        static String encode(RawHttp r) {
            String[] sections = new String[SECTION_COUNT];
            sections[SEC_REQ_HDR] = encodeHeaders(r.getRequestHeaders());
            sections[SEC_REQ_BODY] = str(r.getRequestBody());
            sections[SEC_RES_HDR] = encodeHeaders(r.getResponseHeaders());
            sections[SEC_RES_BODY] = str(r.getResponseBody());
            sections[SEC_MIME] = str(r.getMimeType());
            sections[SEC_COOKIES] = str(r.getCookies());
            sections[SEC_QUERY] = str(r.getQueryParams());
            sections[SEC_REFERRER] = str(r.getReferrer());
            // 4 bytes per section length + UTF-8 payload.
            int total = SECTION_COUNT * 4;
            byte[][] bytes = new byte[SECTION_COUNT][];
            for (int i = 0; i < SECTION_COUNT; i++) {
                bytes[i] = sections[i] == null
                        ? new byte[0]
                        : sections[i].getBytes(StandardCharsets.UTF_8);
                total += bytes[i].length;
            }
            byte[] out = new byte[total];
            int off = 0;
            for (int i = 0; i < SECTION_COUNT; i++) {
                int len = bytes[i].length;
                out[off++] = (byte) ((len >>> 24) & 0xFF);
                out[off++] = (byte) ((len >>> 16) & 0xFF);
                out[off++] = (byte) ((len >>> 8) & 0xFF);
                out[off++] = (byte) (len & 0xFF);
                System.arraycopy(bytes[i], 0, out, off, len);
                off += len;
            }
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(out);
        }

        static RawHttp decode(String b64) {
            if (b64 == null || b64.isEmpty()) return null;
            byte[] payload;
            try {
                payload = Base64.getUrlDecoder().decode(b64);
            } catch (IllegalArgumentException e) {
                return null;
            }
            // The payload is a sequence of (int32 length, utf-8
            // bytes) sections, in section-index order. Read the
            // length of section i, then skip that many bytes to
            // find the length of section i+1.
            int[] lengths = new int[SECTION_COUNT];
            int off = 0;
            for (int i = 0; i < SECTION_COUNT; i++) {
                if (off + 4 > payload.length) return null;
                int len = ((payload[off] & 0xFF) << 24)
                        | ((payload[off + 1] & 0xFF) << 16)
                        | ((payload[off + 2] & 0xFF) << 8)
                        | (payload[off + 3] & 0xFF);
                lengths[i] = len;
                off += 4 + len;
            }
            if (off != payload.length) return null;
            String[] values = new String[SECTION_COUNT];
            int cur = 0;
            for (int i = 0; i < SECTION_COUNT; i++) {
                cur += 4; // skip length prefix
                int len = lengths[i];
                if (len == 0) {
                    values[i] = null;
                } else {
                    values[i] = new String(payload, cur, len, StandardCharsets.UTF_8);
                    cur += len;
                }
            }
            return new RawHttp(
                    decodeHeaders(values[SEC_REQ_HDR]),
                    emptyToNull(values[SEC_REQ_BODY]),
                    decodeHeaders(values[SEC_RES_HDR]),
                    emptyToNull(values[SEC_RES_BODY]),
                    emptyToNull(values[SEC_MIME]),
                    emptyToNull(values[SEC_COOKIES]),
                    emptyToNull(values[SEC_QUERY]),
                    emptyToNull(values[SEC_REFERRER]));
        }

        private static String str(String s) { return s == null ? "" : s; }
        private static String emptyToNull(String s) {
            return s == null || s.isEmpty() ? null : s;
        }

        private static String encodeHeaders(Map<String, List<String>> h) {
            if (h == null || h.isEmpty()) return "";
            StringBuilder sb = new StringBuilder();
            boolean first = true;
            for (Map.Entry<String, List<String>> e : h.entrySet()) {
                if (!first) sb.append('\n');
                first = false;
                sb.append(e.getKey());
                sb.append('=');
                if (e.getValue() != null) {
                    for (int i = 0; i < e.getValue().size(); i++) {
                        if (i > 0) sb.append(",");
                        sb.append(e.getValue().get(i));
                    }
                }
            }
            return sb.toString();
        }

        private static Map<String, List<String>> decodeHeaders(String s) {
            Map<String, List<String>> map = new LinkedHashMap<>();
            if (s == null || s.isEmpty()) return map;
            for (String line : s.split("\n", -1)) {
                int eq = line.indexOf('=');
                if (eq < 0) continue;
                String name = line.substring(0, eq);
                String values = line.substring(eq + 1);
                List<String> vs = new ArrayList<>();
                if (!values.isEmpty()) {
                    for (String v : values.split(",", -1)) vs.add(v);
                }
                map.put(name, vs);
            }
            return map;
        }
    }
}

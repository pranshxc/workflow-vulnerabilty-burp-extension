# Phase 1: Project skeleton, Gradle build, Montoya entry point, config POJO

## Overview

Set up the foundational Burp Suite extension project structure, build system, and entry point class. This is the first issue to implement — everything else depends on it.

## Requirements

### Project Structure

```
workflow-vuln-scanner/
├── build.gradle (or pom.xml)
├── src/
│   └── main/
│       └── java/
│           └── com/workflowscanner/
│               ├── WorkflowVulnScanner.java          # BurpExtender entry point
│               ├── config/
│               │   └── ExtensionConfig.java           # Settings POJO
│               ├── data/                              # Data layer (future)
│               ├── graph/                             # Graph layer (future)
│               ├── llm/                               # LLM layer (future)
│               ├── analysis/                          # Analysis layer (future)
│               ├── advisory/                          # Burp advisory layer (future)
│               ├── ui/                                # UI panels (future)
│               └── logging/                           # Logging layer (future)
├── resources/
└── README.md
```

### Entry Point (`WorkflowVulnScanner.java`)

- Implement `BurpExtension` (Montoya API) interface
- Register the extension with Burp Suite
- Initialize all subsystems in correct order:
  1. Logging subsystem
  2. Configuration loader
  3. Graph data store
  4. Request processor
  5. LLM client
  6. Analysis engine
  7. UI panels
  8. HTTP handler registration
  9. Context menu registration
- Graceful shutdown / cleanup on extension unload

### Build System

- Gradle with shadow/fat JAR plugin (single deployable JAR)
- Dependency on Montoya API (`net.portswigger.burp.extensions:montoya-api`)
- Java 17+ target
- Produce a single JAR loadable by Burp Suite

### Configuration POJO (`ExtensionConfig.java`)

- LLM Base URL, Model ID, API Key
- Graph data directory path
- Backfill limit and scope
- Scope filter patterns (list of glob/regex patterns)
- Serializable to/from JSON for persistence
- Load/save from Burp's persistence API or local file

## Acceptance Criteria

- [ ] Extension loads in Burp Suite without errors
- [ ] Extension name and version displayed in Burp's Extensions tab
- [ ] All package directories created with placeholder classes
- [ ] Build produces a single fat JAR
- [ ] Configuration can be loaded and saved
- [ ] Extension unloads cleanly without resource leaks
- [ ] README updated with build instructions and project overview

## Technical Notes

- Use Montoya API (not legacy `IBurpExtenderCallbacks`) — it's the modern Burp API
- All subsystem initialization should be fault-tolerant (log errors, don't crash the extension)
- Consider using a simple dependency injection pattern or service locator for subsystem access



---



# Phase 2: Async logging with ring buffer, file writer, filtering, export

## Overview

Implement a centralized logging subsystem that captures **everything** — every LLM request/response, every backfill event, every graph operation, every analysis step. This is critical for debugging, transparency, and trust in findings.

## Requirements

### Log Categories

Each log entry must be categorized:

- `LLM_REQUEST` — outbound LLM API call (full prompt, model, parameters)
- `LLM_RESPONSE` — inbound LLM response (full response body, tokens used, latency)
- `BACKFILL` — proxy history backfill progress (count, scope, duration)
- `GRAPH` — graph building events (node added, edge created, merge, etc.)
- `ANALYSIS` — analysis pipeline events (node selected, verdict, reasoning)
- `ADVISORY` — Burp issue creation/update events
- `CONFIG` — configuration changes
- `ERROR` — errors and exceptions with full stack traces
- `EXTENSION` — lifecycle events (init, shutdown, subsystem status)

### Log Entry Structure

```
[TIMESTAMP] [CATEGORY] [LEVEL] [SOURCE] MESSAGE
--- DETAIL (optional, multi-line) ---
```

Example:

```
[2024-01-15 14:32:01.123] [LLM_REQUEST] [INFO] [LLMClient] Sending graph node #178 for analysis
--- REQUEST BODY ---
{"model": "gpt-4", "messages": [...], "temperature": 0.2}
--- END ---
```

### Log Levels

- `DEBUG` — verbose internal state
- `INFO` — normal operations
- `WARN` — recoverable issues
- `ERROR` — failures requiring attention

### Storage & Access

- In-memory ring buffer (configurable size, default 10,000 entries) for UI display
- Optional file-based logging to the graph data directory
- **No redaction** — everything raw, as specified
- Thread-safe (multiple Burp threads will log concurrently)

### Log Panel Integration (API only in this issue)

- Expose API for the UI Log Panel to consume:
  - `getEntries(category?, level?, limit, offset)` — filtered retrieval
  - `stream()` — live tail for UI updates
  - `clear()` — clear in-memory buffer
  - `exportToFile(path)` — dump all logs

## Acceptance Criteria

- [ ] All log categories implemented and documented
- [ ] Thread-safe concurrent logging from multiple Burp threads
- [ ] In-memory ring buffer with configurable size
- [ ] File-based logging option
- [ ] No redaction — raw data logged for LLM requests/responses
- [ ] Filterable by category and level
- [ ] Timestamps with millisecond precision
- [ ] Performance: logging should not block the calling thread (async write)

## Technical Notes

- Keep it simple — avoid heavy frameworks. A well-designed custom logger is fine.
- Consider using a `BlockingQueue` + dedicated writer thread for async file writes.
- The UI panel for viewing logs is a separate issue — this issue provides the backend.



---



# Phase 3: Proxy listener, backfill service, context menu, scope filter, pipeline



## Overview

Implement the three data sources that feed requests into the extension's processing pipeline:

1. **Live Proxy Traffic** — new requests flowing through Burp's proxy
2. **Proxy History Backfill** — historical requests already captured before the extension was loaded
3. **User-Selected Requests** — requests sent manually via Burp's context menu (single or grouped)

This is the "Data Layer" from the architecture blueprint.

## Architecture Reference

```
+------------------+
| NEW REQUESTS     |  ← Live proxy listener (HttpHandler)
+------------------+
          \
           \
            +----------------+
            | INPUT REQUEST  |  ← Unified internal request model
            +----------------+
           /          \
          /            \
+------------------+   +------------------------------+
| PROXY HISTORY    |   | USER SENT REQUEST            |
| (BACKFILL)       |   | BY CONTEXT MENU              |
+------------------+   | (GROUP/MULTIPLE REQUESTS)    |
                        +------------------------------+
```

## Requirements

### 1. Unified Request Model (`CapturedRequest`)

Internal representation of a request/response pair:

```java
class CapturedRequest {
    String id;                    // Unique identifier
    long timestamp;               // Capture time (epoch ms)
    String method;                // GET, POST, PUT, etc.
    String url;                   // Full URL
    String host;                  // Hostname
    String path;                  // URL path
    Map<String, String> queryParams;
    Map<String, List<String>> requestHeaders;
    String requestBody;           // Raw body (no redaction)
    int statusCode;
    Map<String, List<String>> responseHeaders;
    String responseBody;          // Raw body (no redaction)
    String mimeType;
    String source;                // "PROXY", "BACKFILL", "CONTEXT_MENU"
    List<String> cookies;
    String referrer;
    String contentType;
    boolean isInScope;            // Matches scope filter
}
```

### 2. Live Proxy Listener

- Register as `HttpHandler` via Montoya API
- Capture every request/response pair flowing through the proxy
- Convert to `CapturedRequest` model
- Apply scope filter before forwarding to processing pipeline
- Must not slow down proxy traffic — processing happens asynchronously
- Log each captured request at DEBUG level

### 3. Proxy History Backfill

- On-demand backfill triggered by user (button in UI or on extension load)
- Read from `api.proxy().history()` (Montoya API)
- Configurable **limit** (max number of requests to backfill)
- Configurable **scope** (apply scope filter to historical requests)
- Progress reporting: log and expose progress (e.g., "Backfilled 150/500 requests")
- Run in background thread — must not freeze Burp UI
- Deduplicate against already-ingested requests (by URL + method + timestamp)
- Respect the configured backfill limit from settings

### 4. Context Menu Integration

- Register context menu item: "Send to Workflow Scanner" (or similar)
- Available in Proxy History, Repeater, Target Site Map
- Support **single request** and **multiple selected requests**
- Convert selected items to `CapturedRequest` model
- When multiple requests are selected, treat them as a **group** (potential workflow chain)
- Log the user action and number of requests sent

### 5. Scope Filtering

- Apply scope filter patterns from configuration
- Support glob patterns (e.g., `*.example.com`, `*.example.*`)
- Requests outside scope are silently dropped (logged at DEBUG)
- Scope filter applies to all three data sources uniformly

### 6. Request Pipeline

- All three sources feed into a single `RequestPipeline` / queue
- Pipeline is a thread-safe queue consumed by the Graph Builder (next layer)
- Backpressure handling: if graph builder is slow, queue should be bounded with overflow strategy (drop oldest or block)

## Acceptance Criteria

- [ ] Live proxy requests captured and converted to internal model
- [ ] Backfill reads from proxy history with configurable limit and scope
- [ ] Backfill runs in background thread with progress logging
- [ ] Context menu appears in Proxy History, Repeater, and Site Map
- [ ] Single and multiple request selection supported via context menu
- [ ] Scope filter applied uniformly across all data sources
- [ ] Glob pattern matching works for scope filters (e.g., `*.example.com`)
- [ ] Unified request pipeline feeds downstream graph builder
- [ ] No redaction — raw request/response bodies preserved
- [ ] All events logged (capture, backfill progress, context menu actions)
- [ ] Proxy performance not degraded (async processing)

## Technical Notes

- Use Montoya API's `HttpHandler` for live traffic, `ContextMenuItemsProvider` for context menu
- Backfill should use `api.proxy().history()` — iterate with care on large histories
- Consider a `LinkedBlockingQueue` with configurable capacity for the request pipeline
- Scope matching: convert glob patterns to regex at config load time for performance



---



# Phase 4: Graph builder with 5 heuristics, inverted index, chain detection, persistence



## Overview

Implement the **Macro / Chain Layer** — the core intelligence that takes individual captured requests and builds a directed graph of relationships between them. This graph represents how endpoints connect and how data flows through multi-step workflows.

This is the most critical data structure in the extension. The quality of vulnerability detection depends entirely on the accuracy of this graph.

## Architecture Reference

```
Redirect Chains --------\
Referrer Header ---------\
Time Window ------------- > Graph Relation Between Requests
Parameter Reuse ---------/
Response→Request -------/
Correlation
```

## Requirements

### 1. Graph Data Model

```java
class RequestNode {
    String id;                          // Unique node ID
    CapturedRequest request;            // The actual request/response
    String method;                      // HTTP method
    String host;
    String path;
    Map<String, Object> extractedParams; // All parameters (query, body, headers)
    Map<String, Object> responseData;    // Extracted response data (JSON fields, set-cookie, etc.)
    long timestamp;
    int nodeIndex;                      // Sequential index for LLM context
}

class RequestEdge {
    String sourceNodeId;
    String targetNodeId;
    EdgeType type;                      // REDIRECT, REFERRER, TIME_WINDOW, PARAM_REUSE, RESPONSE_CORRELATION
    double confidence;                  // 0.0 - 1.0 confidence score
    String evidence;                    // Human-readable explanation of why this edge exists
}

enum EdgeType {
    REDIRECT,              // HTTP 3xx redirect chain
    REFERRER,              // Referer header points to source
    TIME_WINDOW,           // Requests within configurable time window
    PARAM_REUSE,           // Parameter value from response appears in next request
    RESPONSE_CORRELATION,  // Response body data used in subsequent request
    USER_DEFINED           // Manually grouped by user via context menu
}

class RequestGraph {
    Map<String, RequestNode> nodes;
    List<RequestEdge> edges;
    // Graph operations...
}
```

### 2. Relationship Detection Heuristics

#### a) Redirect Chains

- Detect HTTP 3xx responses where the `Location` header matches a subsequent request's URL
- Chain: `A → 302 Location: /B` + `GET /B` → Edge(A→B, REDIRECT, confidence=1.0)
- Follow full redirect chains (A→B→C→D)

#### b) Referrer Header Analysis

- If request B has `Referer: URL_of_A`, create Edge(A→B, REFERRER, confidence=0.9)
- Handle both `Referer` and `Referrer` header spellings
- Normalize URLs before matching (strip fragments, normalize encoding)

#### c) Time Window Correlation

- Requests from the same host within a configurable time window (default: 5 seconds)
- Lower confidence than explicit links: confidence=0.3-0.5
- Ordered by timestamp
- Only create edges between requests to the same host (or related hosts per scope)

#### d) Parameter Reuse Detection

- Extract all parameters from each request (query string, POST body, JSON body, URL path segments)
- Extract all "interesting" values from each response (JSON field values, Set-Cookie values, hidden form fields, tokens in response body)
- If a value from Response A appears as a parameter in Request B → Edge(A→B, PARAM_REUSE, confidence=0.8)
- **Key patterns to detect:**
  - CSRF tokens passed from response to next request
  - Session tokens / auth tokens
  - IDs (order ID, user ID, transaction ID) flowing through steps
  - Prices, quantities, or other business values
- Minimum value length threshold (skip very short/common values like "true", "1", "0")

#### e) Response → Request Correlation

- Parse JSON responses and look for values that appear in subsequent requests
- Parse HTML responses for form actions, hidden fields, and links that match subsequent requests
- Detect `Set-Cookie` → `Cookie` header chains
- Confidence varies: exact match = 0.85, partial/substring = 0.5

### 3. Graph Operations

- `addRequest(CapturedRequest)` — add a new node and compute edges to existing nodes
- `getWorkflowChains()` — return all connected subgraphs (each is a potential workflow)
- `getChainForNode(nodeId)` — return the full chain containing this node
- `getNodesByHost(host)` — filter nodes by hostname
- `getNodesByPath(pathPattern)` — filter nodes by path pattern
- `serialize() / deserialize()` — save/load graph to/from the configured directory
- `merge(RequestGraph other)` — merge backfill data into live graph
- `getStats()` — node count, edge count, chain count, etc.

### 4. Performance Requirements

- Graph building must handle **thousands of requests** without degradation
- Edge computation should be incremental (only compute edges for new nodes against existing nodes)
- Use indexing for parameter value lookups (inverted index: value → list of nodes containing it)
- Background thread for graph building — never block the proxy or UI

### 5. Persistence

- Save graph to the configured directory path as JSON files
- Auto-save periodically (configurable interval, default: every 60 seconds)
- Load on extension startup if data exists
- Support clearing/resetting the graph

## Acceptance Criteria

- [ ] All five relationship detection heuristics implemented
- [ ] Confidence scores assigned to each edge type
- [ ] Evidence strings explain why each edge was created
- [ ] Graph correctly identifies multi-step workflow chains
- [ ] Parameter reuse detection works for JSON, form data, query strings, cookies
- [ ] Redirect chains fully followed and linked
- [ ] Incremental graph building (new requests don't reprocess entire graph)
- [ ] Graph serialization/deserialization to configured directory
- [ ] Performance: handles 5,000+ nodes without noticeable lag
- [ ] All graph events logged (node added, edge created, chain detected)
- [ ] Thread-safe concurrent access (proxy thread adds, analysis thread reads)

## Technical Notes

- Consider an adjacency list representation for the graph (efficient for sparse graphs)
- For parameter reuse detection, build an inverted index: `Map<String, Set<String>>` mapping values to node IDs
- Set a minimum value length (e.g., 4+ characters) to avoid false positive edges on common short values
- URL normalization is critical — use a consistent canonicalization approach
- For large graphs, consider pruning old/low-confidence edges periodically




---




# Phase 5: LLM client, system prompt, prompt builder, context manager, response parser



## Overview

Implement the LLM integration layer — an OpenAI-compatible HTTP client that sends graph nodes (with full request/response data and accumulated context) to an LLM for workflow vulnerability analysis. This is the "brain" that reasons about whether a workflow chain contains exploitable vulnerabilities.

## Architecture Reference

```
GRAPH NODE #178
  - With LLM past context
        |
        v
LLM JSON
  - All requests and responses
        |
        v
LLM ANALYSIS
  - Verdict
  - Reasoning
  - Tests
```

## Requirements

### 1. LLM Client (`LLMClient`)

- HTTP client for OpenAI-compatible chat completion API
- Configurable: Base URL, Model ID, API Key (from `ExtensionConfig`)
- **Test Connection** functionality — validate credentials and model availability
- Retry logic with exponential backoff (max 3 retries)
- Timeout handling (configurable, default 60 seconds per request)
- Rate limiting awareness (respect 429 responses)
- All requests and responses logged in full (no redaction) via the logging subsystem

### 2. Request Format

Standard OpenAI chat completion format:

```json
{
  "model": "configured-model-id",
  "messages": [
    {"role": "system", "content": "SYSTEM_PROMPT"},
    {"role": "user", "content": "GRAPH_NODE_CONTEXT + REQUEST_DATA"}
  ],
  "temperature": 0.2,
  "response_format": {"type": "json_object"}
}
```

### 3. System Prompt Engineering

The system prompt must instruct the LLM to act as a workflow vulnerability analyst. It should encode the attacker mental models:

```
You are a security analyst specializing in multi-step workflow vulnerabilities. 
You analyze HTTP request/response chains to identify vulnerabilities that exist 
in the RELATIONSHIPS between requests, not in individual requests.

You think in these attack modes:
1. THE SKIPPER: Can steps be skipped? Does step N verify step N-1 completed?
2. THE REPEATER: Can one-time actions be repeated? Are there missing idempotency checks?
3. THE MANIPULATOR: Can values be changed between steps that the server no longer validates?
4. THE PARALLEL EXECUTOR: Can race conditions be triggered with concurrent requests?
5. THE STATE CONFUSER: Can the system be put into an inconsistent state?

Root causes you look for:
- Implicit trust in client-reported state
- Missing state validation between steps
- Missing re-validation of values set in earlier steps
- Race conditions from concurrent valid states
- IDOR in sequential workflows
- Missing rate limits on bounded actions
- Logic gaps in business rules
- Stale data used despite invalidation

You MUST respond in JSON format with your analysis.
```

### 4. Context Management (`LLMContextManager`)

Critical feature: each analyzed node contributes context for future node analysis.

```java
class LLMContextManager {
    // Rolling context window
    List<NodeAnalysisContext> previousAnalyses;
    int maxContextTokens;  // Configurable token budget
    
    // Build prompt for a new node including relevant past context
    String buildPrompt(RequestNode node, List<RequestEdge> edges);
    
    // Add completed analysis to context
    void addAnalysisResult(NodeAnalysisContext result);
    
    // Prune old context to stay within token budget
    void pruneContext();
}

class NodeAnalysisContext {
    int nodeIndex;
    String summary;          // Condensed summary of the node
    String verdict;          // VULNERABLE / SUSPICIOUS / SAFE
    String keyFindings;      // Brief findings
    List<String> stateInfo;  // State/tokens/IDs discovered
}
```

**Context enrichment strategy:**

- Each analyzed node produces a summary that's added to context
- Subsequent nodes receive relevant prior context (same host, related parameters)
- Context is pruned to stay within model's token limit
- Priority: recent nodes \> high-confidence findings \> older context

### 5. User Message Format (per node)

```
## Graph Node #{nodeIndex}

### Workflow Chain Context
[Previous node summaries and findings relevant to this chain]

### Current Request
Method: {method}
URL: {url}
Headers:
{headers}
Body:
{body}

### Response
Status: {statusCode}
Headers:
{responseHeaders}
Body:
{responseBody}

### Relationships
- Connected to Node #{otherNode} via {edgeType} (confidence: {confidence})
  Evidence: {evidence}
- ...

### Parameters Flowing Through This Chain
- Token "csrf_abc123" first seen in Node #12, reused here
- Order ID "ORD-456" set in Node #15, present in this request
- ...

Analyze this node for workflow vulnerabilities. Consider the full chain context.
```

### 6. Expected LLM Response Format

```json
{
  "verdict": "VULNERABLE | SUSPICIOUS | SAFE",
  "confidence": 0.85,
  "vulnerability_type": "step_skipping | value_manipulation | race_condition | state_confusion | replay_attack | idor_in_workflow | missing_rate_limit | null",
  "reasoning": "Detailed explanation of the finding...",
  "attack_scenario": "Step-by-step description of how to exploit this...",
  "affected_parameters": ["param1", "param2"],
  "suggested_tests": [
    {
      "test_name": "Skip step 2 and go directly to step 3",
      "method": "POST",
      "url": "/api/confirm",
      "modifications": {"order_total": "0.01"},
      "expected_behavior": "Server should reject without valid step 2 token"
    }
  ],
  "chain_context_update": "Summary of what was learned from this node for future analysis"
}
```

### 7. Response Parsing

- Parse JSON response with validation
- Handle malformed responses gracefully (log error, mark as unparseable)
- Extract structured `LLMAnalysisResult` object
- Feed `chain_context_update` back into `LLMContextManager`

## Acceptance Criteria

- [ ] OpenAI-compatible HTTP client with configurable base URL, model, and API key
- [ ] Test Connection button validates credentials and returns model info
- [ ] System prompt encodes all 5 attacker mental models and root causes
- [ ] Context management accumulates findings across nodes in a chain
- [ ] Context pruning stays within configurable token budget
- [ ] Full request/response data sent to LLM (no redaction)
- [ ] JSON response parsing with validation and error handling
- [ ] Retry logic with exponential backoff
- [ ] All LLM requests and responses logged in full
- [ ] Rate limiting / 429 handling
- [ ] Timeout handling with configurable duration
- [ ] Async execution — LLM calls don't block the UI or proxy

## Technical Notes

- Use Java's `HttpClient` (Java 11+) for HTTP calls — no need for external HTTP libraries
- Token counting: approximate with `chars / 4` for context budget management (or use tiktoken if available)
- Consider streaming responses for long analyses (SSE parsing)
- The system prompt is the most important part — iterate on it based on real-world testing
- Temperature 0.2 for consistency; consider allowing user override




---



# Phase 6: Analysis engine, chain prioritizer, heuristic pre-filter, verdict aggregation




## Overview

Implement the analysis orchestration engine that ties the Graph and LLM layers together. This engine selects which workflow chains to analyze, feeds nodes to the LLM in the correct order, accumulates context, and produces final verdicts.

This is the "conductor" — it decides **what** to analyze, **in what order**, and **how to interpret** the results.

## Architecture Reference

```
Request Graph
    |
    v
Chain Selector (prioritize interesting chains)
    |
    v
Node Iterator (walk chain in order)
    |
    v
LLM Analysis (per node, with accumulated context)
    |
    v
Verdict Aggregator (chain-level verdict from node-level results)
    |
    v
Burp Advisory Layer (report findings)
```

## Requirements

### 1. Chain Selection & Prioritization

Not all chains are equally interesting. Prioritize chains that are more likely to contain workflow vulnerabilities:

**Priority scoring heuristics:**

- Chains with **state-changing methods** (POST, PUT, DELETE, PATCH) score higher
- Chains with **authentication/authorization endpoints** (login, oauth, token, session) score higher
- Chains with **financial/transactional endpoints** (payment, checkout, transfer, order) score higher
- Chains with **parameter reuse edges** (data flowing between steps) score higher
- Chains with **more nodes** (longer workflows = more attack surface) score higher
- Chains with **mixed methods** (GET→POST→GET pattern) score higher
- Chains that are **purely static assets** (images, CSS, JS) score lowest / skip

```java
class ChainPrioritizer {
    double scoreChain(List<RequestNode> chain, List<RequestEdge> edges);
    List<List<RequestNode>> prioritize(List<List<RequestNode>> chains);
}
```

### 2. Node-by-Node Analysis Orchestration

For each selected chain:

1. Sort nodes by timestamp (chronological order)
2. For each node in order: a. Build LLM prompt with node data + accumulated context b. Send to LLM client c. Parse response d. Add findings to context for next node e. Record node-level verdict
3. After all nodes analyzed, compute chain-level verdict

### 3. Chain-Level Verdict Aggregation

Combine node-level results into a chain-level finding:

```java
class ChainVerdict {
    String chainId;
    List<RequestNode> chain;
    String overallVerdict;           // VULNERABLE / SUSPICIOUS / SAFE
    double overallConfidence;
    String vulnerabilityType;
    String attackNarrative;          // Full story of the vulnerability
    List<NodeAnalysisResult> nodeResults;
    List<SuggestedTest> suggestedTests;
}
```

**Aggregation rules:**

- If ANY node is VULNERABLE with confidence \> 0.7 → chain is VULNERABLE
- If multiple nodes are SUSPICIOUS → chain may be VULNERABLE (escalate)
- If all nodes are SAFE → chain is SAFE
- Confidence = weighted average of node confidences (higher weight for VULNERABLE nodes)

### 4. Analysis Queue & Scheduling

- Analysis runs in a background thread pool
- Configurable concurrency (default: 1 concurrent chain analysis to manage LLM rate limits)
- Queue of chains to analyze, processed in priority order
- Ability to pause/resume analysis
- Ability to cancel in-progress analysis
- Progress tracking: "Analyzing chain 3/15, node 4/7"

### 5. Deduplication & Caching

- Don't re-analyze chains that haven't changed
- Cache analysis results keyed by chain fingerprint (sorted node IDs + edge types)
- Invalidate cache when new nodes are added to a chain
- Allow manual re-analysis (force refresh)

### 6. Heuristic Pre-Filtering (before LLM)

Before sending to the LLM (which costs time and tokens), apply fast heuristic checks:

- **Step-skip detection**: Check if later endpoints in a chain are directly accessible without earlier steps (simple HTTP probe)
- **Parameter tampering signals**: Identify parameters that look like prices, quantities, IDs, roles
- **Missing CSRF tokens**: Detect state-changing requests without anti-CSRF tokens
- **Session fixation signals**: Detect session tokens that don't rotate after authentication
- **Rate limit absence**: Detect endpoints that accept rapid repeated requests

These heuristics don't replace LLM analysis but help prioritize and provide additional signal.

### 7. Analysis Events & Logging

- Log every analysis step: chain selected, node analyzed, verdict reached
- Emit events for UI updates (progress, findings)
- Track analysis statistics: chains analyzed, findings count, LLM calls made, tokens used

## Acceptance Criteria

- [ ] Chain prioritization scores and sorts chains by vulnerability likelihood
- [ ] Node-by-node analysis with context accumulation works correctly
- [ ] Chain-level verdict aggregation produces meaningful overall findings
- [ ] Background thread pool with configurable concurrency
- [ ] Pause/resume/cancel analysis controls
- [ ] Progress tracking exposed for UI consumption
- [ ] Deduplication prevents redundant re-analysis
- [ ] Heuristic pre-filtering reduces unnecessary LLM calls
- [ ] Static asset chains automatically deprioritized/skipped
- [ ] All analysis events logged comprehensively
- [ ] Analysis doesn't block proxy traffic or UI

## Technical Notes

- Use `ExecutorService` with configurable thread pool for analysis scheduling
- Chain fingerprinting: hash of sorted (method+path) pairs in the chain
- Heuristic pre-filters should be fast (\< 100ms per chain) — they run before the slow LLM call
- Consider a state machine for analysis lifecycle: QUEUED → ANALYZING → COMPLETE / FAILED / CANCELLED
- The verdict aggregation logic will need tuning based on real-world results — keep it configurable




---



# Phase 7: Validation Layer: Automated Vulnerability Confirmation via Request Replay




## Overview

Implement the validation layer that takes LLM-identified potential vulnerabilities and **confirms them** by replaying requests with mutations. This is what separates this tool from a theoretical scanner — it proves findings are real by actually testing them.

The goal: **zero false positives that reach the user**. Every reported vulnerability should be validated or clearly marked as "unconfirmed."

## Requirements

### 1. Validation Strategy per Vulnerability Type

#### a) Step Skipping Validation

```
Original flow: Step1 → Step2 → Step3
Test: Send Step3 request directly (skip Step1 and Step2)
Validate: Does Step3 succeed without prerequisites?
```

- Replay the final step's request without completing earlier steps
- Use a fresh session (new cookies, no prior state)
- Compare response to the original (same success indicators?)
- If the server returns success → **CONFIRMED step-skip vulnerability**

#### b) Value Manipulation Validation

```
Original flow: Set price=$100 → Confirm → Charge $100
Test: Set price=$100 → [Modify to $0.01] → Charge
Validate: Does the charge use the manipulated value?
```

- Identify mutable parameters from LLM analysis (prices, quantities, IDs, roles)
- Replay the chain with modified values at the identified step
- Check if the server accepts the modified value in subsequent steps
- Compare response to detect if manipulation was accepted

#### c) Replay/Repeat Validation

```
Original flow: Claim reward → [one-time]
Test: Claim reward → Claim reward → Claim reward
Validate: Does the action succeed multiple times?
```

- Replay the same request multiple times
- Check if the server allows repeated execution
- Detect if idempotency controls are missing

#### d) Race Condition Validation

```
Original flow: Check balance → Deduct
Test: [Check balance → Deduct] × N concurrent
Validate: Did total deductions exceed balance?
```

- Send multiple concurrent requests using parallel threads
- Configurable concurrency level (default: 5 parallel requests)
- Analyze responses for signs of race condition (multiple successes where only one should occur)

#### e) IDOR in Workflow Validation

```
Original flow: View own order #123 → Modify order #123
Test: View own order #123 → Modify order #456 (other user's)
Validate: Does modification of other user's resource succeed?
```

- Swap resource IDs in the chain with different IDs
- Check if the server allows access to other resources
- **Caution**: This test modifies data — require explicit user approval

### 2. Validation Engine (`ValidationEngine`)

```java
class ValidationEngine {
    // Run all applicable validations for a finding
    ValidationResult validate(ChainVerdict finding);
    
    // Run a specific test
    ValidationResult runTest(SuggestedTest test, RequestNode originalNode);
    
    // Replay a request with modifications
    HttpResponse replay(CapturedRequest original, Map<String, String> modifications);
    
    // Compare original and test responses
    ComparisonResult compare(HttpResponse original, HttpResponse test);
}

class ValidationResult {
    String testName;
    boolean confirmed;              // True if vulnerability confirmed
    double confidence;
    String evidence;                // What proved/disproved the vulnerability
    HttpResponse originalResponse;
    HttpResponse testResponse;
    String diff;                    // Key differences between responses
}
```

### 3. Request Replay Mechanism

- Use Burp's `HttpRequestResponse` API to send requests through Burp (respects upstream proxies, SSL, etc.)
- Modify specific parameters while preserving the rest of the request
- Support modifications to: query params, body params, JSON fields, headers, cookies, URL path segments
- Handle redirects appropriately (follow or don't follow based on test type)
- Timeout handling for replay requests

### 4. Response Comparison

Smart comparison that understands what "success" vs "failure" looks like:

- HTTP status code comparison (200 vs 403/401/400)
- Response body keyword detection (success indicators: "success", "confirmed", "approved", "completed")
- Response body keyword detection (failure indicators: "error", "denied", "unauthorized", "invalid")
- JSON response field comparison (specific fields that indicate outcome)
- Response size comparison (similar size = similar outcome)
- Set-Cookie presence (new session tokens = state change occurred)

### 5. Safety Controls

- **Dry-run mode**: Show what would be tested without actually sending requests
- **User approval required** for destructive tests (modifications, deletions)
- **Rate limiting**: Don't flood the target (configurable delay between replay requests)
- **Scope enforcement**: Only replay to in-scope targets
- **Rollback awareness**: Log all modifications so user can manually revert if needed

### 6. Validation Reporting

Each validation produces a detailed report:

```
Test: Skip Step 2 (direct access to /api/confirm)
Status: CONFIRMED ✓
Evidence: 
  - Original: POST /api/confirm with valid step2_token → 200 OK
  - Test: POST /api/confirm without step2_token → 200 OK (SHOULD HAVE BEEN 403)
  - Response bodies are 95% similar
  - Server did not validate prerequisite step completion
Confidence: 0.95
```

## Acceptance Criteria

- [ ] Step-skip validation: replays final step without prerequisites
- [ ] Value manipulation validation: modifies parameters between steps
- [ ] Replay/repeat validation: sends same request multiple times
- [ ] Race condition validation: concurrent parallel requests
- [ ] IDOR validation: swaps resource IDs (with user approval)
- [ ] Request replay uses Burp's HTTP API (respects proxy settings, SSL)
- [ ] Smart response comparison (status codes, keywords, body similarity)
- [ ] Dry-run mode shows planned tests without executing
- [ ] Safety controls: rate limiting, scope enforcement, user approval for destructive tests
- [ ] Detailed validation reports with evidence
- [ ] All replay requests and responses logged
- [ ] Validation results feed back into advisory layer

## Technical Notes

- Use `api.http().sendRequest()` from Montoya API for replaying requests
- For race conditions, use `ExecutorService` with `CountDownLatch` for synchronized parallel sends
- Response similarity: consider using Levenshtein distance or Jaccard similarity on response bodies
- Be careful with IDOR tests — they can modify real data. Always require user confirmation.
- Consider a "validation profile" concept: conservative (only safe tests) vs aggressive (all tests)




---



# Phase 8: Burp advisory layer, HTML detail builder, severity mapper, remediation templates


## Overview

Implement the advisory layer that reports confirmed (and high-confidence unconfirmed) vulnerabilities as **Burp Suite scanner issues**. This integrates findings directly into Burp's native issue listing, making them visible alongside Burp's own scanner findings.

Full use of the Burp API for issue reporting and user interaction.

## Requirements

### 1. Custom Scanner Issue Creation

Use Burp's `ScanCheck` or `AuditIssue` API to create custom issues:

```java
class WorkflowVulnerabilityIssue implements AuditIssue {
    String name();              // e.g., "Workflow Step Skipping: Payment Bypass"
    String detail();            // Full HTML-formatted finding detail
    String remediation();       // Remediation guidance
    AuditIssueSeverity severity();     // HIGH, MEDIUM, LOW, INFO
    AuditIssueConfidence confidence(); // CERTAIN, FIRM, TENTATIVE
    String baseUrl();
    List<HttpRequestResponse> requestResponses();  // Evidence requests
}
```

### 2. Issue Detail Formatting

Each issue should contain rich, actionable detail in HTML format:

```html
<h3>Workflow Vulnerability: Step Skipping</h3>

<h4>Summary</h4>
<p>The payment confirmation endpoint (/api/confirm-payment) can be accessed 
directly without completing the prerequisite cart validation step (/api/validate-cart). 
This allows an attacker to bypass price validation.</p>

<h4>Workflow Chain</h4>
<ol>
  <li>GET /api/cart → 200 (cart contents)</li>
  <li>POST /api/validate-cart → 200 (price validated) ← <b>SKIPPABLE</b></li>
  <li>POST /api/confirm-payment → 200 (payment processed)</li>
</ol>

<h4>Attack Scenario</h4>
<p>1. Add items to cart normally<br>
2. Skip the validate-cart step entirely<br>
3. Send confirm-payment directly with modified total<br>
4. Payment processes with attacker-controlled amount</p>

<h4>LLM Analysis</h4>
<p><i>Reasoning from the AI analysis...</i></p>

<h4>Validation Results</h4>
<p>✓ CONFIRMED: Direct access to step 3 without step 2 returned 200 OK<br>
Original response and test response are 95% similar</p>

<h4>Affected Parameters</h4>
<ul>
  <li>order_total (manipulable between steps)</li>
  <li>cart_token (not re-validated at payment step)</li>
</ul>

<h4>Remediation</h4>
<p>Implement server-side state validation at each step. The payment endpoint 
should verify that cart validation was completed in the current session and 
re-validate the order total server-side.</p>
```

### 3. Severity & Confidence Mapping

| Vulnerability Type | Validated | Severity | Confidence |
|--------------------|-----------|----------|------------|
| Step skipping (financial) | Yes | HIGH | CERTAIN |
| Step skipping (financial) | No | HIGH | TENTATIVE |
| Value manipulation (price) | Yes | HIGH | CERTAIN |
| Value manipulation (non-financial) | Yes | MEDIUM | FIRM |
| Race condition | Yes | HIGH | FIRM |
| Race condition | No | MEDIUM | TENTATIVE |
| Replay/repeat abuse | Yes | MEDIUM | CERTAIN |
| IDOR in workflow | Yes | HIGH | CERTAIN |
| Missing rate limit | Yes | LOW | FIRM |
| State confusion | Yes | MEDIUM | FIRM |
| Generic suspicious pattern | No | INFO | TENTATIVE |

### 4. Evidence Attachment

Each issue should include the relevant HTTP request/response pairs as evidence:

- Original workflow chain requests (in order)
- Validation replay requests and responses
- Highlighted differences between original and test responses
- The LLM's full reasoning (as a comment/detail section)

### 5. Issue Deduplication

- Don't create duplicate issues for the same vulnerability
- Fingerprint: vulnerability_type + affected_endpoint + affected_parameters
- If a duplicate is detected, update the existing issue with new evidence
- Log deduplication events

### 6. Issue Lifecycle

- Issues created as "open" by default
- If re-analysis shows the vulnerability is fixed → update issue status
- Track issue creation time, last validation time
- Support manual dismissal (user marks as false positive)

### 7. Context Annotation

As specified in the blueprint: "Each request adds context about its analysis for the next node"

- Each advisory should reference related advisories in the same workflow
- Cross-reference: "This finding is related to \[other issue\] in the same workflow chain"

## Acceptance Criteria

- [ ] Custom scanner issues created via Burp's AuditIssue API
- [ ] Rich HTML-formatted issue details with all sections
- [ ] Correct severity and confidence mapping based on type and validation status
- [ ] HTTP request/response evidence attached to each issue
- [ ] Issue deduplication prevents duplicate findings
- [ ] LLM reasoning included in issue detail
- [ ] Validation results clearly presented (confirmed vs unconfirmed)
- [ ] Remediation guidance included for each vulnerability type
- [ ] Issues visible in Burp's Scanner/Issues tab
- [ ] Cross-references between related issues in the same workflow
- [ ] All advisory creation events logged

## Technical Notes

- Use Montoya API's `api.siteMap().add()` with custom `AuditIssue` implementations
- HTML formatting in issue details — Burp renders HTML in the issue detail pane
- Keep evidence request/response pairs — Burp displays these in the issue's HTTP tab
- Consider creating a template system for issue detail generation (one template per vuln type)
- Remediation text should be specific to the vulnerability type, not generic



---



# Phase 9: Settings panel UI (LLM config, scope, backfill, analysis controls)




## Overview

Implement the Settings UI panel as a Burp Suite tab. This is the user's primary configuration interface for the extension — LLM connection, scope filters, backfill controls, and graph data directory.

## Requirements

### 1. Tab Registration

- Register a new tab in Burp Suite: "Workflow Scanner" (or similar)
- The tab contains sub-panels: **Settings**, **Log**, **Graph** (Log and Graph are separate issues)
- Use Swing (Burp's UI framework) for all components

### 2. Settings Panel Layout

```
┌─────────────────────────────────────────────────────┐
│  WORKFLOW VULNERABILITY SCANNER - SETTINGS           │
├─────────────────────────────────────────────────────┤
│                                                      │
│  ── LLM Configuration ──────────────────────────     │
│  Base URL:    [https://api.openai.com/v1        ]    │
│  Model ID:    [gpt-4                            ]    │
│  API Key:     [••••••••••••••••••••              ]    │
│  [Test Connection]  ✓ Connected (gpt-4, 128k ctx)    │
│                                                      │
│  ── Graph Data Directory ───────────────────────     │
│  Path:        [/home/user/.workflow-scanner      ]    │
│  [Browse...]  [Clear Graph Data]                     │
│  Status: 1,247 nodes, 3,891 edges loaded             │
│                                                      │
│  ── Backfill Settings ──────────────────────────     │
│  Limit:       [500     ] requests                    │
│  Scope:       [○ All history  ● In-scope only]       │
│  [Start Backfill]  Progress: Idle                    │
│                                                      │
│  ── Scope Filter ───────────────────────────────     │
│  ┌──────────────────────────────────────────┐        │
│  │ *.example.com                             │        │
│  │ *.example.*                               │        │
│  │ api.target.io                             │        │
│  └──────────────────────────────────────────┘        │
│  [Add Pattern] [Remove Selected] [Clear All]         │
│  Matching: 847 of 1,247 captured requests            │
│                                                      │
│  ── Analysis Controls ──────────────────────────     │
│  Concurrency:  [1  ▼] concurrent chains              │
│  Auto-analyze: [☑] Analyze new chains automatically  │
│  Validation:   [○ Conservative  ● Standard  ○ Aggressive] │
│  [Start Analysis] [Pause] [Stop]                     │
│  Status: Analyzing chain 3/15, node 4/7              │
│                                                      │
│  [Save Settings] [Reset to Defaults]                 │
└─────────────────────────────────────────────────────┘
```

### 3. LLM Configuration Section

- **Base URL**: Text field, default `https://api.openai.com/v1`
- **Model ID**: Text field, default `gpt-4`
- **API Key**: Password field (masked input), with show/hide toggle
- **Test Connection**: Button that calls the LLM client's test endpoint
  - On success: show green checkmark + model info
  - On failure: show red X + error message
- All values persisted via `ExtensionConfig`

### 4. Graph Data Directory Section

- **Path**: Text field + Browse button (file chooser dialog)
- **Clear Graph Data**: Button with confirmation dialog ("Are you sure? This deletes all graph data.")
- **Status**: Live display of current graph stats (node count, edge count)

### 5. Backfill Settings Section

- **Limit**: Numeric spinner (min 1, max 10000, default 500)
- **Scope**: Radio buttons — "All history" or "In-scope only"
- **Start Backfill**: Button that triggers backfill process
  - Disabled while backfill is running
  - Progress bar or text showing "Backfilled 150/500 requests"
  - Cancel button appears during backfill

### 6. Scope Filter Section

- **Pattern list**: Multi-line text area or list component
- One pattern per line
- Support glob patterns: `*.example.com`, `api.*`, `*.example.*`
- **Add/Remove/Clear** buttons
- **Matching count**: Live display of how many captured requests match current filters

### 7. Analysis Controls Section

- **Concurrency**: Dropdown (1-5 concurrent chain analyses)
- **Auto-analyze**: Checkbox — automatically analyze new chains as they're built
- **Validation profile**: Radio buttons — Conservative / Standard / Aggressive
- **Start/Pause/Stop**: Analysis control buttons
- **Status**: Live progress display

### 8. Persistence

- All settings saved when "Save Settings" is clicked
- Also auto-save on extension unload
- Load saved settings on extension startup
- "Reset to Defaults" restores factory settings with confirmation

## Acceptance Criteria

- [ ] Settings tab appears in Burp Suite UI
- [ ] All configuration fields functional and editable
- [ ] Test Connection validates LLM credentials with visual feedback
- [ ] Browse button opens file chooser for graph directory
- [ ] Backfill controls trigger backfill with progress display
- [ ] Scope filter patterns editable with add/remove/clear
- [ ] Analysis controls (start/pause/stop) functional
- [ ] Settings persist across extension reload
- [ ] Reset to defaults works with confirmation dialog
- [ ] UI is responsive — no freezing during operations
- [ ] All setting changes logged

## Technical Notes

- Use Java Swing — Burp Suite's UI is Swing-based
- Use `GridBagLayout` or `MigLayout` for clean panel layout
- All long-running operations (test connection, backfill) must run on background threads with `SwingUtilities.invokeLater()` for UI updates
- Consider using Burp's persistence API (`api.persistence()`) for settings storage
- Password field for API key — use `JPasswordField`




---



# Phase 10: Log panel UI (real-time filtering, search, export, color-coded)



## Overview

Implement the Log Panel UI — a real-time, filterable, searchable log viewer that displays everything the extension does. This is the user's window into the extension's internals: every LLM call, every graph operation, every analysis step.

## Requirements

### 1. Log Panel Layout

```
┌─────────────────────────────────────────────────────────────┐
│  LOG PANEL                                                   │
├─────────────────────────────────────────────────────────────┤
│  Filters: [☑ LLM] [☑ GRAPH] [☑ ANALYSIS] [☑ BACKFILL]     │
│           [☑ ADVISORY] [☑ CONFIG] [☑ ERROR] [☑ EXTENSION]  │
│  Level:   [○ ALL  ● INFO+  ○ WARN+  ○ ERROR]               │
│  Search:  [________________________] [🔍]                    │
│  [Auto-scroll ☑] [Clear] [Export...]                        │
├─────────────────────────────────────────────────────────────┤
│  14:32:01.123 [LLM_REQ]  [INFO] Sending node #178...       │
│  14:32:01.124 [LLM_REQ]  [DEBUG] Request body: {"model"... │
│  14:32:03.456 [LLM_RES]  [INFO] Received analysis for #178 │
│  14:32:03.457 [ANALYSIS] [INFO] Verdict: SUSPICIOUS (0.72) │
│  14:32:03.458 [GRAPH]    [INFO] Context updated for chain 5│
│  14:32:04.001 [LLM_REQ]  [INFO] Sending node #179...       │
│  14:32:06.789 [LLM_RES]  [INFO] Received analysis for #179 │
│  14:32:06.790 [ANALYSIS] [WARN] VULNERABLE: step_skipping  │
│  14:32:06.791 [ADVISORY] [INFO] Created issue: Step Skip...│
│  ▼ (auto-scrolling)                                         │
├─────────────────────────────────────────────────────────────┤
│  ── Detail View ────────────────────────────────────────     │
│  Selected: [14:32:01.124] LLM_REQUEST                       │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ {"model": "gpt-4", "messages": [                    │    │
│  │   {"role": "system", "content": "You are a..."},    │    │
│  │   {"role": "user", "content": "## Graph Node #178   │    │
│  │     ### Current Request\n Method: POST\n URL: ..."}  │    │
│  │ ], "temperature": 0.2}                              │    │
│  └─────────────────────────────────────────────────────┘    │
│  [Copy to Clipboard] [Open in Editor]                       │
└─────────────────────────────────────────────────────────────┘
```

### 2. Log List (Top Pane)

- Table/list view with columns: Timestamp, Category, Level, Message (truncated)
- Color-coded by level: DEBUG=gray, INFO=white, WARN=yellow, ERROR=red
- Color-coded category badges
- Click a row to show full detail in the bottom pane
- Virtual scrolling for performance (don't render 10,000+ rows at once)

### 3. Filtering

- **Category toggles**: Checkbox per category — show/hide log entries by type
- **Level filter**: Radio buttons — ALL, INFO+, WARN+, ERROR only
- **Text search**: Free-text search across message and detail content
- Filters apply in real-time (no "apply" button needed)
- Show filtered count: "Showing 234 of 1,847 entries"

### 4. Auto-Scroll

- Toggle for auto-scroll to bottom (new entries)
- When enabled, list automatically scrolls to show newest entries
- When user scrolls up manually, auto-scroll pauses
- Visual indicator when auto-scroll is paused and new entries exist

### 5. Detail View (Bottom Pane)

- Split pane: log list on top, detail on bottom
- Shows full content of selected log entry
- For LLM requests/responses: formatted JSON with syntax highlighting (or at minimum, proper indentation)
- For errors: full stack trace
- **Copy to Clipboard** button
- Resizable split

### 6. Export

- **Export** button opens save dialog
- Export formats: plain text, JSON
- Export options: all entries, filtered entries only, selected entries
- Include full detail content in export

### 7. Performance

- Handle 10,000+ log entries without UI lag
- Use virtual scrolling / lazy rendering
- Filtering should be responsive (\< 100ms for 10k entries)
- New entries added without full list re-render

## Acceptance Criteria

- [ ] Log panel displays real-time log entries from all categories
- [ ] Category filter toggles work correctly
- [ ] Level filter works correctly
- [ ] Text search filters entries in real-time
- [ ] Auto-scroll follows new entries
- [ ] Detail view shows full content of selected entry
- [ ] LLM request/response bodies displayed in full (no redaction)
- [ ] Color coding by level and category
- [ ] Export to file works (text and JSON formats)
- [ ] Copy to clipboard works for detail view
- [ ] Performance: smooth with 10,000+ entries
- [ ] Split pane resizable

## Technical Notes

- Use `JTable` with custom `TableModel` for the log list — supports virtual scrolling
- For large datasets, implement a `ListModel` backed by the ring buffer with filtering
- Color coding: custom `TableCellRenderer`
- Detail pane: `JTextArea` or `JEditorPane` (for basic formatting)
- Consider `SwingWorker` for export operations
- Connect to the logging subsystem's API (from issue #2) for data



---



# Phase 11: Graph panel UI (chain list, custom painted graph, node detail, Repeater)



## Overview

Implement a graph visualization panel that lets users see the request graph — nodes (endpoints), edges (relationships), and workflow chains. This provides visual insight into how the extension understands the application's workflow structure.

## Requirements

### 1. Graph Panel Layout

```
┌──────────────────────────────────────────────────────────────┐
│  GRAPH EXPLORER                                               │
├──────────────────────────────────────────────────────────────┤
│  Host Filter: [All hosts ▼]  Chains: [15 detected]           │
│  [Refresh] [Reset Layout] [Export Graph]                     │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  Chain List          │  Chain Detail / Graph View             │
│  ┌────────────────┐  │  ┌──────────────────────────────────┐ │
│  │ Chain 1 (7 nodes)│ │  │                                  │ │
│  │  ★ VULNERABLE   │  │  │  GET /          POST /signin     │ │
│  │ Chain 2 (4 nodes)│ │  │    │               │             │ │
│  │  ⚠ SUSPICIOUS   │  │  │    ▼               ▼             │ │
│  │ Chain 3 (12 nodes│ │  │  GET /signin → POST /signinForm  │ │
│  │  ○ Not analyzed │  │  │                    │             │ │
│  │ Chain 4 (3 nodes)│ │  │                    ▼             │ │
│  │  ✓ SAFE         │  │  │              GET /GeoIP          │ │
│  │ Chain 5 (5 nodes)│ │  │                    │             │ │
│  │  ○ Not analyzed │  │  │                    ▼             │ │
│  │                  │  │  │           POST /UserGeoIP       │ │
│  │                  │  │  │                    │             │ │
│  │                  │  │  │                    ▼             │ │
│  │                  │  │  │             GET /success         │ │
│  │                  │  │  │                                  │ │
│  └────────────────┘  │  └──────────────────────────────────┘ │
├──────────────────────┼───────────────────────────────────────┤
│  Node Detail (selected node)                                  │
│  ┌──────────────────────────────────────────────────────────┐│
│  │ Node #3: POST /signinForm                                 ││
│  │ Status: 302 → /GeoIP                                     ││
│  │ Edges: REDIRECT→#4 (1.0), REFERRER←#2 (0.9)             ││
│  │ Params: username, password, csrf_token                    ││
│  │ Analysis: SAFE (0.92) — "Standard login form..."          ││
│  │ [View Full Request] [View Full Response] [Analyze Node]   ││
│  └──────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────┘
```

### 2. Chain List (Left Panel)

- List all detected workflow chains
- Show: chain ID, node count, analysis status
- Status indicators:
  - ★ VULNERABLE (red) — confirmed vulnerability
  - :warning: SUSPICIOUS (yellow) — needs investigation
  - ✓ SAFE (green) — analyzed, no issues
  - ○ Not analyzed (gray) — pending analysis
- Sortable by: priority score, node count, status, timestamp
- Click to select and display in the graph view

### 3. Chain Graph View (Right Panel)

- Visual representation of the selected chain
- Nodes displayed as boxes with: method, path, status code
- Edges displayed as arrows with: edge type label, confidence
- Color-coded edges by type:
  - REDIRECT: blue
  - REFERRER: green
  - PARAM_REUSE: orange
  - RESPONSE_CORRELATION: purple
  - TIME_WINDOW: gray
  - USER_DEFINED: cyan
- Nodes color-coded by analysis verdict (red/yellow/green/gray)
- Click a node to show its detail in the bottom panel

### 4. Node Detail (Bottom Panel)

- Full detail of the selected node:
  - Method, URL, status code
  - All edges (incoming and outgoing) with types and confidence
  - Extracted parameters
  - Analysis verdict and reasoning (if analyzed)
- Action buttons:
  - **View Full Request**: Opens request in a dialog/popup
  - **View Full Response**: Opens response in a dialog/popup
  - **Analyze Node**: Trigger LLM analysis for this specific node
  - **Send to Repeater**: Send the request to Burp's Repeater tool

### 5. Graph Statistics

- Display at top: total nodes, total edges, total chains
- Host filter dropdown to focus on specific hosts
- Refresh button to reload graph data

### 6. Graph Layout

- Simple top-to-bottom or left-to-right flow layout for chains
- Nodes arranged chronologically
- For complex chains with branches, use a basic tree layout
- No need for a full force-directed graph — chains are mostly linear

## Acceptance Criteria

- [ ] Chain list displays all detected workflow chains with status
- [ ] Selecting a chain shows its graph visualization
- [ ] Nodes and edges rendered with correct colors and labels
- [ ] Node detail panel shows full information for selected node
- [ ] View Request/Response buttons show full raw data
- [ ] Analyze Node triggers LLM analysis for that node
- [ ] Send to Repeater works via Burp API
- [ ] Host filter narrows displayed chains
- [ ] Graph statistics displayed accurately
- [ ] UI handles large graphs (100+ chains) without lag
- [ ] Export graph data option

## Technical Notes

- For graph rendering, consider a simple custom `JPanel` with `paintComponent()` — no need for heavy graph libraries
- Alternatively, use a `JTree` for chain visualization (simpler, still effective)
- The chain list can be a `JList` with custom `ListCellRenderer`
- Split pane layout: left (chain list) | right-top (graph view) | right-bottom (node detail)
- Use `api.repeater().sendToRepeater()` for the Send to Repeater feature
- Keep the visualization simple and functional — this is a security tool, not a design showcase




---



# Phase 12: Event bus, config validator, health check, full pipeline wiring



## Overview

Wire all subsystems together into the complete end-to-end pipeline and harden the extension for real-world use. This is the integration issue — ensuring that data flows correctly from capture → graph → analysis → validation → advisory, and that the extension is robust under real conditions.

## Requirements

### 1. Full Pipeline Integration

Connect all layers in the correct order:

```
[Proxy/Backfill/Context Menu]
        │
        ▼
[Scope Filter]
        │
        ▼
[Request Pipeline Queue]
        │
        ▼
[Graph Builder] ──── [Graph Persistence]
        │
        ▼
[Chain Prioritizer]
        │
        ▼
[Analysis Engine] ◄── [LLM Client + Context Manager]
        │
        ▼
[Validation Engine]
        │
        ▼
[Advisory Layer] ──── [Burp Issue Listing]
        │
        ▼
[UI Updates] ──── [Log Panel, Graph Panel, Settings]
```

### 2. Event Bus / Notification System

Implement a simple event bus for inter-subsystem communication:

- `REQUEST_CAPTURED` → Graph Builder listens
- `GRAPH_UPDATED` → UI Graph Panel refreshes
- `CHAIN_DETECTED` → Analysis Engine queues (if auto-analyze enabled)
- `ANALYSIS_COMPLETE` → Validation Engine processes, UI updates
- `VALIDATION_COMPLETE` → Advisory Layer creates issues, UI updates
- `ISSUE_CREATED` → Log Panel logs, UI notification
- `CONFIG_CHANGED` → All subsystems reload configuration

### 3. Error Handling & Resilience

- **LLM failures**: Retry with backoff, then mark chain as "analysis failed" (don't crash)
- **Network errors**: Log and continue — don't stop processing other chains
- **Malformed responses**: Log the raw response, skip the node, continue chain
- **Out of memory**: Graph pruning when memory pressure detected
- **Thread pool exhaustion**: Bounded queues with rejection policies
- **Extension unload**: Graceful shutdown — save graph, flush logs, cancel in-progress analysis

### 4. Thread Safety Audit

Verify thread safety across all shared state:

- Graph data structure (concurrent reads from UI + writes from builder)
- Log ring buffer (concurrent writes from all threads + reads from UI)
- Configuration (reads from all threads + writes from settings UI)
- Analysis queue (writes from chain detector + reads from analysis engine)
- Context manager (writes from analysis + reads for prompt building)

### 5. Performance Testing

- Test with 1,000+ requests in proxy history (backfill performance)
- Test with 50+ concurrent proxy requests (live capture performance)
- Test with 100+ workflow chains (analysis queue management)
- Test with large LLM responses (parsing performance)
- Verify Burp UI remains responsive during all operations

### 6. End-to-End Test Scenarios

#### Scenario A: Basic Workflow Detection

1. Configure scope for a test application
2. Browse the application through Burp proxy (login → dashboard → action)
3. Verify graph builds correctly with redirect + referrer edges
4. Verify chain is detected and prioritized
5. Trigger analysis → verify LLM is called with correct context
6. Verify advisory created if vulnerability found

#### Scenario B: Backfill + Analysis

1. Load extension after proxy history already has 500+ requests
2. Trigger backfill with limit=200
3. Verify graph builds from historical data
4. Verify chains detected from backfill data
5. Trigger analysis on backfilled chains

#### Scenario C: Context Menu Workflow

1. Select 5 related requests in Proxy History
2. Right-click → "Send to Workflow Scanner"
3. Verify requests added to graph as a user-defined chain
4. Trigger analysis on the user-defined chain

#### Scenario D: Validation Confirmation

1. Analyze a chain with a known step-skip vulnerability
2. Verify LLM identifies the vulnerability
3. Verify validation engine replays the request
4. Verify advisory created with "CONFIRMED" status

### 7. Configuration Validation

- Validate LLM config before first analysis (test connection)
- Validate graph directory is writable
- Validate scope patterns are valid glob syntax
- Show clear error messages for invalid configuration

### 8. Startup & Shutdown Sequence

**Startup:**

1. Load configuration
2. Initialize logging
3. Load persisted graph (if exists)
4. Initialize LLM client (don't test connection yet — lazy)
5. Register HTTP handler
6. Register context menu
7. Initialize UI panels
8. Log "Extension loaded successfully"

**Shutdown:**

1. Cancel all in-progress analyses
2. Flush analysis queue
3. Save graph to disk
4. Flush log buffer to file
5. Release all thread pools
6. Log "Extension unloaded"

## Acceptance Criteria

- [ ] Full pipeline works end-to-end: capture → graph → analysis → validation → advisory
- [ ] Event bus connects all subsystems correctly
- [ ] Error handling prevents crashes — extension degrades gracefully
- [ ] Thread safety verified for all shared state
- [ ] Performance acceptable with 1,000+ requests
- [ ] Burp UI remains responsive during all operations
- [ ] All four test scenarios pass
- [ ] Configuration validation with clear error messages
- [ ] Clean startup and shutdown sequences
- [ ] No resource leaks (threads, file handles, memory)
- [ ] Extension can be unloaded and reloaded without issues

## Technical Notes

- Event bus: simple observer pattern with `CopyOnWriteArrayList` of listeners — no need for a framework
- Thread safety: prefer `ConcurrentHashMap`, `CopyOnWriteArrayList`, `AtomicReference` over synchronized blocks
- For the shutdown sequence, use `Runtime.addShutdownHook()` as a backup, but primarily rely on Burp's extension unload callback
- Consider a health check that periodically verifies all subsystems are running
- Integration testing is best done manually in Burp Suite with a vulnerable test application (e.g., DVWA, Juice Shop, or a custom test server)
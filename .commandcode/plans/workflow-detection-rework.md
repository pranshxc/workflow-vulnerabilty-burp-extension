# Workflow Detection Rework

## Problem

`RequestGraph.getWorkflowChains()` uses BFS connected components — not workflows. This
means static assets, telemetry, background polling, and SPA noise all merge into fake
"chains" that waste LLM calls and produce false positives. The LLM is not the bottleneck;
the detector is.

## Approach

Add a **traffic intent classifier** before graph insertion to drop noise, then replace
connected-component chain detection with a dedicated `WorkflowDetector` that segments by
session, uses edge strength tiers, normalizes endpoints, and scores candidates.

---

## New Files

### `classification/RequestIntent.java`
Enum: `BUSINESS_ACTION`, `BUSINESS_READ`, `AUTHENTICATION`, `WORKFLOW_STATE`,
`STATIC_ASSET`, `BACKGROUND_POLLING`, `TELEMETRY_ANALYTICS`, `THIRD_PARTY`,
`PREFLIGHT`, `HEALTHCHECK`, `UNKNOWN`

### `classification/RequestClassification.java`
POJO holding `RequestIntent`, `businessScore`, `noiseScore`, `workflowRelevant` boolean,
`reason`, `EndpointKey`.

### `classification/EndpointNormalizer.java`
Converts `/api/users/123` -> `/api/users/{int}`, `/api/orders/6f7a9d` -> `/api/orders/{hex}`,
`/api/files/{uuid}`. Uses regex patterns for path segment replacement.
Returns `EndpointKey(method, host, normalizedPath, queryParamNames)`.

### `classification/StaticNoiseRules.java`
Static sets of path extensions, domains, URL keywords for analytics/telemetry/health checks.
Provides `isStaticAsset()`, `isTelemetry()`, `isPreflight()`, `isHealthCheck()`, etc.

### `classification/BusinessKeywordRules.java`
Static sets of business path keywords (create, update, payment, checkout, etc.) and
parameter names (amount, price, role, user_id, etc.). Provides `score()`, `containsBusinessKeyword()`.

### `classification/RequestClassifier.java`
Main class. Deterministic rules (no LLM):
1. Check OPTIONS + CORS headers -> PREFLIGHT
2. Check static extensions -> STATIC_ASSET (but JS gets flagged, not fully dropped)
3. Check telemetry/analytics path keywords -> TELEMETRY_ANALYTICS
4. Check polling patterns (notifications, heartbeat, status, etc.) -> BACKGROUND_POLLING
5. Check auth path keywords -> AUTHENTICATION
6. Check business keywords + state-changing methods -> BUSINESS_ACTION / WORKFLOW_STATE
7. Fallback -> UNKNOWN (kept if suspicious/includes body, dropped if trivial GET with low entropy)

`classify(CapturedRequest) -> RequestClassification`

### `classification/EdgeStrength.java`
Enum: `STRONG` (redirect, user-defined, business-token flow), `MEDIUM` (referrer to business
endpoint, object-ID reuse), `WEAK` (same-host time proximity), `CONTEXT_ONLY` (telemetry,
polling, static dependency, session cookies).

### `classification/ValueKind.java`
Enum for parameter kind classification: `BUSINESS_ID`, `SECURITY_TOKEN`, `SESSION_TOKEN`,
`MONEY`, `EMAIL`, `USERNAME`, `STATUS`, `BOOLEANISH`, `STATIC_CONFIG`, `LOW_ENTROPY`, `UNKNOWN`.
Used by `ParameterExtractor.isInterestingCorrelationValue()`.

### `workflow/WorkflowType.java`
Enum: `AUTHENTICATION` (login/signin/mfa), `REGISTRATION` (signup/register),
`PASSWORD_RESET`, `CHECKOUT`, `PAYMENT`, `ORDER_MANAGEMENT`, `PROFILE_UPDATE`,
`ROLE_ADMIN`, `FILE_UPLOAD`, `INVITATION`, `APPROVAL`, `TRANSFER`,
`UNKNOWN_BUSINESS_FLOW`. Detected by `WorkflowDetector` based on path keywords and
endpoint patterns.

### `workflow/SessionKey.java`
Value object: `(host, authCookieHash, topLevelReferrerPath)`. Used for session segmentation
instead of graph connectivity. `authCookieHash` is SHA-256 of the session cookie values
(JSESSIONID/PHPSESSID/connect.sid/etc.), not individual business tokens.

### `workflow/WorkflowCandidate.java`
POJO: `id`, `SessionKey`, `WorkflowType type`, `List<RequestNode> steps`,
`List<RequestEdge> supportingEdges`, `double workflowScore`, `String startReason`,
`String endReason`, `WorkflowEvidence evidence`.

### `workflow/WorkflowEvidence.java`
POJO: `List<String> startSignals`, `List<String> continuationSignals`, `List<String> endSignals`,
`List<String> objectFlows`, `List<String> suppressedNoise`, `double confidence`.

### `workflow/WorkflowBoundaryDetector.java`
Static methods:
- `startsWorkflow(RequestNode) -> boolean` — looks for form pages, login, cart, checkout,
  settings pages, POST to start/create/submit endpoints
- `continuesWorkflow(RequestNode previous, RequestNode current) -> boolean` — checks
  same host, referrer chain, response-to-request object flow, method transition pattern
- `endsWorkflow(RequestNode) -> boolean` — looks for confirmation pages, 201 Created,
  303 redirect to result, order/dashboard terminal pages
- `isBoundaryReset(RequestNode previous, RequestNode current) -> boolean` — different host,
  time gap > 30s, logout, new top-level navigation, static-only sequence

### `workflow/WorkflowSessionizer.java`
Reads chronological workflow-relevant nodes (filtered by `RequestClassifier`), groups by
`SessionKey`. Builds candidates incrementally:

```
for node in chronologicalNodes:
    key = sessionKey(node)
    active = activeWorkflows.get(key)
    if active is null or boundaryDetector.startsNewWorkflow(active, node):
        active = new WorkflowCandidate(key)
        activeWorkflows.put(key, active)
    if classifier.isWorkflowRelevant(node):
        active.addStep(node)
    if boundaryDetector.endsWorkflow(node):
        emit(active)
        activeWorkflows.remove(key)
```

Uses idle timeout (30s gap without same-session requests) to close orphaned candidates.
Thread-safe via `ConcurrentHashMap`.

### `workflow/WorkflowScorer.java`
Scores `WorkflowCandidate` using weighted heuristics:

| Feature | Weight |
|---------|--------|
| POST/PUT/PATCH/DELETE count | +5 each |
| Business keyword hits | +3 each |
| Object-ID value-flow count | +6 each |
| Redirect-after-POST | +4 |
| Terminal confirmation | +5 |
| Money/role parameter | +8 |
| Method diversity | +2 per method |
| Static assets in chain | -10 each |
| Telemetry in chain | -10 each |
| Only TIME_WINDOW edges (no strong edges) | -15 |
| Repeated same endpoint | -2 each |

**Thresholds**: `score >= 20` → send to LLM. `10-19` → show as candidate only (no LLM).
`< 10` → suppress entirely.

### `workflow/WorkflowDetector.java`
Main orchestrator. Takes `RequestGraph`, runs:
1. Collect all nodes sorted chronologically
2. Filter to workflow-relevant nodes (pass to `WorkflowSessionizer`)
3. Detect `WorkflowType` from path patterns and parameter names
4. Build `WorkflowEvidence` (object flows, start/end signals)
5. Score via `WorkflowScorer`
6. Return sorted `List<WorkflowCandidate>`

This replaces `graph.getWorkflowChains()` in the analysis pipeline.

### `analysis/ApplicationModel.java`
Accumulated app-wide context built from all analyzed workflow candidates:
```java
class ApplicationModel {
    Set<EndpointKey> discoveredEndpoints;
    Map<String, ObjectType> objectIdParameters;  // "order_id" -> ORDER, "user_id" -> USER
    Map<String, Set<String>> roles;              // "path_pattern" -> ["admin", "user"]
    List<StateTransition> knownStateTransitions; // cart -> checkout -> payment
    List<AuthBoundary> authBoundaries;           // where auth state changes
}
```
Built incrementally as candidates are processed. Passed to LLM prompts for app-wide
understanding: "This candidate workflow appears to be CHECKOUT. Known objects: cart_id,
order_id, payment_intent. Known transitions: cart -> checkout -> payment -> confirmation."

### `ui/StatusBarPanel.java`
Small status bar shown at the bottom of the main UI tab. Displays live operational metrics:
- Pipeline queue depth / capacity
- Graph nodes / edges / candidates
- Suppressed noise count (by intent category)
- Analyzed workflows / findings count
- LLM errors / replay errors

Updates via a 5-second timer polling `HealthCheck.getMetrics()`. Adds a `getMetrics()`
method to `HealthCheck` that returns a `Map<String, String>` of current values.

---

## Modified Files

### `graph/RelationshipDetector.java`
- **TIME_WINDOW**: No longer creates graph edges. Only contributes to `RelationshipScore`
  as a context feature. If another meaningful signal exists, it boosts confidence by 0.1.
- **REFERRER**: Demoted to MEDIUM for business targets, WEAK for static/telemetry targets.
- **RESPONSE_CORRELATION (cookies)**: Session cookies (JSESSIONID, PHPSESSID, connect.sid,
  _auth, access_token, refresh_token, session) are excluded from edge creation. Only
  business state tokens (checkout_session_id, order_id, cart_id, payment_intent, etc.)
  produce RESPONSE_CORRELATION edges.
- **PARAM_REUSE**: Filtered through `ValueKind` classification. Only `BUSINESS_ID`,
  `SECURITY_TOKEN`, `MONEY` produce graph edges. Common values (en-US, dark, user, true,
  false, null, common enums, timestamps, static config values) are ignored via
  `isInterestingCorrelationValue()`.
- New method: `getEdgeStrength(EdgeType, RequestNode, RequestNode) -> EdgeStrength`
  for downstream edge-strength filtering.

### `graph/EdgeType.java`
No change to enum values.

### `graph/GraphBuilder.java`
- `processRequest()` now calls `RequestClassifier.classify()` first.
- If `!classification.isWorkflowRelevant()`, the request is **logged and dropped** with
  reason — no node created, no edges computed. Metrics counter incremented.
- If relevant, `RequestNode.setClassification()` is called before adding to graph.
- `CapturedRequest` now persisted in serialization so loaded nodes have raw data for
  replay/LLM context. Add `RequestBody`, `ResponseBody`, `RequestHeaders`,
  `ResponseHeaders`, `Cookies`, `StatusCode`, `MimeType` to `NodeData`.
- `NodeData` gains `classification` field (serialized enum + reason).
- After each node add, publishes `GRAPH_UPDATED` via injected `EventBus` or listener.

### `graph/RequestGraph.java`
- `getWorkflowChains()` kept for debugging/visualization but renamed to
  `getConnectedComponents()`.
- New method: `detectWorkflowCandidates(WorkflowDetector) -> List<WorkflowCandidate>`
  that delegates to the detector.

### `graph/RequestNode.java`
- New field: `RequestClassification classification` with getter/setter.
- New field: `EndpointKey endpointKey` with getter/setter.

### `graph/ParameterExtractor.java`
- `MIN_VALUE_LENGTH` stays 4. New method:
  `isInterestingCorrelationValue(String name, String value) -> boolean` — uses
  `ValueKind.classify(name, value)`. Returns true only for BUSINESS_ID, SECURITY_TOKEN,
  MONEY, WORKFLOW_STATE_TOKEN. False for session cookies, booleans, enums, static config,
  low-entropy values.
- `ValueKind.classify(String name, String value)` — checks parameter name patterns
  (`id`, `token`, `amount`, `price`, `session`, `role`) and value entropy/patterns
  (numeric, UUID, hex, short/common strings).
- Hidden field parsing: regex approach improved with more robust pattern matching.
  Not switching to JSoup — keeping zero external dependencies (only Gson + Montoya API).
  Instead, use two independent regex passes (separate name/value extraction per `<input>`
  block) to handle attribute reordering.
- URL parsing in `RequestConverter`: replace manual string manipulation with
  `java.net.URI` for proper host/path extraction.

### `data/CapturedRequest.java`
- `getDeduplicationKey()` changes from including timestamp to:
  `method + "|" + normalizedUrl + "|" + sha256(normalizedBody)`.
  This ensures the same request from backfill and live proxy is deduplicated.
- Add `getNormalizedUrl()` helper: strips query params and fragments, removes trailing
  slash, lowercases.

### `analysis/AnalysisEngine.java`
- `runAnalysisPipeline()` calls `graph.detectWorkflowCandidates(detector)` instead of
  `graph.getWorkflowChains()`.
- Chain analysis now gets whole `WorkflowCandidate` — not just raw node list.
- Scoring/prioritization logic moved to `WorkflowScorer`. `ChainPrioritizer` deprecated
  (kept for backward compat, unused).
- **3-prompt analysis structure** for each candidate (replaces node-by-node):
  1. **Prompt 1 — Classify**: Send entire candidate workflow, ask LLM to identify
     `WorkflowType`, business objects, state transitions, and threat model
     (The Skipper / The Repeater / etc.)
  2. **Prompt 2 — Hypotheses**: Based on classification, ask for specific testable
     hypotheses (e.g., "Step 3 can be accessed without Step 2", "Amount from Step 1
     not re-validated in Step 4")
  3. **Prompt 3 — Validation Plan**: Generate structured validation tests
     (method, URL, modifications, expected behavior)
- Optional node-level prompts only for deep-dive on specific suspicious nodes.
- Auto-analyze wiring: subscribe to `CHAIN_DETECTED` event; if
  `config.isAutoAnalyzeNewChains()` and candidate score >= threshold, submit to executor.
- `ApplicationModel` built incrementally as candidates complete analysis, passed into
  subsequent LLM prompts for context.

### `analysis/ChainPrioritizer.java`
Marked `@Deprecated`. No longer called by `AnalysisEngine`. Kept for potential manual
triggering from UI.

### `analysis/ChainVerdict.java`
- `generateFingerprint()` — remove `.sorted()`. Workflow order matters.
  Fingerprint: `method:path->method:path->method:path` in chronological order.
- Add `workflowType` (WorkflowType), `workflowScore` (double), `sessionKey` (SessionKey) fields.

### `analysis/HeuristicPreFilter.java`
No structural changes, but heuristic signals now include workflow-type context
("CHECKOUT workflow with tamperable price parameter") instead of generic signals.

### `llm/PromptBuilder.java`
Updated to support 3-prompt structure. New methods:
- `buildClassificationPrompt(WorkflowCandidate, ApplicationModel) -> String`
- `buildHypothesisPrompt(WorkflowCandidate, ApplicationModel, WorkflowType) -> String`
- `buildValidationPlanPrompt(WorkflowCandidate, hypotheses) -> String`
Each includes the candidate's full node data, evidence, and app-model context.

### `llm/LLMContextManager.java`
Now manages two context levels:
- **CandidateContext**: nodes in the current workflow candidate
- **ApplicationContext**: global `ApplicationModel` (endpoints, object types, state
  transitions, auth boundaries) accumulated across all analyzed candidates

### `validation/ValidationEngine.java`
- Step-skipping: Add `AUTHENTICATED_SKIP_PREVIOUS_STEPS` mode (preserves auth, removes
  workflow-state tokens) alongside existing `ANONYMOUS_DIRECT_ACCESS`.
- Value manipulation: Replace response-similarity confirmation with state-effect
  validation. After replay, send a follow-up request to fetch the object/status and
  compare before/after state.
- Add `ValidationProof` inner class: `requestAccepted`, `stateChanged`, `changedObjectId`,
  `beforeState`, `afterState`.
- `RequestReplayer.applyModification()` — add body-type-aware mutators:
  `JsonBodyMutator`, `FormBodyMutator`, `QueryParamMutator`. Return `MutationResult`
  with `applied`, `location`, `oldValue`, `newValue`, `reason`. If not applied, don't replay.

### `advisory/AdvisoryManager.java`
- `createFromVerdict()` now attaches evidence: `List<HttpRequestResponse>` with original
  chain requests + replay requests/responses. Fix the empty evidence list.

### `advisory/IssueDetailBuilder.java`
- Fix `esc()` method: replace `"&"` with `"&amp;"` (current code has just `"&"`).
  Full order: `&` -> `&amp;`, `<` -> `&lt;`, `>` -> `&gt;`, `"` -> `&quot;`.

### `EventBus.java`
No code changes — already has the right structure. Now actually wired:
- `GraphBuilder` publishes `GRAPH_UPDATED` after each node add
- `WorkflowDetector` publishes `CHAIN_DETECTED` when a candidate is emitted
- `AnalysisEngine` subscribes to `CHAIN_DETECTED`
- `SettingsPanel` publishes `CONFIG_CHANGED`
- Inject `EventBus` into `GraphBuilder` (via constructor parameter or setter).

### `WorkflowVulnScanner.java`
- Wire new pipeline in `initGraph()` / `startGraphBuilder()`:
  ```
  pipeline -> classifier -> graphBuilder -> workflowDetector -> analysisEngine
  ```
- Instantiate `RequestClassifier` after config init.
- Instantiate `WorkflowDetector` after graph, pass to `AnalysisEngine`.
- Wire `EventBus.CHAIN_DETECTED` to auto-analysis.
- Wire `EventBus.GRAPH_UPDATED` to UI GraphPanel refresh.
- Register `StatusBarPanel` in the main UI.

### `config/ExtensionConfig.java`
- Add fields: `workflowScoreThreshold` (int, default 20), `autoAnalyzeNewChains`
  (boolean, default false), `edgeStrengthMode` (String, default "tiered").
  Persisted via existing Gson serialization.

### `HealthCheck.java`
- Add `getMetrics() -> Map<String, String>` returning:
  - `pipeline_depth`, `pipeline_capacity`, `graph_nodes`, `graph_edges`,
    `workflow_candidates`, `analyzed_chains`, `findings_count`,
    `suppressed_total`, `suppressed_by_type` (JSON), `llm_errors`, `replay_errors`

### `ui/MainTabPanel.java`
- Add `StatusBarPanel` at the bottom of the main panel. Shows metrics from
  `HealthCheck.getMetrics()` updated every 5 seconds via timer.

---

## Pipeline (After)

```
[Proxy/Backfill/ContextMenu]
  -> RequestPipeline
  -> RequestClassifier.classify() — drops noise, tags intents
  -> GraphBuilder.processRequest() — only workflow-relevant nodes
  -> RelationshipDetector.detectRelationships() — tiered edge strengths
  -> WorkflowDetector.detect() — session segmentation + boundary detection
  -> WorkflowScorer.score() — >=20 analyzed, 10-19 candidate, <10 suppressed
  -> AnalysisEngine (3-prompt: classify -> hypothesize -> validate)
     with ApplicationModel context
  -> ValidationEngine — state-effect validation with follow-up fetches
  -> AdvisoryManager — evidence-backed issues with raw requests
```

## Verification

1. `./gradlew build` — must compile with no errors
2. Manual test with Burp: browse a target with SPAs, verify static assets, telemetry, and
   background polling are suppressed in graph stats and logs. Verify suppressed count
   visible in status bar.
3. Manual test: backfill proxy history with 500+ requests, verify chain count drops
   significantly (no more garbage chains from time-window connections).
4. Manual test: context menu 5 related requests, verify they become a single
   `USER_DEFINED` workflow candidate with score >= 20.
5. Manual test: trigger analysis, verify LLM receives 3-prompt sequence (classify,
   hypothesize, validate) with full workflow context, not node-by-node with garbage
   neighbors.
6. Log panel: verify `[CLASSIFIER]` log category shows suppressed requests with reason.
7. Manual test: validate a step-skipping finding, verify `AUTHENTICATED_SKIP_PREVIOUS_STEPS`
   mode is used (preserves auth, strips workflow tokens) and follow-up state check is
   performed.

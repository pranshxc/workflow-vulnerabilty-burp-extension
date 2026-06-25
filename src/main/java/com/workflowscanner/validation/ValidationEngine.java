package com.workflowscanner.validation;

import burp.api.montoya.MontoyaApi;

import com.workflowscanner.analysis.ChainVerdict;
import com.workflowscanner.config.ExtensionConfig;
import com.workflowscanner.data.ScopeFilter;
import com.workflowscanner.graph.RequestNode;
import com.workflowscanner.llm.LLMAnalysisResult;
import com.workflowscanner.llm.SuggestedTest;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;
import com.workflowscanner.store.RequestHydrator;
import com.workflowscanner.store.RequestStore;
import com.workflowscanner.workflow.WorkflowDetector;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Validates LLM-identified vulnerabilities by replaying requests with mutations.
 * Separates this tool from a theoretical scanner by proving findings are real.
 *
 * Validation strategies:
 * a) Step skipping - replay final step without prerequisites
 * b) Value manipulation - modify parameters between steps
 * c) Replay/repeat - send same request multiple times
 * d) Race condition - concurrent parallel requests
 * e) IDOR - swap resource IDs (requires user approval)
 *
 * Safety controls:
 * - Dry-run mode, rate limiting, scope enforcement
 * - User approval for destructive tests
 * - Comprehensive logging of all replays
 */
public class ValidationEngine {

    private final MontoyaApi api;
    private final ExtensionConfig config;
    private final ExtensionLogger logger;
    private final RequestReplayer replayer;
    private final ScopeFilter scopeFilter;
    // Optional sink for live status counters. When set, every
    // validate() call publishes the latest strict / probable counts
    // so the status panel can show "findings: 3 confirmed / 7 probable"
    // without re-scanning all results.
    private volatile WorkflowDetector metricsSink;

    private final AtomicBoolean dryRunMode = new AtomicBoolean(false);
    private final AtomicBoolean allowDestructiveTests = new AtomicBoolean(false);
    private int replayDelayMs = 500; // Rate limiting between replays

    private final List<ValidationResult> allResults = new CopyOnWriteArrayList<>();

    // Disk-backed request store for raw HTTP re-hydration.
    private volatile RequestStore requestStore;

    public ValidationEngine(MontoyaApi api, ExtensionConfig config, ExtensionLogger logger) {
        this.api = api;
        this.config = config;
        this.logger = logger;
        this.replayer = new RequestReplayer(api, logger);
        this.scopeFilter = new ScopeFilter(config);

        // Set validation profile
        String profile = config.getValidationProfile();
        if ("conservative".equals(profile)) {
            this.replayDelayMs = 1000;
            this.allowDestructiveTests.set(false);
        } else if ("aggressive".equals(profile)) {
            this.replayDelayMs = 200;
            this.allowDestructiveTests.set(true);
        }
    }

    /**
     * Set the disk-backed request store so the validator can
     * re-hydrate raw HTTP for nodes whose payload has been
     * dropped from the hot in-memory graph. The replayer is
     * also wired so its {@code replay} and {@code fetchGet}
     * paths can hydrate the same way.
     */
    public void setRequestStore(RequestStore store) {
        this.requestStore = store;
        this.replayer.setRequestStore(store);
    }

    /**
     * Validate all findings in a chain verdict.
     * Returns a list of validation results.
     */
    public List<ValidationResult> validate(ChainVerdict verdict) {
        if (verdict == null || verdict.getChain() == null) return Collections.emptyList();

        List<ValidationResult> results = new ArrayList<>();
        List<RequestNode> chain = verdict.getChain();

        logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "ValidationEngine",
                "Starting validation for chain " + verdict.getChainId()
                        + " (" + verdict.getOverallVerdict() + ")");

        // Re-hydrate raw HTTP for every node in the chain so the
        // various validation strategies (state-effect, IDOR, race
        // detection) have bodies and headers to compare. Without
        // this, validation against backfilled candidates would
        // miss every signal because the hot graph had dropped
        // the raw payload.
        if (requestStore != null) {
            for (RequestNode n : chain) {
                if (n != null) RequestHydrator.ensureHydrated(n, requestStore);
            }
        }
        String vulnType = verdict.getVulnerabilityType();

        if (vulnType != null) {
            switch (vulnType) {
                case "step_skipping":
                    results.addAll(validateStepSkipping(chain));
                    // Also check state effects
                    results.addAll(validateStateEffects(chain));
                    break;
                case "value_manipulation":
                    results.addAll(validateValueManipulation(chain, verdict));
                    results.addAll(validateStateEffects(chain));
                    break;
                case "replay_attack":
                    results.addAll(validateReplay(chain));
                    break;
                case "race_condition":
                    results.addAll(validateRaceCondition(chain));
                    break;
                case "idor_in_workflow":
                    results.addAll(validateIDOR(chain, verdict));
                    break;
                default:
                    // Run suggested tests from LLM
                    results.addAll(runSuggestedTests(verdict));
                    break;
            }
        }

        // Always run LLM-suggested tests if available
        if (verdict.getSuggestedTests() != null && !verdict.getSuggestedTests().isEmpty()) {
            results.addAll(runSuggestedTests(verdict));
        }

        allResults.addAll(results);

        int confirmed = (int) results.stream().filter(ValidationResult::isConfirmed).count();
        logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "ValidationEngine",
                "Validation complete for chain " + verdict.getChainId()
                        + ": " + results.size() + " tests, " + confirmed + " confirmed.");

        // Publish live confirmed/probable counts to the metrics sink
        // so the status panel can show them without re-scanning.
        if (metricsSink != null) {
            metricsSink.setLiveValidationCounts(
                    getStrictConfirmedCount(),
                    (int) allResults.stream()
                            .filter(ValidationResult::isConfirmed)
                            .count() - getStrictConfirmedCount());
        }

        return results;
    }

    // ========================================================================
    // a) Step Skipping Validation (auth-preserving skip mode)
    // ========================================================================

    private List<ValidationResult> validateStepSkipping(List<RequestNode> chain) {
        List<ValidationResult> results = new ArrayList<>();
        if (chain.size() < 2) return results;

        // Replay the final step without completing earlier steps.
        // Uses auth-preserving skip mode: keeps session/auth cookies,
        // strips only workflow-state tokens (CSRF, nonce, etc.).
        RequestNode finalNode = chain.get(chain.size() - 1);

        if (!isInScope(finalNode)) return results;

        ValidationResult result = new ValidationResult(
                "Skip to final step: " + finalNode.getMethod() + " " + finalNode.getPath(),
                ValidationResult.Strategy.STEP_SKIP);

        if (dryRunMode.get()) {
            result.setDryRun(true);
            result.setEvidence("[DRY RUN] Would replay " + finalNode.getMethod()
                    + " " + finalNode.getUrl() + " with auth-preserving skip mode");
            results.add(result);
            return results;
        }

        long start = System.currentTimeMillis();
        RequestReplayer.ReplayResponse response = replayer.replay(finalNode, null, true);
        result.setDurationMs(System.currentTimeMillis() - start);

        if (response != null) {
            result.setOriginalStatusCode(finalNode.getStatusCode());
            result.setTestStatusCode(response.statusCode);

            String origBody = finalNode.getRequest() != null
                    ? finalNode.getRequest().getResponseBody() : "";
            ResponseComparator.ComparisonResult comparison =
                    ResponseComparator.compare(finalNode.getStatusCode(), origBody,
                            response.statusCode, response.body);

            result.setResponseSimilarity(comparison.bodySimilarity);
            applyProofLevel(result, comparison,
                    "Step-skip test (auth-preserving): replayed final step without prerequisites.\n",
                    "\nServer accepted request without prerequisites!",
                    "\nServer correctly rejected the request.");
        } else {
            result.setProofLevel(ValidationResult.ProofLevel.ERROR);
            result.setConfidence(0.1);
            result.setEvidence("Replay failed - no response received.");
        }

        results.add(result);
        rateLimitDelay();
        return results;
    }

    // ========================================================================
    // f) State Effect Validation
    //    After replaying a mutated/replayed request, send a follow-up GET to
    //    the referrer or the previous step's URL to detect state changes.
    //    The baseline is fetched FRESH just before the replay, not taken
    //    from the captured original response — using a stale baseline
    //    would cause false positives when the app state has drifted.
    // ========================================================================

    private List<ValidationResult> validateStateEffects(List<RequestNode> chain) {
        List<ValidationResult> results = new ArrayList<>();
        if (chain.size() < 2) return results;

        // For each step that's a POST/PUT/DELETE, replay it and then
        // follow up with a GET to the referrer (if available) or previous URL.
        for (int i = 1; i < chain.size(); i++) {
            RequestNode targetNode = chain.get(i);
            String method = targetNode.getMethod() != null ? targetNode.getMethod().toUpperCase() : "GET";
            if (!"POST".equals(method) && !"PUT".equals(method) && !"DELETE".equals(method)) continue;
            if (!isInScope(targetNode)) continue;

            // Find the follow-up URL from referrer or previous step's path
            String followUpUrl = null;
            if (targetNode.getRequest() != null && targetNode.getRequest().getReferrer() != null) {
                followUpUrl = targetNode.getRequest().getReferrer();
            } else if (chain.get(i - 1) != null && chain.get(i - 1).getUrl() != null) {
                followUpUrl = chain.get(i - 1).getUrl();
            }

            if (followUpUrl == null) continue;

            ValidationResult result = new ValidationResult(
                    "State effect: " + targetNode.getMethod() + " " + targetNode.getPath()
                            + " -> GET " + followUpUrl,
                    ValidationResult.Strategy.STATE_EFFECT);

            if (dryRunMode.get()) {
                result.setDryRun(true);
                result.setEvidence("[DRY RUN] Would replay " + targetNode.getMethod()
                        + " " + targetNode.getUrl() + " then fetch " + followUpUrl
                        + " to detect state changes");
                results.add(result);
                continue;
            }

            long start = System.currentTimeMillis();

            // Phase 1: Fresh "before" baseline. We fetch the follow-up URL
            // *now* rather than reusing the captured response, because the
            // app state may have changed since capture. The target node
            // provides auth/tenant/Accept headers so the GET is
            // authenticated and tenant-scoped like a normal in-app
            // navigation.
            RequestReplayer.ReplayResponse beforeResponse = replayer.fetchGet(followUpUrl, targetNode);
            if (beforeResponse == null) {
                result.setProofLevel(ValidationResult.ProofLevel.ERROR);
                result.setEvidence("State effect test failed: could not fetch fresh-before "
                        + followUpUrl);
                result.setDurationMs(System.currentTimeMillis() - start);
                results.add(result);
                rateLimitDelay();
                continue;
            }

            // Phase 2: Replay the state-changing request.
            RequestReplayer.ReplayResponse changeResponse = replayer.replay(
                    targetNode, null, false);

            if (changeResponse == null) {
                result.setProofLevel(ValidationResult.ProofLevel.ERROR);
                result.setEvidence("State effect test failed: no response from replay.");
                result.setDurationMs(System.currentTimeMillis() - start);
                results.add(result);
                rateLimitDelay();
                continue;
            }

            // Phase 3: Fresh "after" snapshot, taken from the same URL.
            RequestReplayer.ReplayResponse afterResponse = replayer.fetchGet(followUpUrl, targetNode);

            result.setDurationMs(System.currentTimeMillis() - start);

            if (afterResponse != null) {
                // Diff fresh before vs fresh after. This is the meaningful
                // comparison; the original captured response is no longer
                // used as a baseline.
                StateCheck check = StateEffectExtractor.diff(
                        followUpUrl,
                        beforeResponse.statusCode, beforeResponse.body,
                        afterResponse.statusCode, afterResponse.body);
                result.addStateCheck(check);

                result.setOriginalStatusCode(beforeResponse.statusCode);
                result.setTestStatusCode(afterResponse.statusCode);
                result.setResponseSimilarity(check.statusChanged() ? 0.0 :
                        ResponseComparator.computeJaccardSimilarity(
                                beforeResponse.body, afterResponse.body));

                switch (result.getProofLevel()) {
                    case CONFIRMED:
                        result.setConfidence(0.9);
                        break;
                    case PROBABLE:
                        result.setConfidence(0.5);
                        break;
                    default:
                        result.setConfidence(0.2);
                }
                result.setEvidence("State effect test (fresh before/after):\n"
                        + "  Replayed " + targetNode.getMethod() + " " + targetNode.getPath()
                        + " (status " + changeResponse.statusCode + ")\n"
                        + "  Follow-up GET " + followUpUrl
                        + ": " + beforeResponse.statusCode + " -> " + afterResponse.statusCode
                        + "\n  " + check.summarize()
                        + (result.getProofLevel() == ValidationResult.ProofLevel.CONFIRMED
                                ? "\nBusiness effect confirmed."
                                : (result.getProofLevel() == ValidationResult.ProofLevel.PROBABLE
                                        ? "\nMarker-only evidence; needs human review."
                                        : "\nNo concrete business effect observed.")));
            } else {
                result.setProofLevel(ValidationResult.ProofLevel.ERROR);
                result.setEvidence("State effect test: replayed successfully but fresh-after GET failed.");
            }

            results.add(result);
            rateLimitDelay();
        }
        return results;
    }

    // ========================================================================
    // b) Value Manipulation Validation
    // ========================================================================

    private List<ValidationResult> validateValueManipulation(List<RequestNode> chain,
                                                              ChainVerdict verdict) {
        List<ValidationResult> results = new ArrayList<>();

        // Find nodes with tamperable parameters from LLM results
        for (int i = 0; i < chain.size() && i < verdict.getNodeResults().size(); i++) {
            RequestNode node = chain.get(i);
            LLMAnalysisResult nodeResult = verdict.getNodeResults().get(i);
            if (nodeResult == null || nodeResult.getAffectedParameters() == null) continue;
            if (!isInScope(node)) continue;

            for (String param : nodeResult.getAffectedParameters()) {
                Map<String, String> mods = new HashMap<>();
                mods.put(param, "0.01"); // Try minimal value

                ValidationResult result = new ValidationResult(
                        "Manipulate '" + param + "' in " + node.getMethod() + " " + node.getPath(),
                        ValidationResult.Strategy.VALUE_MANIPULATION);

                if (dryRunMode.get()) {
                    result.setDryRun(true);
                    result.setEvidence("[DRY RUN] Would modify " + param + "=0.01 in "
                            + node.getMethod() + " " + node.getUrl());
                    results.add(result);
                    continue;
                }

                long start = System.currentTimeMillis();
                List<MutationResult> mutations = new java.util.ArrayList<>();
                RequestReplayer.ReplayResponse response = replayer.replay(
                        node, mods, false, mutations);
                result.setDurationMs(System.currentTimeMillis() - start);

                if (response != null) {
                    result.setOriginalStatusCode(node.getStatusCode());
                    result.setTestStatusCode(response.statusCode);

                    String origBody = node.getRequest() != null
                            ? node.getRequest().getResponseBody() : "";
                    ResponseComparator.ComparisonResult comparison =
                            ResponseComparator.compare(node.getStatusCode(), origBody,
                                    response.statusCode, response.body);

                    result.setResponseSimilarity(comparison.bodySimilarity);
                    applyProofLevel(result, comparison,
                            "Value manipulation: set " + param + "=0.01\n",
                            null,
                            null);

                    // Add a state check so the result is promoted to
                    // CONFIRMED when an attacker-controlled value (e.g. 0.01)
                    // actually persists in the response.
                    result.addStateCheck(StateEffectExtractor.diff(
                            response.body != null ? node.getUrl() : null,
                            node.getStatusCode(), origBody,
                            response.statusCode, response.body));

                    // If the mutation could not be applied at all, this
                    // test is invalid. Mark it as ERROR with a clear reason.
                    boolean anyApplied = mutations.stream().anyMatch(MutationResult::isApplied);
                    if (!anyApplied) {
                        String reason = mutations.isEmpty()
                                ? "no mutations were specified"
                                : "mutation did not apply: " + mutations.get(0).getReason();
                        result.setProofLevel(ValidationResult.ProofLevel.ERROR);
                        result.setConfidence(0.1);
                        result.setEvidence("Value manipulation failed: " + reason
                                + ". The test cannot be trusted.");
                    }
                }

                results.add(result);
                rateLimitDelay();
            }
        }
        return results;
    }

    // ========================================================================
    // c) Replay/Repeat Validation
    // ========================================================================

    private List<ValidationResult> validateReplay(List<RequestNode> chain) {
        List<ValidationResult> results = new ArrayList<>();

        // Find state-changing requests to replay
        for (RequestNode node : chain) {
            String method = node.getMethod() != null ? node.getMethod().toUpperCase() : "GET";
            if (!"POST".equals(method) && !"PUT".equals(method)) continue;
            if (!isInScope(node)) continue;

            ValidationResult result = new ValidationResult(
                    "Replay: " + node.getMethod() + " " + node.getPath(),
                    ValidationResult.Strategy.REPLAY);

            if (dryRunMode.get()) {
                result.setDryRun(true);
                result.setEvidence("[DRY RUN] Would replay " + node.getMethod()
                        + " " + node.getUrl() + " 3 times");
                results.add(result);
                continue;
            }

            // Replay 3 times
            int successCount = 0;
            for (int attempt = 0; attempt < 3; attempt++) {
                RequestReplayer.ReplayResponse response = replayer.replay(node, null, false);
                if (response != null && response.statusCode >= 200 && response.statusCode < 400) {
                    successCount++;
                }
                rateLimitDelay();
            }

            // 3/3 identical successes are PROBABLE, not CONFIRMED —
            // the server might legitimately accept identical requests
            // (idempotent read) or silently dedupe. Without a business
            // effect observation, treat as needing human review.
            if (successCount >= 3) {
                result.setProofLevel(ValidationResult.ProofLevel.PROBABLE);
                result.setConfidence(0.6);
            } else if (successCount >= 2) {
                result.setProofLevel(ValidationResult.ProofLevel.PROBABLE);
                result.setConfidence(0.5);
            } else {
                result.setProofLevel(ValidationResult.ProofLevel.NOT_CONFIRMED);
                result.setConfidence(0.2);
            }
            result.setEvidence("Replay test: sent request 3 times, "
                    + successCount + "/3 succeeded."
                    + (successCount >= 2 ? " Possible missing idempotency control; needs review." : ""));

            results.add(result);
        }
        return results;
    }

    // ========================================================================
    // d) Race Condition Validation
    // ========================================================================

    private List<ValidationResult> validateRaceCondition(List<RequestNode> chain) {
        List<ValidationResult> results = new ArrayList<>();

        for (RequestNode node : chain) {
            String method = node.getMethod() != null ? node.getMethod().toUpperCase() : "GET";
            if (!"POST".equals(method)) continue;
            if (!isInScope(node)) continue;

            ValidationResult result = new ValidationResult(
                    "Race condition: " + node.getMethod() + " " + node.getPath(),
                    ValidationResult.Strategy.RACE_CONDITION);

            if (dryRunMode.get()) {
                result.setDryRun(true);
                result.setEvidence("[DRY RUN] Would send 5 concurrent requests to "
                        + node.getMethod() + " " + node.getUrl());
                results.add(result);
                continue;
            }

            // Send 5 concurrent requests
            int concurrency = 5;
            CountDownLatch startLatch = new CountDownLatch(1);
            CountDownLatch doneLatch = new CountDownLatch(concurrency);
            List<RequestReplayer.ReplayResponse> responses =
                    Collections.synchronizedList(new ArrayList<>());

            ExecutorService raceExecutor = Executors.newFixedThreadPool(concurrency);
            for (int i = 0; i < concurrency; i++) {
                raceExecutor.submit(() -> {
                    try {
                        startLatch.await(); // Synchronized start
                        RequestReplayer.ReplayResponse resp = replayer.replay(node, null, false);
                        if (resp != null) responses.add(resp);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        doneLatch.countDown();
                    }
                });
            }

            startLatch.countDown(); // Release all threads simultaneously
            try {
                doneLatch.await(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            raceExecutor.shutdownNow();

            int successCount = (int) responses.stream()
                    .filter(r -> r.statusCode >= 200 && r.statusCode < 400).count();

            // Race conditions are an interesting case: a 2xx from every
            // concurrent request is necessary but not sufficient proof.
            // Without an observed business effect (e.g. duplicate order
            // count, new state appearing), the result is at most PROBABLE.
            if (successCount >= 4) {
                result.setProofLevel(ValidationResult.ProofLevel.PROBABLE);
                result.setConfidence(0.7);
            } else if (successCount >= 2) {
                result.setProofLevel(ValidationResult.ProofLevel.PROBABLE);
                result.setConfidence(0.5);
            } else {
                result.setProofLevel(ValidationResult.ProofLevel.NOT_CONFIRMED);
                result.setConfidence(0.2);
            }
            result.setEvidence("Race condition test: sent " + concurrency
                    + " concurrent requests, " + successCount + "/" + responses.size()
                    + " succeeded."
                    + (successCount > 1 ? " Possible race condition; needs review." : ""));

            results.add(result);
            rateLimitDelay();
        }
        return results;
    }

    // ========================================================================
    // e) IDOR Validation
    // ========================================================================

    private List<ValidationResult> validateIDOR(List<RequestNode> chain, ChainVerdict verdict) {
        List<ValidationResult> results = new ArrayList<>();

        if (!allowDestructiveTests.get()) {
            ValidationResult result = new ValidationResult(
                    "IDOR validation skipped", ValidationResult.Strategy.IDOR);
            result.setDryRun(true);
            result.setEvidence("IDOR tests require user approval (destructive). "
                    + "Enable 'aggressive' validation profile or allow destructive tests.");
            results.add(result);
            return results;
        }

        // Find nodes with ID-like parameters
        for (RequestNode node : chain) {
            if (!isInScope(node)) continue;
            Map<String, Object> params = node.getExtractedParams();
            if (params == null) continue;

            for (Map.Entry<String, Object> entry : params.entrySet()) {
                String name = entry.getKey().toLowerCase();
                if (name.contains("id") || name.contains("user") || name.contains("account")) {
                    String origValue = entry.getValue().toString();
                    // Try incrementing/decrementing numeric IDs
                    String newValue;
                    try {
                        long numericId = Long.parseLong(origValue);
                        newValue = String.valueOf(numericId + 1);
                    } catch (NumberFormatException e) {
                        continue; // Skip non-numeric IDs
                    }

                    Map<String, String> mods = new HashMap<>();
                    mods.put(entry.getKey(), newValue);

                    ValidationResult result = new ValidationResult(
                            "IDOR: change " + entry.getKey() + " from " + origValue + " to " + newValue,
                            ValidationResult.Strategy.IDOR);

                    if (dryRunMode.get()) {
                        result.setDryRun(true);
                        result.setEvidence("[DRY RUN] Would modify " + entry.getKey()
                                + "=" + newValue + " in " + node.getMethod() + " " + node.getUrl());
                        results.add(result);
                        continue;
                    }

                    long start = System.currentTimeMillis();
                    List<MutationResult> mutations = new java.util.ArrayList<>();
                    RequestReplayer.ReplayResponse response = replayer.replay(
                            node, mods, false, mutations);
                    result.setDurationMs(System.currentTimeMillis() - start);

                    if (response != null) {
                        result.setOriginalStatusCode(node.getStatusCode());
                        result.setTestStatusCode(response.statusCode);

                        // IDOR confirmation requires more than a 2xx — the
                        // server can return 200 with an empty body or with
                        // the original resource even when the ID is wrong.
                        // We require a state observation (different id
                        // echoed, different fields) to call it CONFIRMED.
                        String origBody = node.getRequest() != null
                                ? node.getRequest().getResponseBody() : "";
                        ResponseComparator.ComparisonResult comparison =
                                ResponseComparator.compare(node.getStatusCode(), origBody,
                                        response.statusCode, response.body);
                        applyProofLevel(result, comparison,
                                "IDOR test: changed " + entry.getKey() + " to " + newValue + "\n",
                                null,
                                null);
                        result.addStateCheck(StateEffectExtractor.diff(
                                node.getUrl(), node.getStatusCode(), origBody,
                                response.statusCode, response.body));
                        result.setResponseSimilarity(comparison.bodySimilarity);
                        result.setEvidence("IDOR test: changed " + entry.getKey()
                                + " to " + newValue + ", got " + response.statusCode
                                + "\nProof level: " + result.getProofLevel()
                                + (result.getProofLevel() == ValidationResult.ProofLevel.CONFIRMED
                                        ? " - accessed another user's resource."
                                        : " - needs review; not enough evidence."));
                    } else {
                        result.setProofLevel(ValidationResult.ProofLevel.ERROR);
                        result.setEvidence("IDOR test failed: no response from replay.");
                    }

                    // If the ID mutation did not apply, the test is invalid.
                    if (!mutations.isEmpty() && mutations.stream().noneMatch(MutationResult::isApplied)) {
                        result.setProofLevel(ValidationResult.ProofLevel.ERROR);
                        result.setEvidence("IDOR mutation failed to apply: "
                                + mutations.get(0).getReason());
                    }

                    results.add(result);
                    rateLimitDelay();
                }
            }
        }
        return results;
    }

    // ========================================================================
    // LLM-Suggested Tests
    // ========================================================================

    private List<ValidationResult> runSuggestedTests(ChainVerdict verdict) {
        List<ValidationResult> results = new ArrayList<>();
        if (verdict.getSuggestedTests() == null) return results;

        for (SuggestedTest test : verdict.getSuggestedTests()) {
            if (test.getUrl() == null) continue;
            if (!scopeFilter.isUrlInScope(test.getUrl())) continue;

            // Find the matching node in the chain
            RequestNode matchingNode = null;
            for (RequestNode node : verdict.getChain()) {
                if (node.getUrl() != null && node.getUrl().contains(test.getUrl())) {
                    matchingNode = node;
                    break;
                }
            }
            if (matchingNode == null) continue;

            ValidationResult result = new ValidationResult(
                    test.getTestName() != null ? test.getTestName() : "LLM suggested test",
                    ValidationResult.Strategy.VALUE_MANIPULATION);

            if (dryRunMode.get()) {
                result.setDryRun(true);
                result.setEvidence("[DRY RUN] " + test.getMethod() + " " + test.getUrl()
                        + " with modifications: " + test.getModifications()
                        + "\nExpected: " + test.getExpectedBehavior());
                results.add(result);
                continue;
            }

            long start = System.currentTimeMillis();
            List<MutationResult> mutations = new java.util.ArrayList<>();
            RequestReplayer.ReplayResponse response = replayer.replay(
                    matchingNode, test.getModifications(), false, mutations);
            result.setDurationMs(System.currentTimeMillis() - start);

            if (response != null) {
                result.setOriginalStatusCode(matchingNode.getStatusCode());
                result.setTestStatusCode(response.statusCode);

                String origBody = matchingNode.getRequest() != null
                        ? matchingNode.getRequest().getResponseBody() : "";
                ResponseComparator.ComparisonResult comparison =
                        ResponseComparator.compare(matchingNode.getStatusCode(), origBody,
                                response.statusCode, response.body);

                result.setResponseSimilarity(comparison.bodySimilarity);
                applyProofLevel(result, comparison,
                        "LLM suggested test: " + test.getTestName() + "\n",
                        null,
                        null);
                result.addStateCheck(StateEffectExtractor.diff(
                        matchingNode.getUrl(), matchingNode.getStatusCode(), origBody,
                        response.statusCode, response.body));

                // If the LLM-supplied modification could not apply, the
                // test did not test what it claims to test.
                if (!mutations.isEmpty() && mutations.stream().noneMatch(MutationResult::isApplied)) {
                    result.setProofLevel(ValidationResult.ProofLevel.ERROR);
                    result.setEvidence("LLM suggested test mutation failed: "
                            + mutations.get(0).getReason());
                }
            } else {
                result.setProofLevel(ValidationResult.ProofLevel.ERROR);
                result.setEvidence("LLM suggested test failed: no response from replay.");
            }

            results.add(result);
            rateLimitDelay();
        }
        return results;
    }

    // ========================================================================
    // Safety & Utility
    // ========================================================================

    private boolean isInScope(RequestNode node) {
        return node.getHost() != null && scopeFilter.isInScope(node.getHost());
    }

    private void rateLimitDelay() {
        if (replayDelayMs > 0) {
            try { Thread.sleep(replayDelayMs); } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    // --- Configuration ---

    public void setDryRunMode(boolean dryRun) { this.dryRunMode.set(dryRun); }
    public boolean isDryRunMode() { return dryRunMode.get(); }

    public void setAllowDestructiveTests(boolean allow) { this.allowDestructiveTests.set(allow); }
    public boolean isAllowDestructiveTests() { return allowDestructiveTests.get(); }

    /**
     * Set a sink for live validation counts. The validation engine
     * publishes strict-confirmed and probable counts to the sink
     * after every {@link #validate(ChainVerdict)} call so the status
     * panel can show them in O(1).
     */
    public void setMetricsSink(WorkflowDetector detector) {
        this.metricsSink = detector;
    }

    public void setReplayDelayMs(int delayMs) { this.replayDelayMs = delayMs; }
    public int getReplayDelayMs() { return replayDelayMs; }

    public List<ValidationResult> getAllResults() {
        return Collections.unmodifiableList(allResults);
    }

    public int getConfirmedCount() {
        return (int) allResults.stream().filter(ValidationResult::isConfirmed).count();
    }

    public int getStrictConfirmedCount() {
        return (int) allResults.stream()
                .filter(ValidationResult::isConfirmedStrict)
                .count();
    }

    // ========================================================================
    // Proof-level wiring helpers
    // ========================================================================

    /**
     * Map a {@link ResponseComparator.ComparisonResult} onto the result's
     * proof level. The comparator can return CONFIRMED only when a
     * business-state observation is present; this helper centralises the
     * evidence-string composition so the per-strategy call sites stay
     * readable.
     */
    private void applyProofLevel(ValidationResult result,
                                  ResponseComparator.ComparisonResult comparison,
                                  String evidencePrefix,
                                  String confirmedSuffix,
                                  String notConfirmedSuffix) {
        ValidationResult.ProofLevel level =
                ResponseComparator.classifyProof(comparison);
        result.setProofLevel(level);
        switch (level) {
            case CONFIRMED:
                result.setConfidence(0.9);
                break;
            case PROBABLE:
                result.setConfidence(0.6);
                break;
            case NOT_CONFIRMED:
                result.setConfidence(0.2);
                break;
            case ERROR:
                result.setConfidence(0.1);
                break;
        }
        StringBuilder sb = new StringBuilder(evidencePrefix);
        sb.append(comparison.evidence);
        switch (level) {
            case CONFIRMED:
                if (confirmedSuffix != null) sb.append(confirmedSuffix);
                break;
            case PROBABLE:
                sb.append("\nResponse looks similar to success but no business-effect proof yet; review manually.");
                break;
            case NOT_CONFIRMED:
                if (notConfirmedSuffix != null) sb.append(notConfirmedSuffix);
                break;
            case ERROR:
                break;
        }
        result.setEvidence(sb.toString());
    }
}

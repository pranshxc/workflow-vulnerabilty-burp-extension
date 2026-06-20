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

    private final AtomicBoolean dryRunMode = new AtomicBoolean(false);
    private final AtomicBoolean allowDestructiveTests = new AtomicBoolean(false);
    private int replayDelayMs = 500; // Rate limiting between replays

    private final List<ValidationResult> allResults = new CopyOnWriteArrayList<>();

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

        // Run applicable validations based on vulnerability type
        String vulnType = verdict.getVulnerabilityType();

        if (vulnType != null) {
            switch (vulnType) {
                case "step_skipping":
                    results.addAll(validateStepSkipping(chain));
                    break;
                case "value_manipulation":
                    results.addAll(validateValueManipulation(chain, verdict));
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

        return results;
    }

    // ========================================================================
    // a) Step Skipping Validation
    // ========================================================================

    private List<ValidationResult> validateStepSkipping(List<RequestNode> chain) {
        List<ValidationResult> results = new ArrayList<>();
        if (chain.size() < 2) return results;

        // Replay the final step without completing earlier steps (fresh session)
        RequestNode finalNode = chain.get(chain.size() - 1);

        if (!isInScope(finalNode)) return results;

        ValidationResult result = new ValidationResult(
                "Skip to final step: " + finalNode.getMethod() + " " + finalNode.getPath(),
                ValidationResult.Strategy.STEP_SKIP);

        if (dryRunMode.get()) {
            result.setDryRun(true);
            result.setEvidence("[DRY RUN] Would replay " + finalNode.getMethod()
                    + " " + finalNode.getUrl() + " with fresh session (no cookies/auth)");
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
            boolean confirmed = ResponseComparator.isVulnerabilityConfirmed(comparison);
            result.setConfirmed(confirmed);
            result.setConfidence(confirmed ? 0.9 : 0.3);
            result.setEvidence("Step-skip test: replayed final step with fresh session.\n"
                    + comparison.evidence
                    + (confirmed ? "\nServer accepted request without prerequisites!"
                    : "\nServer correctly rejected the request."));
        } else {
            result.setEvidence("Replay failed - no response received.");
        }

        results.add(result);
        rateLimitDelay();
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
                RequestReplayer.ReplayResponse response = replayer.replay(node, mods, false);
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
                    boolean confirmed = ResponseComparator.isVulnerabilityConfirmed(comparison);
                    result.setConfirmed(confirmed);
                    result.setConfidence(confirmed ? 0.85 : 0.2);
                    result.setEvidence("Value manipulation: set " + param + "=0.01\n"
                            + comparison.evidence);
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

            result.setConfirmed(successCount >= 2);
            result.setConfidence(successCount >= 3 ? 0.9 : successCount >= 2 ? 0.7 : 0.2);
            result.setEvidence("Replay test: sent request 3 times, "
                    + successCount + "/3 succeeded."
                    + (successCount >= 2 ? " Missing idempotency control!" : ""));

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

            // If multiple concurrent requests all succeeded where only one should
            result.setConfirmed(successCount > 1);
            result.setConfidence(successCount >= 4 ? 0.9 : successCount >= 2 ? 0.7 : 0.2);
            result.setEvidence("Race condition test: sent " + concurrency
                    + " concurrent requests, " + successCount + "/" + responses.size()
                    + " succeeded."
                    + (successCount > 1 ? " Possible race condition!" : ""));

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
                    RequestReplayer.ReplayResponse response = replayer.replay(node, mods, false);
                    result.setDurationMs(System.currentTimeMillis() - start);

                    if (response != null) {
                        result.setOriginalStatusCode(node.getStatusCode());
                        result.setTestStatusCode(response.statusCode);
                        boolean confirmed = response.statusCode >= 200 && response.statusCode < 400;
                        result.setConfirmed(confirmed);
                        result.setConfidence(confirmed ? 0.9 : 0.2);
                        result.setEvidence("IDOR test: changed " + entry.getKey()
                                + " to " + newValue + ", got " + response.statusCode
                                + (confirmed ? " - accessed another user's resource!" : ""));
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
            RequestReplayer.ReplayResponse response = replayer.replay(
                    matchingNode, test.getModifications(), false);
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
                boolean confirmed = ResponseComparator.isVulnerabilityConfirmed(comparison);
                result.setConfirmed(confirmed);
                result.setConfidence(confirmed ? 0.85 : 0.2);
                result.setEvidence("LLM suggested test: " + test.getTestName() + "\n"
                        + comparison.evidence);
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

    public void setReplayDelayMs(int delayMs) { this.replayDelayMs = delayMs; }
    public int getReplayDelayMs() { return replayDelayMs; }

    public List<ValidationResult> getAllResults() {
        return Collections.unmodifiableList(allResults);
    }

    public int getConfirmedCount() {
        return (int) allResults.stream().filter(ValidationResult::isConfirmed).count();
    }
}

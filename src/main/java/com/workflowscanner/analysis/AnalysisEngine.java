package com.workflowscanner.analysis;

import com.workflowscanner.config.ExtensionConfig;
import com.workflowscanner.graph.RequestEdge;
import com.workflowscanner.graph.RequestGraph;
import com.workflowscanner.graph.RequestNode;
import com.workflowscanner.llm.LLMAnalysisResult;
import com.workflowscanner.llm.LLMClient;
import com.workflowscanner.llm.LLMContextManager;
import com.workflowscanner.llm.LLMResponseParser;
import com.workflowscanner.llm.NodeAnalysisContext;
import com.workflowscanner.llm.PromptBuilder;
import com.workflowscanner.llm.SystemPrompt;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * Orchestrates workflow chain analysis by:
 * 1. Selecting and prioritizing chains from the graph
 * 2. Running heuristic pre-filters
 * 3. Feeding nodes to the LLM in chronological order with accumulated context
 * 4. Aggregating node-level results into chain-level verdicts
 *
 * Features:
 * - Background thread pool with configurable concurrency
 * - Priority-ordered analysis queue
 * - Pause/resume/cancel controls
 * - Progress tracking for UI
 * - Deduplication via chain fingerprint caching
 * - Force re-analysis support
 * - Comprehensive logging
 */
public class AnalysisEngine {

    private final RequestGraph graph;
    private final LLMClient llmClient;
    private final ExtensionConfig config;
    private final ExtensionLogger logger;
    private final ChainPrioritizer prioritizer;
    private final HeuristicPreFilter preFilter;

    private ExecutorService executor;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean paused = new AtomicBoolean(false);

    // Results and caching
    private final Map<String, ChainVerdict> verdictCache = new ConcurrentHashMap<>();
    private final List<ChainVerdict> allVerdicts = new CopyOnWriteArrayList<>();

    // Progress tracking
    private final AtomicInteger totalChains = new AtomicInteger(0);
    private final AtomicInteger completedChains = new AtomicInteger(0);
    private final AtomicInteger currentChainNodes = new AtomicInteger(0);
    private final AtomicInteger currentNodeProgress = new AtomicInteger(0);
    private volatile String currentChainId = "";

    // Statistics
    private final AtomicLong totalLLMCalls = new AtomicLong(0);
    private final AtomicLong totalFindings = new AtomicLong(0);

    // Listeners for UI updates
    private final CopyOnWriteArrayList<Consumer<ChainVerdict>> verdictListeners = new CopyOnWriteArrayList<>();

    public AnalysisEngine(RequestGraph graph, LLMClient llmClient,
                          ExtensionConfig config, ExtensionLogger logger) {
        this.graph = graph;
        this.llmClient = llmClient;
        this.config = config;
        this.logger = logger;
        this.prioritizer = new ChainPrioritizer();
        this.preFilter = new HeuristicPreFilter();
        this.executor = Executors.newFixedThreadPool(config.getAnalysisConcurrency());
    }

    /**
     * Start analysis of all detected chains in priority order.
     */
    public void start() {
        if (running.get()) {
            logger.log(LogCategory.ANALYSIS, LogLevel.WARN, "AnalysisEngine",
                    "Analysis already running.");
            return;
        }

        if (!llmClient.isConfigured()) {
            logger.log(LogCategory.ANALYSIS, LogLevel.ERROR, "AnalysisEngine",
                    "Cannot start analysis: LLM client not configured.");
            return;
        }

        running.set(true);
        paused.set(false);
        completedChains.set(0);

        executor.submit(this::runAnalysisPipeline);

        logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine",
                "Analysis started.");
    }

    /**
     * Analyze a specific chain (e.g., triggered from UI).
     */
    public void analyzeChain(List<RequestNode> chain, boolean forceReanalyze) {
        if (!llmClient.isConfigured()) {
            logger.log(LogCategory.ANALYSIS, LogLevel.ERROR, "AnalysisEngine",
                    "Cannot analyze: LLM client not configured.");
            return;
        }

        String fingerprint = ChainVerdict.generateFingerprint(chain);
        if (!forceReanalyze && verdictCache.containsKey(fingerprint)) {
            logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine",
                    "Chain already analyzed (cached). Use force to re-analyze.");
            return;
        }

        executor.submit(() -> analyzeChainInternal(chain));
    }

    /**
     * Main analysis pipeline: discover chains, prioritize, analyze.
     */
    private void runAnalysisPipeline() {
        try {
            // 1. Get all workflow chains from graph
            List<List<RequestNode>> chains = graph.getWorkflowChains();
            if (chains.isEmpty()) {
                logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine",
                        "No workflow chains detected in graph.");
                running.set(false);
                return;
            }

            // 2. Get edges for each chain (for prioritization)
            List<List<RequestEdge>> chainEdges = new ArrayList<>();
            for (List<RequestNode> chain : chains) {
                List<RequestEdge> edges = new ArrayList<>();
                for (RequestNode node : chain) {
                    edges.addAll(graph.getEdgesForNode(node.getId()));
                }
                chainEdges.add(edges);
            }

            // 3. Prioritize chains
            List<List<RequestNode>> prioritized = prioritizer.prioritize(chains, chainEdges);
            totalChains.set(prioritized.size());

            logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine",
                    "Starting analysis of " + prioritized.size() + " chains (from "
                            + chains.size() + " total, after filtering).");

            // 4. Analyze each chain in priority order
            for (int i = 0; i < prioritized.size(); i++) {
                if (!running.get()) break;

                // Pause support
                while (paused.get() && running.get()) {
                    try { Thread.sleep(500); } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }

                List<RequestNode> chain = prioritized.get(i);
                String fingerprint = ChainVerdict.generateFingerprint(chain);

                // Skip already-analyzed chains
                if (verdictCache.containsKey(fingerprint)) {
                    completedChains.incrementAndGet();
                    continue;
                }

                logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine",
                        "Analyzing chain " + (i + 1) + "/" + prioritized.size()
                                + " (" + chain.size() + " nodes)");

                analyzeChainInternal(chain);
                completedChains.incrementAndGet();
            }

            logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine",
                    "Analysis complete. Chains analyzed: " + completedChains.get()
                            + ", Findings: " + totalFindings.get()
                            + ", LLM calls: " + totalLLMCalls.get());

        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "AnalysisEngine",
                    "Analysis pipeline error.", e);
        } finally {
            running.set(false);
        }
    }

    /**
     * Analyze a single chain: pre-filter, then node-by-node LLM analysis.
     */
    private void analyzeChainInternal(List<RequestNode> chain) {
        String chainId = UUID.randomUUID().toString().substring(0, 8);
        String fingerprint = ChainVerdict.generateFingerprint(chain);
        currentChainId = chainId;

        ChainVerdict verdict = new ChainVerdict();
        verdict.setChainId(chainId);
        verdict.setFingerprint(fingerprint);
        verdict.setChain(chain);
        verdict.setState(AnalysisState.ANALYZING);
        verdict.setStartTime(System.currentTimeMillis());

        try {
            // 1. Run heuristic pre-filters
            List<HeuristicPreFilter.HeuristicSignal> signals = preFilter.analyze(chain);
            verdict.setHeuristicSignals(signals);
            if (!signals.isEmpty()) {
                logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine",
                        "Chain " + chainId + ": " + signals.size() + " heuristic signals found.");
                for (HeuristicPreFilter.HeuristicSignal signal : signals) {
                    logger.log(LogCategory.ANALYSIS, LogLevel.DEBUG, "AnalysisEngine",
                            "  " + signal);
                }
            }

            // 2. Node-by-node LLM analysis with context accumulation
            LLMContextManager contextManager = new LLMContextManager(config.getLlmMaxContextTokens());
            List<LLMAnalysisResult> nodeResults = new ArrayList<>();
            currentChainNodes.set(chain.size());

            for (int i = 0; i < chain.size(); i++) {
                if (!running.get()) {
                    verdict.setState(AnalysisState.CANCELLED);
                    break;
                }

                while (paused.get() && running.get()) {
                    try { Thread.sleep(500); } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        verdict.setState(AnalysisState.CANCELLED);
                        break;
                    }
                }

                RequestNode node = chain.get(i);
                currentNodeProgress.set(i + 1);

                logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine",
                        "Chain " + chainId + ": analyzing node " + (i + 1) + "/" + chain.size()
                                + " (Node#" + node.getNodeIndex() + " " + node.getMethod()
                                + " " + node.getPath() + ")");

                // Build prompt
                List<RequestEdge> nodeEdges = graph.getEdgesForNode(node.getId());
                String userMessage = PromptBuilder.buildPrompt(
                        node, nodeEdges, contextManager, graph.getNodes());

                // Send to LLM
                totalLLMCalls.incrementAndGet();
                String rawResponse = llmClient.sendChatCompletion(
                        SystemPrompt.PROMPT, userMessage);

                if (rawResponse == null) {
                    logger.log(LogCategory.ANALYSIS, LogLevel.WARN, "AnalysisEngine",
                            "LLM returned null for Node#" + node.getNodeIndex() + ", skipping.");
                    nodeResults.add(null);
                    continue;
                }

                // Track token usage
                long tokens = LLMResponseParser.extractTokenUsage(rawResponse);
                if (tokens > 0) llmClient.addTokensUsed(tokens);

                // Parse response
                LLMAnalysisResult result = LLMResponseParser.parse(rawResponse, logger);
                nodeResults.add(result);

                if (result != null) {
                    logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine",
                            "Node#" + node.getNodeIndex() + " verdict: " + result);

                    // Feed context back for next node
                    NodeAnalysisContext ctx = NodeAnalysisContext.fromResult(
                            result, node.getNodeIndex(), node.getHost(), node.getPath());
                    contextManager.addAnalysisResult(ctx);
                }
            }

            // 3. Aggregate results
            verdict.setNodeResults(nodeResults);
            verdict.aggregateResults();
            verdict.setEndTime(System.currentTimeMillis());

            if (verdict.getState() != AnalysisState.CANCELLED) {
                verdict.setState(AnalysisState.COMPLETE);
            }

            // Track findings
            if (verdict.isVulnerable() || verdict.isSuspicious()) {
                totalFindings.incrementAndGet();
            }

            logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine",
                    "Chain " + chainId + " complete: " + verdict);

        } catch (Exception e) {
            verdict.setState(AnalysisState.FAILED);
            verdict.setErrorMessage(e.getMessage());
            verdict.setEndTime(System.currentTimeMillis());
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "AnalysisEngine",
                    "Chain " + chainId + " analysis failed.", e);
        }

        // Cache and store result
        verdictCache.put(fingerprint, verdict);
        allVerdicts.add(verdict);

        // Notify listeners
        for (Consumer<ChainVerdict> listener : verdictListeners) {
            try { listener.accept(verdict); } catch (Exception ignored) {}
        }
    }

    // --- Controls ---

    public void pause() {
        paused.set(true);
        logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine", "Analysis paused.");
    }

    public void resume() {
        paused.set(false);
        logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine", "Analysis resumed.");
    }

    public void stop() {
        running.set(false);
        paused.set(false);
        logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine", "Analysis stopped.");
    }

    public void shutdown() {
        running.set(false);
        if (executor != null && !executor.isShutdown()) {
            executor.shutdownNow();
            try { executor.awaitTermination(5, TimeUnit.SECONDS); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
        logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine",
                "Analysis engine shut down.");
    }

    // --- Listeners ---

    public void addVerdictListener(Consumer<ChainVerdict> listener) {
        verdictListeners.add(listener);
    }

    public void removeVerdictListener(Consumer<ChainVerdict> listener) {
        verdictListeners.remove(listener);
    }

    // --- Accessors ---

    public boolean isRunning() { return running.get(); }
    public boolean isPaused() { return paused.get(); }

    public List<ChainVerdict> getAllVerdicts() {
        return Collections.unmodifiableList(allVerdicts);
    }

    public List<ChainVerdict> getVulnerableVerdicts() {
        List<ChainVerdict> result = new ArrayList<>();
        for (ChainVerdict v : allVerdicts) {
            if (v.isVulnerable() || v.isSuspicious()) result.add(v);
        }
        return result;
    }

    public ChainVerdict getVerdictByFingerprint(String fingerprint) {
        return verdictCache.get(fingerprint);
    }

    /**
     * Clear all cached verdicts (allows re-analysis).
     */
    public void clearCache() {
        verdictCache.clear();
        allVerdicts.clear();
        logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine",
                "Verdict cache cleared.");
    }

    // --- Progress ---

    public String getProgressText() {
        if (!running.get()) {
            if (totalChains.get() == 0) return "Idle";
            return "Complete: " + completedChains.get() + "/" + totalChains.get()
                    + " chains, " + totalFindings.get() + " findings";
        }
        if (paused.get()) return "Paused";
        return "Analyzing chain " + completedChains.get() + "/" + totalChains.get()
                + ", node " + currentNodeProgress.get() + "/" + currentChainNodes.get();
    }

    public int getTotalChains() { return totalChains.get(); }
    public int getCompletedChains() { return completedChains.get(); }
    public long getTotalLLMCalls() { return totalLLMCalls.get(); }
    public long getTotalFindings() { return totalFindings.get(); }
}

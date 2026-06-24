package com.workflowscanner.analysis;

import com.workflowscanner.config.ExtensionConfig;
import com.workflowscanner.graph.EdgeType;
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
import com.workflowscanner.workflow.WorkflowCandidate;
import com.workflowscanner.workflow.WorkflowDetector;
import com.workflowscanner.workflow.WorkflowType;

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
 * Orchestrates workflow vulnerability analysis using a 3-prompt structure:
 * 1. <b>Classify</b> – Is this candidate a real workflow? What business purpose?
 * 2. <b>Hypotheses</b> – What could go wrong? Generate vulnerability hypotheses.
 * 3. <b>Validate</b> – For each hypothesis, propose a validation plan.
 *
 * Replaces the old node-by-node per-node LLM approach with candidate-level
 * analysis that includes ApplicationModel context and WorkflowDetector output.
 */
public class AnalysisEngine {

    private final RequestGraph graph;
    private final LLMClient llmClient;
    private final ExtensionConfig config;
    private final ExtensionLogger logger;
    private final HeuristicPreFilter preFilter;

    private WorkflowDetector workflowDetector;
    private ApplicationModel applicationModel;

    private ExecutorService executor;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean paused = new AtomicBoolean(false);

    // Results and caching
    private final Map<String, ChainVerdict> verdictCache = new ConcurrentHashMap<>();
    private final List<ChainVerdict> allVerdicts = new CopyOnWriteArrayList<>();

    // Progress tracking
    private final AtomicInteger totalCandidates = new AtomicInteger(0);
    private final AtomicInteger completedCandidates = new AtomicInteger(0);
    private final AtomicInteger currentCandidateSteps = new AtomicInteger(0);
    private final AtomicInteger currentStepProgress = new AtomicInteger(0);
    private volatile String currentCandidateId = "";

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
        this.preFilter = new HeuristicPreFilter();
        this.applicationModel = new ApplicationModel();
        this.executor = Executors.newFixedThreadPool(config.getAnalysisConcurrency());
    }

    /**
     * Set the WorkflowDetector used for candidate discovery.
     */
    public void setWorkflowDetector(WorkflowDetector detector) {
        this.workflowDetector = detector;
    }

    /**
     * Set the ApplicationModel (shared across the pipeline).
     */
    public void setApplicationModel(ApplicationModel model) {
        this.applicationModel = model != null ? model : new ApplicationModel();
    }

    /**
     * Start analysis of all detected workflow candidates.
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

        if (workflowDetector == null) {
            logger.log(LogCategory.ANALYSIS, LogLevel.ERROR, "AnalysisEngine",
                    "Cannot start analysis: WorkflowDetector not set.");
            return;
        }

        running.set(true);
        paused.set(false);
        completedCandidates.set(0);

        executor.submit(this::runAnalysisPipeline);

        logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine",
                "Analysis started.");
    }

    /**
     * Analyze a specific candidate (e.g., triggered from UI).
     */
    public void analyzeCandidate(WorkflowCandidate candidate, boolean forceReanalyze) {
        if (!llmClient.isConfigured()) {
            logger.log(LogCategory.ANALYSIS, LogLevel.ERROR, "AnalysisEngine",
                    "Cannot analyze: LLM client not configured.");
            return;
        }

        String fingerprint = ChainVerdict.generateFingerprint(candidate.getSteps());
        if (!forceReanalyze && verdictCache.containsKey(fingerprint)) {
            logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine",
                    "Candidate already analyzed (cached). Use force to re-analyze.");
            return;
        }

        executor.submit(() -> analyzeCandidateInternal(candidate, fingerprint));
    }

    /**
     * Main analysis pipeline: discover workflow candidates, then analyze.
     */
    private void runAnalysisPipeline() {
        try {
            // 1. Detect workflow candidates
            List<WorkflowCandidate> candidates = graph.detectWorkflowCandidates(workflowDetector);
            if (candidates.isEmpty()) {
                logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine",
                        "No workflow candidates detected.");
                running.set(false);
                return;
            }

            // Filter to analysis-ready candidates (respect configured threshold)
            double analysisThreshold = config.getWorkflowScoreThreshold();
            List<WorkflowCandidate> analysisCandidates = candidates.stream()
                    .filter(c -> c.getWorkflowScore() >= analysisThreshold)
                    .toList();

            if (analysisCandidates.isEmpty()) {
                logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine",
                        "No candidates above analysis threshold (" + analysisThreshold
                                + "). Found " + candidates.size()
                                + " display-only candidates.");
                running.set(false);
                return;
            }

            totalCandidates.set(analysisCandidates.size());

            logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine",
                    "Starting analysis of " + analysisCandidates.size()
                            + "/" + candidates.size() + " workflow candidates "
                            + "(threshold: " + analysisThreshold + ").");

            // 2. Build ApplicationModel from all candidates (including display-only)
            for (WorkflowCandidate candidate : candidates) {
                for (RequestNode step : candidate.getSteps()) {
                    if (step != null) {
                        applicationModel.learnFromCandidate(List.of(step));
                    }
                }
            }

            // 3. Analyze each analysis-eligible candidate
            for (int i = 0; i < analysisCandidates.size(); i++) {
                if (!running.get()) break;

                // Pause support
                while (paused.get() && running.get()) {
                    try { Thread.sleep(500); } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }

                WorkflowCandidate candidate = analysisCandidates.get(i);
                String fingerprint = ChainVerdict.generateFingerprint(candidate.getSteps());

                // Skip already-analyzed
                if (verdictCache.containsKey(fingerprint)) {
                    completedCandidates.incrementAndGet();
                    continue;
                }

                logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine",
                        "Analyzing candidate " + (i + 1) + "/" + candidates.size()
                                + " (" + candidate.getSteps().size() + " steps, score: "
                                + String.format("%.1f", candidate.getWorkflowScore()) + ")");

                analyzeCandidateInternal(candidate, fingerprint);
                completedCandidates.incrementAndGet();
            }

            logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine",
                    "Analysis complete. Candidates analyzed: " + completedCandidates.get()
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
     * Analyze a single candidate using the 3-prompt structure:
     * 1. Classify the workflow
     * 2. Generate vulnerability hypotheses
     * 3. Validate and produce final verdict
     */
    private void analyzeCandidateInternal(WorkflowCandidate candidate, String fingerprint) {
        String candidateId = UUID.randomUUID().toString().substring(0, 8);
        currentCandidateId = candidateId;

        ChainVerdict verdict = new ChainVerdict();
        verdict.setChainId(candidateId);
        verdict.setFingerprint(fingerprint);
        // Convert WorkflowStep -> RequestNode for backward compat
        List<RequestNode> nodes = new ArrayList<>();
        for (RequestNode step : candidate.getSteps()) {
            if (step != null) nodes.add(step);
        }
        verdict.setChain(nodes);
        verdict.setState(AnalysisState.ANALYZING);
        verdict.setStartTime(System.currentTimeMillis());

        try {
            // 1. Run heuristic pre-filters
            List<HeuristicPreFilter.HeuristicSignal> signals = preFilter.analyze(nodes);
            verdict.setHeuristicSignals(signals);
            if (!signals.isEmpty()) {
                logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine",
                        "Candidate " + candidateId + ": " + signals.size()
                                + " heuristic signals found.");
            }

            // 2. --- Prompt 1: Classify the workflow ---
            String classifyPrompt = PromptBuilder.buildWorkflowClassifyPrompt(
                    candidate, applicationModel);
            totalLLMCalls.incrementAndGet();
            String classifyResponse = llmClient.sendChatCompletion(
                    SystemPrompt.PROMPT, classifyPrompt);

            if (classifyResponse == null) {
                logger.log(LogCategory.ANALYSIS, LogLevel.WARN, "AnalysisEngine",
                        "LLM returned null for classify step, skipping candidate.");
                verdict.setState(AnalysisState.FAILED);
                verdict.setErrorMessage("LLM classify step returned null");
                verdict.setEndTime(System.currentTimeMillis());
                cacheAndNotify(fingerprint, verdict);
                return;
            }

            // Extract candidate context from classify response
            String workflowContext = LLMResponseParser.extractChainContext(classifyResponse);
            String workflowType = LLMResponseParser.extractWorkflowType(classifyResponse);

            // 3. --- Prompt 2: Generate vulnerability hypotheses ---
            String hypothesesPrompt = PromptBuilder.buildHypothesesPrompt(
                    candidate, workflowContext, workflowType, applicationModel);
            totalLLMCalls.incrementAndGet();
            String hypothesesResponse = llmClient.sendChatCompletion(
                    SystemPrompt.PROMPT, hypothesesPrompt);

            if (hypothesesResponse == null) {
                logger.log(LogCategory.ANALYSIS, LogLevel.WARN, "AnalysisEngine",
                        "LLM returned null for hypotheses step, skipping candidate.");
                verdict.setState(AnalysisState.FAILED);
                verdict.setErrorMessage("LLM hypotheses step returned null");
                verdict.setEndTime(System.currentTimeMillis());
                cacheAndNotify(fingerprint, verdict);
                return;
            }

            List<String> hypotheses = LLMResponseParser.extractHypotheses(hypothesesResponse);

            // 4. --- Prompt 3: Validate each hypothesis (per-step analysis) ---
            LLMContextManager contextManager = new LLMContextManager(config.getLlmMaxContextTokens());
            List<LLMAnalysisResult> nodeResults = new ArrayList<>();
            currentCandidateSteps.set(nodes.size());

            for (int i = 0; i < nodes.size(); i++) {
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

                RequestNode node = nodes.get(i);
                currentStepProgress.set(i + 1);

                logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine",
                        "Candidate " + candidateId + ": analyzing step " + (i + 1)
                                + "/" + nodes.size() + " (" + node.getMethod()
                                + " " + node.getPath() + ")");

                // Build validation prompt for this step
                List<RequestEdge> nodeEdges = graph.getEdgesForNode(node.getId());
                String validatePrompt = PromptBuilder.buildValidationPrompt(
                        node, nodeEdges, contextManager, graph.getNodes(),
                        hypotheses, workflowContext, workflowType, applicationModel);

                totalLLMCalls.incrementAndGet();
                String validateResponse = llmClient.sendChatCompletion(
                        SystemPrompt.PROMPT, validatePrompt);

                if (validateResponse == null) {
                    logger.log(LogCategory.ANALYSIS, LogLevel.WARN, "AnalysisEngine",
                            "LLM returned null for Node step, skipping.");
                    nodeResults.add(null);
                    continue;
                }

                // Track token usage
                long tokens = LLMResponseParser.extractTokenUsage(validateResponse);
                if (tokens > 0) llmClient.addTokensUsed(tokens);

                // Parse response
                LLMAnalysisResult result = LLMResponseParser.parse(validateResponse, logger);
                nodeResults.add(result);

                if (result != null) {
                    logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine",
                            "Step " + (i + 1) + " verdict: " + result.getVerdict());

                    // Feed context back for next step
                    NodeAnalysisContext ctx = NodeAnalysisContext.fromResult(
                            result, node.getNodeIndex(), node.getHost(), node.getPath());
                    contextManager.addAnalysisResult(ctx);
                }
            }

            // 5. Aggregate results
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

            // Update ApplicationModel from this candidate
            applicationModel.learnFromCandidate(nodes);

            logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine",
                    "Candidate " + candidateId + " complete: " + verdict);

        } catch (Exception e) {
            verdict.setState(AnalysisState.FAILED);
            verdict.setErrorMessage(e.getMessage());
            verdict.setEndTime(System.currentTimeMillis());
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "AnalysisEngine",
                    "Candidate " + candidateId + " analysis failed.", e);
        }

        // Cache and notify
        cacheAndNotify(fingerprint, verdict);
    }

    /**
     * Legacy entry point: analyze a raw node chain (bridge for old callers).
     * Wraps nodes into a WorkflowCandidate and delegates.
     */
    @Deprecated
    public void analyzeChain(List<RequestNode> chain, boolean forceReanalyze) {
        if (!llmClient.isConfigured()) return;
        String fingerprint = ChainVerdict.generateFingerprint(chain);
        if (!forceReanalyze && verdictCache.containsKey(fingerprint)) return;

        // Build a WorkflowCandidate from the raw chain
        // (score will be 0 since we don't have a detector, but analysis still works)
        executor.submit(() -> {
            WorkflowCandidate candidate = new WorkflowCandidate();
            candidate.setWorkflowType(WorkflowType.UNKNOWN_BUSINESS_FLOW);
            for (RequestNode node : chain) {
                candidate.addStep(node);
            }
            analyzeCandidateInternal(candidate, fingerprint);
        });
    }

    /**
     * Re-analyze all cached verdicts.
     */
    public void reanalyzeAll() {
        List<ChainVerdict> existing = new ArrayList<>(allVerdicts);
        clearCache();
        for (ChainVerdict v : existing) {
            List<RequestNode> chain = v.getChain();
            if (chain != null && !chain.isEmpty()) {
                analyzeChain(chain, true);
            }
        }
    }

    private void cacheAndNotify(String fingerprint, ChainVerdict verdict) {
        verdictCache.put(fingerprint, verdict);
        allVerdicts.add(verdict);

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

    public void clearCache() {
        verdictCache.clear();
        allVerdicts.clear();
        logger.log(LogCategory.ANALYSIS, LogLevel.INFO, "AnalysisEngine",
                "Verdict cache cleared.");
    }

    public ApplicationModel getApplicationModel() { return applicationModel; }

    // --- Progress ---

    public String getProgressText() {
        if (!running.get()) {
            if (totalCandidates.get() == 0) return "Idle";
            return "Complete: " + completedCandidates.get() + "/" + totalCandidates.get()
                    + " candidates, " + totalFindings.get() + " findings";
        }
        if (paused.get()) return "Paused";
        return "Analyzing candidate " + completedCandidates.get() + "/" + totalCandidates.get()
                + ", step " + currentStepProgress.get() + "/" + currentCandidateSteps.get();
    }

    public int getTotalCandidates() { return totalCandidates.get(); }
    public int getCompletedCandidates() { return completedCandidates.get(); }
    public long getTotalLLMCalls() { return totalLLMCalls.get(); }
    public long getTotalFindings() { return totalFindings.get(); }
}

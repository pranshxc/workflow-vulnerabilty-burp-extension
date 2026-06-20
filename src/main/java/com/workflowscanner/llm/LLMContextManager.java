package com.workflowscanner.llm;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Manages rolling context for LLM analysis.
 * Each analyzed node contributes context for future node analysis.
 *
 * Features:
 * - Token budget management (chars/4 approximation)
 * - Priority pruning: recent nodes > high-confidence findings > older context
 * - Chain-scoped context retrieval (same host, related parameters)
 * - Feeds chain_context_update back from LLM responses
 */
public class LLMContextManager {

    private final List<NodeAnalysisContext> previousAnalyses;
    private int maxContextTokens;
    private int currentTokenEstimate;

    public LLMContextManager(int maxContextTokens) {
        this.maxContextTokens = maxContextTokens;
        this.previousAnalyses = new ArrayList<>();
        this.currentTokenEstimate = 0;
    }

    /**
     * Add a completed analysis result to the context.
     * Automatically prunes if over token budget.
     */
    public synchronized void addAnalysisResult(NodeAnalysisContext result) {
        if (result == null) return;
        previousAnalyses.add(result);
        currentTokenEstimate += estimateContextTokens(result);
        pruneContext();
    }

    /**
     * Get all previous analyses.
     */
    public synchronized List<NodeAnalysisContext> getPreviousAnalyses() {
        return Collections.unmodifiableList(new ArrayList<>(previousAnalyses));
    }

    /**
     * Get context relevant to a specific host, limited to maxResults.
     * Prioritizes: same host > VULNERABLE findings > recent entries.
     */
    public synchronized List<NodeAnalysisContext> getRelevantContext(String host, int maxResults) {
        if (previousAnalyses.isEmpty()) return Collections.emptyList();

        // Score each context entry for relevance
        List<ScoredContext> scored = new ArrayList<>();
        for (int i = 0; i < previousAnalyses.size(); i++) {
            NodeAnalysisContext ctx = previousAnalyses.get(i);
            double score = 0;

            // Recency bonus (newer = higher)
            score += (double) i / previousAnalyses.size() * 2.0;

            // Vulnerability bonus
            if ("VULNERABLE".equals(ctx.getVerdict())) score += 5.0;
            else if ("SUSPICIOUS".equals(ctx.getVerdict())) score += 2.0;

            // Same host bonus
            if (host != null && ctx.getHost() != null
                    && host.equalsIgnoreCase(ctx.getHost())) {
                score += 3.0;
            }

            scored.add(new ScoredContext(ctx, score));
        }

        // Sort by score descending, take top N
        scored.sort((a, b) -> Double.compare(b.score, a.score));

        return scored.stream()
                .limit(maxResults)
                .map(sc -> sc.context)
                .collect(Collectors.toList());
    }

    /**
     * Prune old context to stay within token budget.
     * Removes lowest-priority entries first.
     */
    private void pruneContext() {
        while (currentTokenEstimate > maxContextTokens && previousAnalyses.size() > 1) {
            // Find lowest priority entry to remove
            int removeIdx = 0;
            double lowestScore = Double.MAX_VALUE;

            for (int i = 0; i < previousAnalyses.size() - 1; i++) { // Never remove the most recent
                NodeAnalysisContext ctx = previousAnalyses.get(i);
                double score = 0;
                if ("VULNERABLE".equals(ctx.getVerdict())) score += 5.0;
                else if ("SUSPICIOUS".equals(ctx.getVerdict())) score += 2.0;
                // Older entries get lower scores
                score += (double) i / previousAnalyses.size();

                if (score < lowestScore) {
                    lowestScore = score;
                    removeIdx = i;
                }
            }

            NodeAnalysisContext removed = previousAnalyses.remove(removeIdx);
            currentTokenEstimate -= estimateContextTokens(removed);
        }
    }

    /**
     * Estimate token count for a context entry.
     */
    private int estimateContextTokens(NodeAnalysisContext ctx) {
        int chars = 0;
        if (ctx.getSummary() != null) chars += ctx.getSummary().length();
        if (ctx.getKeyFindings() != null) chars += ctx.getKeyFindings().length();
        if (ctx.getVerdict() != null) chars += ctx.getVerdict().length();
        if (ctx.getStateInfo() != null) {
            for (String s : ctx.getStateInfo()) chars += s.length();
        }
        return chars / 4; // Approximate tokens
    }

    /**
     * Clear all context (e.g., when starting a new chain analysis).
     */
    public synchronized void clear() {
        previousAnalyses.clear();
        currentTokenEstimate = 0;
    }

    public int getContextSize() { return previousAnalyses.size(); }
    public int getCurrentTokenEstimate() { return currentTokenEstimate; }
    public int getMaxContextTokens() { return maxContextTokens; }
    public void setMaxContextTokens(int max) { this.maxContextTokens = max; }

    // --- Internal ---

    private static class ScoredContext {
        final NodeAnalysisContext context;
        final double score;
        ScoredContext(NodeAnalysisContext context, double score) {
            this.context = context;
            this.score = score;
        }
    }
}

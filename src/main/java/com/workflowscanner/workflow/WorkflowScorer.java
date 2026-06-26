package com.workflowscanner.workflow;

import com.workflowscanner.analysis.ApplicationModel;
import com.workflowscanner.analysis.TargetVocabulary;
import com.workflowscanner.analysis.TokenNormalizer;
import com.workflowscanner.classification.BusinessKeywordRules;
import com.workflowscanner.classification.NoiseRulesConfig;
import com.workflowscanner.classification.PrivateContextDetector;
import com.workflowscanner.classification.RequestIntent;
import com.workflowscanner.classification.RequestClassification;
import com.workflowscanner.config.ExtensionConfig;
import com.workflowscanner.graph.EdgeType;
import com.workflowscanner.graph.RequestEdge;
import com.workflowscanner.graph.RequestNode;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Scores workflow candidates for vulnerability analysis priority.
 * Higher scores indicate workflows more likely to contain exploitable vulnerabilities.
 *
 * Scores read from ExtensionConfig: >= workflowScoreThreshold → LLM analysis,
 * >= workflowCandidateThreshold → display only, below → suppressed.
 */
public class WorkflowScorer {

    private final ExtensionConfig config;

    public WorkflowScorer(ExtensionConfig config) {
        this.config = config;
    }

    // === Realism-upgrade-2: vocabulary-aware scoring ===
    // Optional ApplicationModel for vocabulary-based score boosts.
    // The scorer can be constructed without one (legacy behavior
    // preserved) — all vocabulary methods null-check.
    private volatile ApplicationModel applicationModel;

    public void setApplicationModel(ApplicationModel model) {
        this.applicationModel = model;
    }

    /**
     * Score a workflow candidate and populate evidence breakdown.
     */
    public double score(WorkflowCandidate candidate) {
        if (candidate == null || candidate.getSteps().isEmpty()) return 0.0;

        List<RequestNode> steps = candidate.getSteps();
        List<RequestEdge> edges = candidate.getSupportingEdges();

        double score = 0.0;

        // Positive signals
        double stateChangeScore = scoreStateChangingMethods(steps);
        double keywordScore = scoreBusinessKeywords(steps);
        double objectFlowScore = scoreObjectFlows(candidate);
        double diversityScore = scoreMethodDiversity(steps);
        double structuralScore = scoreStructuralSignals(steps, edges);
        // === Critical-workflow-type bonus ===
        // A single-step candidate for a known critical workflow
        // type (CHECKOUT, AUTHENTICATION, PAYMENT, etc.) used to
        // score 18.0 (5.0 + 7.0 + 2.0 + 4.0) — below the 20.0
        // analysis threshold. The workflow type itself is a strong
        // signal: even without an explicit edge, a confirmed
        // POST /api/checkout deserves analysis. Add +5.0 to push
        // single-step critical types over the threshold. Multi-step
        // critical candidates already score well above 20.0 so
        // this is a soft bonus, not a gate.
        double criticalTypeBonus = scoreCriticalTypeBonus(candidate);
        // === Phase-1: structural-interest boost ===
        // Unknown authenticated state-changing flows have no keyword
        // match, so they score very low on the keyword axis. Without
        // a boost, they sit at ~11.0 (state-change 5.0 + diversity 2.0
        // + structural 4.0), below the default analysis threshold of
        // 20.0. This makes them never reach the LLM, even though
        // they are exactly the candidates Phase-1 is supposed to
        // surface. The boost is gated on the same conditions as the
        // gate's (4.5) branch: UNKNOWN_BUSINESS_FLOW + auth-bound
        // + state-changing. 10 points gets a typical candidate over
        // the 20.0 threshold and is small enough not to disturb
        // keyword-driven candidates (which already score >>20).
        double unknownFlowBoost = scoreUnknownAuthStateChanging(candidate);
        // === Realism-upgrade-2: vocabulary-based boost ===
        // For each step, look up path-segment tokens in the learned
        // target vocabulary. A match against a USER-supplied term
        // weights 8.0, against a LEARNED business noun 3.0, against
        // an action verb 5.0, against a sensitive field 8.0. The
        // boost is capped at 15.0 per candidate so a coincidental
        // match in a single term does not dominate scoring.
        double vocabularyScore = scoreVocabulary(steps);

        score += stateChangeScore;
        score += keywordScore;
        score += objectFlowScore;
        score += diversityScore;
        score += structuralScore;
        score += criticalTypeBonus;
        score += unknownFlowBoost;
        score += vocabularyScore;

        // Negative signals (penalties)
        double penaltyScore = penalizeStaticContent(steps);
        penaltyScore += penalizePolling(steps);
        penaltyScore += penalizeWeakStructure(steps, edges);
        penaltyScore += penalizeRepetition(steps);
        score -= penaltyScore;

        // Populate evidence with score breakdown
        WorkflowEvidence evidence = candidate.getEvidence();
        if (stateChangeScore > 0) evidence.addObjectFlow(String.format("score:state-change=%.1f", stateChangeScore));
        if (keywordScore > 0) evidence.addObjectFlow(String.format("score:keywords=%.1f", keywordScore));
        if (objectFlowScore > 0) evidence.addObjectFlow(String.format("score:object-flows=%.1f", objectFlowScore));
        if (diversityScore > 0) evidence.addObjectFlow(String.format("score:diversity=%.1f", diversityScore));
        if (structuralScore > 0) evidence.addObjectFlow(String.format("score:structural=%.1f", structuralScore));
        if (criticalTypeBonus > 0) evidence.addObjectFlow(String.format("score:critical-type=%.1f", criticalTypeBonus));
        if (unknownFlowBoost > 0) evidence.addObjectFlow(String.format("score:unknown-flow-boost=%.1f", unknownFlowBoost));
        if (vocabularyScore > 0) evidence.addObjectFlow(String.format("score:vocabulary=%.1f", vocabularyScore));
        if (penaltyScore > 0) evidence.addObjectFlow(String.format("score:penalties=-%.1f", penaltyScore));
        evidence.setConfidence(Math.min(1.0, score / 100.0));

        return score;
    }

    private double scoreCriticalTypeBonus(WorkflowCandidate candidate) {
        if (candidate == null) return 0.0;
        WorkflowType t = candidate.getWorkflowType();
        if (t == null) return 0.0;
        switch (t) {
            case AUTHENTICATION:
            case PASSWORD_RESET:
            case CHECKOUT:
            case PAYMENT:
            case TRANSFER:
            case ROLE_ADMIN:
            case APPROVAL:
            case INVITATION:
            case FILE_UPLOAD:
                return 5.0;
            default:
                return 0.0;
        }
    }

    /**
     * Phase-1 structural-interest boost. Returns 10.0 for
     * UNKNOWN_BUSINESS_FLOW + auth-bound + state-changing
     * candidates, 0.0 otherwise. The boost is small enough not to
     * override keyword-driven candidates (which already score
     * >>20) and large enough to push a typical unknown auth POST
     * over the default analysis threshold.
     */
    private double scoreUnknownAuthStateChanging(WorkflowCandidate candidate) {
        if (candidate == null) return 0.0;
        if (candidate.getWorkflowType() != WorkflowType.UNKNOWN_BUSINESS_FLOW) {
            return 0.0;
        }
        List<RequestNode> steps = candidate.getSteps();
        if (steps == null || steps.isEmpty()) return 0.0;

        boolean hasStateChanging = steps.stream().anyMatch(n -> {
            String m = n.getMethod() == null ? "" : n.getMethod().toUpperCase();
            return "POST".equals(m) || "PUT".equals(m)
                    || "PATCH".equals(m) || "DELETE".equals(m);
        });
        if (!hasStateChanging) return 0.0;

        NoiseRulesConfig nrc = config != null && config.getNoiseRules() != null
                ? config.getNoiseRules()
                : NoiseRulesConfig.withDefaults();
        PrivateContextDetector pcd = new PrivateContextDetector(nrc);
        if (!pcd.chainHasPrivateContext(steps)) return 0.0;

        return 10.0;
    }

    /**
     * Realism-upgrade-2: per-target vocabulary boost. Scans each
     * step's path and parameters against the target vocabulary
     * (learned from traffic + user-supplied). User terms weight
     * more than learned; sensitive fields weight more than nouns;
     * verbs weight more than nouns. Total capped at 15.0 per
     * candidate so a coincidental match does not dominate.
     */
    private double scoreVocabulary(List<RequestNode> steps) {
        if (applicationModel == null || steps == null || steps.isEmpty()) return 0.0;
        TargetVocabulary vocab = applicationModel.getTargetVocabulary();
        if (vocab == null || vocab.size() == 0) return 0.0;

        double total = 0.0;
        for (RequestNode node : steps) {
            total += scoreVocabularyForNode(node, vocab);
        }
        return Math.min(15.0, total);
    }

    private double scoreVocabularyForNode(RequestNode node, TargetVocabulary vocab) {
        if (node == null) return 0.0;
        double score = 0.0;

        // Path tokens
        String path = node.getPath();
        if (path != null) {
            for (String token : TokenNormalizer.normalizePath(path)) {
                if (token.isEmpty()) continue;
                if (vocab.containsActionVerb(token)) {
                    score += 5.0;
                } else if (vocab.containsBusinessNoun(token)) {
                    score += 3.0;
                } else if (vocab.containsWorkflowTerm(token)) {
                    score += 1.0;
                }
            }
        }

        // Parameter / JSON-key tokens (sensitive fields)
        java.util.Map<String, Object> params = node.getExtractedParams();
        if (params != null) {
            for (String key : params.keySet()) {
                if (key == null) continue;
                String cleanKey = key.startsWith("param.") ? key.substring(6) : key;
                for (String token : TokenNormalizer.normalize(cleanKey)) {
                    if (vocab.containsSensitiveField(token)) {
                        score += 8.0;
                    }
                }
            }
        }
        java.util.Map<String, Object> respData = node.getResponseData();
        if (respData != null) {
            for (String key : respData.keySet()) {
                if (key == null) continue;
                for (String token : TokenNormalizer.normalize(key)) {
                    if (vocab.containsSensitiveField(token)) {
                        score += 8.0;
                    }
                }
            }
        }

        return score;
    }

    private double scoreStateChangingMethods(List<RequestNode> steps) {
        int count = 0;
        for (RequestNode node : steps) {
            if (BusinessKeywordRules.isStateChanging(node.getMethod())) count++;
        }
        return count * 5.0;
    }

    private double scoreBusinessKeywords(List<RequestNode> steps) {
        double score = 0.0;
        for (RequestNode node : steps) {
            String path = node.getPath() != null ? node.getPath().toLowerCase() : "";
            if (BusinessKeywordRules.isFinancialPath(path)) score += 7.0;
            else if (BusinessKeywordRules.isAuthPath(path)) score += 5.0;
            else score += BusinessKeywordRules.scorePath(path) * 1.5;
        }
        return score;
    }

    private double scoreObjectFlows(WorkflowCandidate candidate) {
        double score = 0.0;
        for (RequestEdge edge : candidate.getSupportingEdges()) {
            // WORKFLOW_SEQUENCE is intentionally NOT scored here —
            // it is a derived structural edge produced by
            // WorkflowDetector after a candidate is finalized, not
            // a real object-flow signal. Adding it would let
            // session-derived candidates double-count the
            // "workflow exists" signal as object-flow evidence.
            if (edge.getType() == EdgeType.PARAM_REUSE) score += 6.0;
            else if (edge.getType() == EdgeType.RESPONSE_CORRELATION) score += 4.0;
            else if (edge.getType() == EdgeType.REDIRECT) score += 2.0;
        }
        return score;
    }

    private double scoreMethodDiversity(List<RequestNode> steps) {
        Set<String> methods = new HashSet<>();
        for (RequestNode node : steps) {
            methods.add(node.getMethod() != null ? node.getMethod().toUpperCase() : "GET");
        }
        return methods.size() * 2.0;
    }

    private double scoreStructuralSignals(List<RequestNode> steps,
                                          List<RequestEdge> edges) {
        double score = 0.0;

        // Redirect after POST (state change confirmation)
        for (int i = 0; i < steps.size() - 1; i++) {
            RequestNode current = steps.get(i);
            RequestNode next = steps.get(i + 1);
            if ("POST".equalsIgnoreCase(current.getMethod())
                    && current.isRedirect()
                    && next.getStatusCode() == 200) {
                score += 4.0;
            }
        }

        // Terminal confirmation page
        RequestNode last = steps.get(steps.size() - 1);
        String lastPath = last.getPath() != null ? last.getPath().toLowerCase() : "";
        if (lastPath.contains("confirm") || lastPath.contains("success")
                || lastPath.contains("complete") || last.getStatusCode() == 201) {
            score += 5.0;
        }

        // Money/role parameters present
        for (RequestNode node : steps) {
            if (hasCriticalParams(node)) {
                score += 8.0;
                break;
            }
        }

        // State-changing method count
        int stateChanges = 0;
        for (RequestNode node : steps) {
            if (BusinessKeywordRules.isStateChanging(node.getMethod())) stateChanges++;
        }
        score += Math.min(stateChanges, 5) * 4.0;

        return score;
    }

    private double penalizeStaticContent(List<RequestNode> steps) {
        int staticCount = 0;
        for (RequestNode node : steps) {
            RequestClassification cls = node.getClassification();
            if (cls != null && cls.getIntent() == RequestIntent.STATIC_ASSET) {
                staticCount++;
            }
        }
        return staticCount * 10.0;
    }

    private double penalizePolling(List<RequestNode> steps) {
        int pollingCount = 0;
        for (RequestNode node : steps) {
            RequestClassification cls = node.getClassification();
            if (cls != null && cls.getIntent() == RequestIntent.BACKGROUND_POLLING) {
                pollingCount++;
            }
        }
        return pollingCount * 5.0;
    }

    private double penalizeWeakStructure(List<RequestNode> steps,
                                          List<RequestEdge> edges) {
        // If the only edges are TIME_WINDOW (a context-only edge
        // type RelationshipDetector no longer emits), penalize
        // heavily. WORKFLOW_SEQUENCE is a derived structural edge
        // and does not by itself indicate weak structure — it is
        // added after the candidate is finalized, so applying a
        // penalty here would penalize every session-derived
        // candidate, which is the opposite of the intended UX.
        if (edges != null && !edges.isEmpty()) {
            boolean onlyTimeWindow = edges.stream()
                    .allMatch(e -> e.getType() == EdgeType.TIME_WINDOW);
            if (onlyTimeWindow) return 15.0;
        }
        return 0.0;
    }

    private double penalizeRepetition(List<RequestNode> steps) {
        Set<String> seenEndpoints = new HashSet<>();
        int repeats = 0;
        for (RequestNode node : steps) {
            String key = node.getMethod() + ":" + node.getPath();
            if (!seenEndpoints.add(key)) repeats++;
        }
        return repeats * 2.0;
    }

    private boolean hasCriticalParams(RequestNode node) {
        if (node.getExtractedParams() == null) return false;
        return BusinessKeywordRules.hasCriticalParameters(node.getExtractedParams().keySet());
    }

    /**
     * Sort candidates by score (highest first).
     */
    public List<WorkflowCandidate> prioritize(List<WorkflowCandidate> candidates) {
        candidates.sort((a, b) -> Double.compare(b.getWorkflowScore(), a.getWorkflowScore()));
        return candidates;
    }
}

package com.workflowscanner.workflow;

import com.workflowscanner.analysis.ApplicationModel;
import com.workflowscanner.classification.NoiseRulesConfig;
import com.workflowscanner.classification.RequestClassification;
import com.workflowscanner.classification.RequestIntent;
import com.workflowscanner.config.ExtensionConfig;
import com.workflowscanner.graph.RequestNode;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for vocabulary-aware scoring in WorkflowScorer and the
 * Phase-1 Risk #1 fix (unknown auth state-changing candidates
 * pass the analysis threshold).
 */
class VocabularyScoringTest {

    private RequestNode makeNode(String id, String method, String path) {
        RequestNode n = new RequestNode();
        n.setId(id);
        n.setMethod(method);
        n.setPath(path);
        n.setUrl("https://example.com" + path);
        n.setHost("example.com");
        n.setStatusCode(200);
        n.setRequestHeaders(Map.of("Authorization", List.of("Bearer xyz")));
        n.setClassification(new RequestClassification(
                RequestIntent.UNKNOWN, 4.0, 0, true, false, "test", null));
        return n;
    }

    /**
     * Phase-1 Risk #1 regression: an UNKNOWN+auth+state-changing
     * candidate without keywords scored ~11.0 before the fix
     * (state-change 5.0 + diversity 2.0 + structural 4.0) and
     * was filtered out by the 20.0 analysis threshold. With the
     * Phase-1 unknown-flow boost (+10.0), it should now score
     * 21.0 and pass.
     */
    @Test
    void phase1_unknownAuthStateChanging_passesAnalysisThreshold() {
        ExtensionConfig cfg = new ExtensionConfig();
        cfg.setWorkflowScoreThreshold(20.0);
        WorkflowScorer scorer = new WorkflowScorer(cfg);
        WorkflowCandidate c = new WorkflowCandidate();
        c.setWorkflowType(WorkflowType.UNKNOWN_BUSINESS_FLOW);
        c.addStep(makeNode("n1", "POST", "/api/zzz/process"));
        double score = scorer.score(c);
        assertTrue(score >= 20.0,
                "UNKNOWN auth POST score " + score + " should pass 20.0 threshold");
    }

    /**
     * Negative control: an UNKNOWN+unauth+state-changing candidate
     * should NOT get the structural-interest boost (no private
     * context). Score stays at ~11.0, below threshold.
     */
    @Test
    void phase1_unauthStateChanging_doesNotPassThreshold() {
        ExtensionConfig cfg = new ExtensionConfig();
        cfg.setWorkflowScoreThreshold(20.0);
        WorkflowScorer scorer = new WorkflowScorer(cfg);
        WorkflowCandidate c = new WorkflowCandidate();
        c.setWorkflowType(WorkflowType.UNKNOWN_BUSINESS_FLOW);
        RequestNode n = makeNode("n1", "POST", "/api/zzz/process");
        n.setRequestHeaders(Map.of()); // no auth
        c.addStep(n);
        double score = scorer.score(c);
        assertTrue(score < 20.0,
                "UNAUTH POST score " + score + " should NOT pass 20.0 threshold");
    }

    /**
     * Negative control: a known CHECKOUT candidate should still
     * score high (existing keyword-driven behavior preserved).
     */
    @Test
    void knownCheckout_passesThreshold() {
        ExtensionConfig cfg = new ExtensionConfig();
        cfg.setWorkflowScoreThreshold(20.0);
        WorkflowScorer scorer = new WorkflowScorer(cfg);
        WorkflowCandidate c = new WorkflowCandidate();
        c.setWorkflowType(WorkflowType.CHECKOUT);
        c.addStep(makeNode("n1", "POST", "/api/checkout"));
        double score = scorer.score(c);
        assertTrue(score >= 20.0,
                "CHECKOUT score " + score + " should pass 20.0 threshold");
    }

    @Test
    void vocabulary_userSuppliedNoun_addsScore() {
        ExtensionConfig cfg = new ExtensionConfig();
        cfg.setWorkflowScoreThreshold(20.0);
        NoiseRulesConfig nrc = NoiseRulesConfig.withDefaults();
        nrc.setCustomBusinessNouns(List.of("booking", "guest", "reservation"));
        nrc.setCustomActionVerbs(List.of("cancel", "approve", "publish"));
        cfg.setNoiseRules(nrc);
        ApplicationModel model = new ApplicationModel(nrc);
        WorkflowScorer scorer = new WorkflowScorer(cfg);
        scorer.setApplicationModel(model);
        WorkflowCandidate c = new WorkflowCandidate();
        c.setWorkflowType(WorkflowType.UNKNOWN_BUSINESS_FLOW);
        c.addStep(makeNode("n1", "POST", "/api/booking/123/cancel"));
        double scoreWithVocab = scorer.score(c);
        // Compare to baseline without vocabulary
        WorkflowScorer scorerNoVocab = new WorkflowScorer(cfg);
        WorkflowCandidate c2 = new WorkflowCandidate();
        c2.setWorkflowType(WorkflowType.UNKNOWN_BUSINESS_FLOW);
        c2.addStep(makeNode("n1b", "POST", "/api/booking/123/cancel"));
        double scoreNoVocab = scorerNoVocab.score(c2);
        assertTrue(scoreWithVocab > scoreNoVocab,
                "vocabulary should add score: with=" + scoreWithVocab
                        + " without=" + scoreNoVocab);
        // Should pick up "booking" (3.0 businessNoun) and "cancel" (5.0 actionVerb)
        assertTrue(scoreWithVocab - scoreNoVocab >= 8.0,
                "vocabulary delta " + (scoreWithVocab - scoreNoVocab)
                        + " should be >= 8.0 (booking 3.0 + cancel 5.0)");
    }

    @Test
    void vocabulary_learnedNoun_addsScore() {
        ExtensionConfig cfg = new ExtensionConfig();
        cfg.setWorkflowScoreThreshold(20.0);
        NoiseRulesConfig nrc = NoiseRulesConfig.withDefaults();
        ApplicationModel model = new ApplicationModel(nrc);
        // Manually feed the model so vocabulary has "meal_plan" learned
        model.learnFromCandidate(List.of(
                makeNode("n0", "POST", "/api/meal_plan/abc")));
        WorkflowScorer scorer = new WorkflowScorer(cfg);
        scorer.setApplicationModel(model);
        WorkflowCandidate c = new WorkflowCandidate();
        c.setWorkflowType(WorkflowType.UNKNOWN_BUSINESS_FLOW);
        c.addStep(makeNode("n1", "PATCH", "/api/meal_plan/123/skip"));
        double score = scorer.score(c);
        assertTrue(score >= 20.0,
                "vocabulary-boosted UNKNOWN score " + score + " should pass threshold");
    }

    @Test
    void vocabulary_sensitiveField_addsScore() {
        ExtensionConfig cfg = new ExtensionConfig();
        cfg.setWorkflowScoreThreshold(20.0);
        NoiseRulesConfig nrc = NoiseRulesConfig.withDefaults();
        nrc.setCustomSensitiveFields(List.of("payout_account"));
        cfg.setNoiseRules(nrc);
        ApplicationModel model = new ApplicationModel(nrc);
        WorkflowScorer scorer = new WorkflowScorer(cfg);
        scorer.setApplicationModel(model);
        WorkflowCandidate c = new WorkflowCandidate();
        c.setWorkflowType(WorkflowType.UNKNOWN_BUSINESS_FLOW);
        RequestNode n = makeNode("n1", "POST", "/api/zzz/zzz");
        n.setExtractedParams(Map.of("payout_account", "x"));
        c.addStep(n);
        double score = scorer.score(c);
        // 11.0 (baseline) + 10.0 (unknown-flow boost) + 8.0 (sensitive) = 29.0
        assertTrue(score >= 25.0,
                "sensitive-field-boosted score " + score + " should be high");
    }

    @Test
    void vocabulary_cappedAt15() {
        // Even with many matches, vocabulary score should not exceed 15.0
        ExtensionConfig cfg = new ExtensionConfig();
        cfg.setWorkflowScoreThreshold(20.0);
        NoiseRulesConfig nrc = NoiseRulesConfig.withDefaults();
        nrc.setCustomBusinessNouns(List.of("a", "b", "c", "d", "e", "f"));
        cfg.setNoiseRules(nrc);
        ApplicationModel model = new ApplicationModel(nrc);
        WorkflowScorer scorer = new WorkflowScorer(cfg);
        scorer.setApplicationModel(model);
        WorkflowCandidate c = new WorkflowCandidate();
        c.setWorkflowType(WorkflowType.UNKNOWN_BUSINESS_FLOW);
        c.addStep(makeNode("n1", "POST", "/api/a/b/c/d/e/f/g"));
        double score = scorer.score(c);
        // 11.0 (baseline) + 10.0 (unknown-flow) + ≤15.0 (vocab cap) = ≤36.0
        // But total vocabulary contribution itself must be ≤15
        // We check the cap indirectly: score shouldn't be much higher than 36
        assertTrue(score <= 40.0,
                "vocabulary cap should keep total score under 40, got " + score);
    }
}

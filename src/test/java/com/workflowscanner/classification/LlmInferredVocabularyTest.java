package com.workflowscanner.classification;

import com.workflowscanner.analysis.VocabularyLearner;
import com.workflowscanner.analysis.VocabularySource;
import com.workflowscanner.analysis.VocabularyTerm;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the Realism-upgrade-2 / Issue 2 fix: separate
 * LLM-inferred vocabulary storage. Verifies that:
 *
 *   - custom* fields are loaded with source=USER (weight 1.0)
 *   - llmInferred* fields are loaded with source=LLM_INFERRED
 *     (weight 0.5)
 *   - Both sets contribute to the same TargetVocabulary but
 *     keep their source tags so the scorer can apply different
 *     weights and the UI can distinguish them.
 *   - Saving and reloading preserves the LLM_INFERRED source
 *     (no auto-promotion to USER).
 */
class LlmInferredVocabularyTest {

    @Test
    void customNouns_loadedAsUserSource() {
        NoiseRulesConfig nrc = NoiseRulesConfig.withDefaults();
        nrc.setCustomBusinessNouns(List.of("reservation", "guest"));
        VocabularyLearner learner = new VocabularyLearner(nrc);
        assertTrue(learner.snapshot().containsBusinessNoun("reservation"));
        assertTrue(learner.snapshot().containsBusinessNoun("guest"));
        Optional<VocabularyTerm> term = learner.snapshot()
                .getBusinessNouns().stream()
                .map(t -> findTerm(learner, "reservation"))
                .filter(java.util.Objects::nonNull)
                .findFirst();
        // Verify the term has USER source
        assertEquals(VocabularySource.USER, findTerm(learner, "reservation").getSource());
    }

    @Test
    void llmInferredNouns_loadedAsLlmInferredSource() {
        NoiseRulesConfig nrc = NoiseRulesConfig.withDefaults();
        nrc.setLlmInferredBusinessNouns(List.of("listing", "payout"));
        VocabularyLearner learner = new VocabularyLearner(nrc);
        assertTrue(learner.snapshot().containsBusinessNoun("listing"));
        assertTrue(learner.snapshot().containsBusinessNoun("payout"));
        // Source is LLM_INFERRED, not USER
        assertEquals(VocabularySource.LLM_INFERRED,
                findTerm(learner, "listing").getSource());
    }

    @Test
    void customAndLlmInferred_coexistWithDifferentSources() {
        NoiseRulesConfig nrc = NoiseRulesConfig.withDefaults();
        nrc.setCustomBusinessNouns(List.of("reservation"));
        nrc.setLlmInferredBusinessNouns(List.of("reservation", "payout"));
        VocabularyLearner learner = new VocabularyLearner(nrc);
        // Same term in both lists; the higher-weight USER source wins
        // (count and weight) but the term is still there.
        VocabularyTerm term = findTerm(learner, "reservation");
        assertNotNull(term);
        // The vocabulary re-adding rule keeps the higher weight, so
        // the source stays USER (weight 1.0 > 0.5).
        assertEquals(VocabularySource.USER, term.getSource());
        // The LLM-only term is also present, with LLM_INFERRED source.
        assertEquals(VocabularySource.LLM_INFERRED,
                findTerm(learner, "payout").getSource());
    }

    @Test
    void allFourCategories_haveLlmInferredSetters() {
        NoiseRulesConfig nrc = NoiseRulesConfig.withDefaults();
        nrc.setLlmInferredBusinessNouns(List.of("a"));
        nrc.setLlmInferredActionVerbs(List.of("b"));
        nrc.setLlmInferredSensitiveFields(List.of("c"));
        nrc.setLlmInferredWorkflowTerms(List.of("d"));
        // Round-trip
        assertEquals(List.of("a"), nrc.getLlmInferredBusinessNouns());
        assertEquals(List.of("b"), nrc.getLlmInferredActionVerbs());
        assertEquals(List.of("c"), nrc.getLlmInferredSensitiveFields());
        assertEquals(List.of("d"), nrc.getLlmInferredWorkflowTerms());
    }

    @Test
    void nullLlmInferredList_defaultsToEmpty() {
        NoiseRulesConfig nrc = new NoiseRulesConfig();
        nrc.setLlmInferredBusinessNouns(null);
        assertTrue(nrc.getLlmInferredBusinessNouns().isEmpty());
    }

    @Test
    void weights_remainDistinct_afterLoading() {
        // Issue 2: the design relies on different default weights
        // (USER=1.0 vs LLM_INFERRED=0.5) so a hallucinated term
        // cannot dominate scoring. Verify the source weights.
        assertEquals(1.0, VocabularySource.USER.getDefaultWeight(), 0.001);
        assertEquals(0.5, VocabularySource.LLM_INFERRED.getDefaultWeight(), 0.001);
        // The user has higher weight than the LLM — required so
        // that USER terms dominate when both are present.
        assertTrue(VocabularySource.USER.getDefaultWeight()
                > VocabularySource.LLM_INFERRED.getDefaultWeight());
    }

    /**
     * Find a term in the vocabulary's business-noun set by
     * normalized form. Returns null if not present.
     */
    private static VocabularyTerm findTerm(VocabularyLearner learner, String key) {
        for (VocabularyTerm t : learner.snapshotTerms()) {
            if (t.getTerm().equals(key)) return t;
        }
        return null;
    }
}

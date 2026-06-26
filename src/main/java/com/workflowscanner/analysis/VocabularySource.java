package com.workflowscanner.analysis;

/**
 * Source of a vocabulary term.
 *
 * <p>Used by the reportability gate and the LLM prompt builder to
 * weigh terms by trust. Static-seed terms are coarse but stable;
 * learned terms are fine-grained and target-specific; user terms
 * have the highest trust (the user explicitly listed them);
 * LLM-inferred terms are deferred to a later pass.
 */
public enum VocabularySource {

    /** Built-in keyword list (e.g. BUSINESS_NOUNS in BusinessKeywordRules). */
    STATIC_SEED(0.6),

    /** Extracted from observed traffic by VocabularyLearner. */
    LEARNED(0.7),

    /** User-supplied via NoiseRulesConfig.custom* fields. */
    USER(1.0),

    /** Inferred by the LLM from the endpoint inventory. */
    LLM_INFERRED(0.5);

    private final double defaultWeight;

    VocabularySource(double defaultWeight) {
        this.defaultWeight = defaultWeight;
    }

    public double getDefaultWeight() {
        return defaultWeight;
    }
}

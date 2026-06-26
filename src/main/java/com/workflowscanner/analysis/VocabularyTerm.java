package com.workflowscanner.analysis;

import java.util.Objects;

/**
 * A single term in the target vocabulary.
 *
 * <p>Immutable. The {@code count} is the number of times the term
 * has been observed; {@code weight} is the scoring contribution
 * when the term matches a request path or parameter.
 *
 * <p>Equality is by term text (case-insensitive) so duplicates
 * collapse during learning.
 */
public final class VocabularyTerm {

    private final String term;
    private final VocabularySource source;
    private final int count;
    private final double weight;

    public VocabularyTerm(String term, VocabularySource source, int count, double weight) {
        this.term = Objects.requireNonNull(term, "term").toLowerCase();
        this.source = Objects.requireNonNull(source, "source");
        this.count = Math.max(0, count);
        this.weight = Math.max(0.0, weight);
    }

    public String getTerm() { return term; }
    public VocabularySource getSource() { return source; }
    public int getCount() { return count; }
    public double getWeight() { return weight; }

    public VocabularyTerm withIncrementedCount() {
        return new VocabularyTerm(term, source, count + 1, weight);
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof VocabularyTerm)) return false;
        return term.equals(((VocabularyTerm) o).term);
    }

    @Override
    public int hashCode() {
        return term.hashCode();
    }

    @Override
    public String toString() {
        return term + ":" + source.name() + "x" + count + "w" + String.format("%.2f", weight);
    }
}

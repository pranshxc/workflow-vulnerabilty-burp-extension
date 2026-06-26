package com.workflowscanner.analysis;

import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-target vocabulary learned from observed traffic and user
 * configuration. Thread-safe; observed concurrently from the
 * analysis pipeline and read concurrently from the scorer and
 * the LLM prompt builder.
 *
 * <p>Four categories, each a map from lower-case term to
 * {@link VocabularyTerm}:
 * <ul>
 *   <li>{@link #businessNouns} — terms found in endpoint paths
 *       (e.g. "reservation", "payout", "beneficiary", "meal_plan").
 *       These are the business objects of the target domain.</li>
 *   <li>{@link #actionVerbs} — terms found as the last segment of
 *       state-changing endpoints (e.g. "cancel", "approve",
 *       "sign", "publish").</li>
 *   <li>{@link #sensitiveFields} — parameter or JSON keys that
 *       match sensitive patterns (e.g. "payout_account",
 *       "ssn", "delivery_address", "tenant_id").</li>
 *   <li>{@link #workflowTerms} — generic catch-all for terms that
 *       appear frequently in workflow-relevant requests but do
 *       not match the other three categories.</li>
 * </ul>
 *
 * <p>Static seed lists (built-in keyword sets) are stored in
 * BusinessKeywordRules and treated as a separate source. The
 * vocabulary learner adds LEARNED terms; user configuration
 * adds USER terms. {@code contains} checks any of the four
 * categories.
 */
public class TargetVocabulary {

    private final ConcurrentHashMap<String, VocabularyTerm> businessNouns = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, VocabularyTerm> actionVerbs = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, VocabularyTerm> sensitiveFields = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, VocabularyTerm> workflowTerms = new ConcurrentHashMap<>();

    public void addBusinessNoun(String term, VocabularySource source) {
        addToMap(businessNouns, term, source);
    }

    public void addActionVerb(String term, VocabularySource source) {
        addToMap(actionVerbs, term, source);
    }

    public void addSensitiveField(String term, VocabularySource source) {
        addToMap(sensitiveFields, term, source);
    }

    public void addWorkflowTerm(String term, VocabularySource source) {
        addToMap(workflowTerms, term, source);
    }

    private void addToMap(ConcurrentHashMap<String, VocabularyTerm> map,
                          String term, VocabularySource source) {
        if (term == null || term.isEmpty()) return;
        String key = term.toLowerCase();
        map.compute(key, (k, existing) -> {
            if (existing == null) {
                return new VocabularyTerm(key, source, 1, source.getDefaultWeight());
            }
            // Existing term — increment count, keep higher weight
            int newCount = existing.getCount() + 1;
            double newWeight = Math.max(existing.getWeight(), source.getDefaultWeight());
            return new VocabularyTerm(key, existing.getSource(), newCount, newWeight);
        });
    }

    public boolean containsBusinessNoun(String term) {
        return term != null && businessNouns.containsKey(term.toLowerCase());
    }

    public boolean containsActionVerb(String term) {
        return term != null && actionVerbs.containsKey(term.toLowerCase());
    }

    public boolean containsSensitiveField(String term) {
        return term != null && sensitiveFields.containsKey(term.toLowerCase());
    }

    public boolean containsWorkflowTerm(String term) {
        return term != null && workflowTerms.containsKey(term.toLowerCase());
    }

    public boolean containsAny(String term) {
        if (term == null) return false;
        String key = term.toLowerCase();
        return businessNouns.containsKey(key)
                || actionVerbs.containsKey(key)
                || sensitiveFields.containsKey(key)
                || workflowTerms.containsKey(key);
    }

    public Set<String> getBusinessNouns() {
        return Collections.unmodifiableSet(businessNouns.keySet());
    }

    public Set<String> getActionVerbs() {
        return Collections.unmodifiableSet(actionVerbs.keySet());
    }

    public Set<String> getSensitiveFields() {
        return Collections.unmodifiableSet(sensitiveFields.keySet());
    }

    public Set<String> getWorkflowTerms() {
        return Collections.unmodifiableSet(workflowTerms.keySet());
    }

    public int size() {
        return businessNouns.size() + actionVerbs.size()
                + sensitiveFields.size() + workflowTerms.size();
    }

    /**
     * Render a compact summary suitable for inclusion in the LLM
     * system prompt so the LLM understands the target domain.
     */
    public String toPromptContext() {
        if (size() == 0) return "(no target vocabulary learned yet)";
        StringBuilder sb = new StringBuilder();
        appendSection(sb, "Business objects", businessNouns);
        appendSection(sb, "Workflow actions", actionVerbs);
        appendSection(sb, "Sensitive fields", sensitiveFields);
        appendSection(sb, "Other workflow terms", workflowTerms);
        return sb.toString();
    }

    private void appendSection(StringBuilder sb, String label,
                                ConcurrentHashMap<String, VocabularyTerm> map) {
        if (map.isEmpty()) return;
        sb.append(label).append(" (").append(map.size()).append("): ");
        // Sort by count desc, then term asc — stable, deterministic
        map.values().stream()
                .sorted((a, b) -> {
                    int c = Integer.compare(b.getCount(), a.getCount());
                    return c != 0 ? c : a.getTerm().compareTo(b.getTerm());
                })
                .limit(20)
                .forEach(t -> sb.append(t.getTerm()).append("(")
                        .append(t.getCount()).append(") "));
        sb.append("\n");
    }
}

package com.workflowscanner.analysis;

import com.workflowscanner.classification.NoiseRulesConfig;
import com.workflowscanner.classification.PrivateContextDetector;
import com.workflowscanner.graph.RequestNode;
import com.workflowscanner.workflow.WorkflowCandidate;

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Observes request nodes and workflow candidates, extracts
 * target-specific vocabulary terms, and stores them in a
 * {@link TargetVocabulary}.
 *
 * <p>Source preference:
 * <ol>
 *   <li>USER — user-supplied via {@link NoiseRulesConfig#customBusinessNouns}
 *       and friends. Loaded once at construction.</li>
 *   <li>LEARNED — extracted from observed traffic. Updated on
 *       each observe() call.</li>
 * </ol>
 * The static seed (built-in keyword lists in BusinessKeywordRules)
 * is treated separately as a scoring source, not stored here.
 *
 * <p>Categorization rules (heuristic, not ground truth):
 * <ul>
 *   <li>Path segment (not last) → businessNouns (e.g. "reservation",
 *       "payout", "meal_plan").</li>
 *   <li>Path segment (last) on POST/PATCH/DELETE → actionVerbs
 *       (e.g. "cancel", "approve", "sign").</li>
 *   <li>Path segment (last) on GET/HEAD → businessNouns
 *       (e.g. "details", "summary").</li>
 *   <li>Parameter or JSON key matching a sensitive pattern →
 *       sensitiveFields (e.g. "ssn", "payout_account", "tenant_id").</li>
 *   <li>Other frequently-seen terms → workflowTerms.</li>
 * </ul>
 *
 * <p>Noise filtering: only requests that are workflow-relevant
 * OR auth-bound OR state-changing are observed. Pure telemetry,
 * static assets, and source maps are ignored.
 */
public class VocabularyLearner {

    /** Substrings that flag a parameter name as sensitive. */
    private static final Pattern SENSITIVE_FIELD_PATTERN = Pattern.compile(
            "(?i).*(" +
                    "amount|price|cost|total|subtotal|tax|shipping|discount|fee|" +
                    "charge|balance|credit|debit|wallet|payout|revenue|rate|" +
                    "role|permission|privilege|access|admin|owner|tenant|org|" +
                    "account_id|user_id|customer_id|beneficiary_id|" +
                    "ssn|tax_id|dob|birthdate|passport|license|drivers|" +
                    "email|phone|mobile|address|street|zip|postal|country|" +
                    "password|secret|token|key|api_key|auth|signature" +
                    ").*"
    );

    private static final Set<String> STATE_CHANGING_METHODS = Set.of(
            "POST", "PUT", "PATCH", "DELETE");

    private final TargetVocabulary vocabulary = new TargetVocabulary();
    private final PrivateContextDetector privateContextDetector;

    public VocabularyLearner(NoiseRulesConfig noiseConfig) {
        NoiseRulesConfig nrc = noiseConfig != null
                ? noiseConfig : NoiseRulesConfig.withDefaults();
        this.privateContextDetector = new PrivateContextDetector(nrc);
        loadUserVocabulary(nrc);
    }

    private void loadUserVocabulary(NoiseRulesConfig nrc) {
        if (nrc.getCustomBusinessNouns() != null) {
            for (String term : nrc.getCustomBusinessNouns()) {
                for (String normalized : TokenNormalizer.normalize(term)) {
                    vocabulary.addBusinessNoun(normalized, VocabularySource.USER);
                }
            }
        }
        if (nrc.getCustomActionVerbs() != null) {
            for (String term : nrc.getCustomActionVerbs()) {
                for (String normalized : TokenNormalizer.normalize(term)) {
                    vocabulary.addActionVerb(normalized, VocabularySource.USER);
                }
            }
        }
        if (nrc.getCustomSensitiveFields() != null) {
            for (String term : nrc.getCustomSensitiveFields()) {
                for (String normalized : TokenNormalizer.normalize(term)) {
                    vocabulary.addSensitiveField(normalized, VocabularySource.USER);
                }
            }
        }
        if (nrc.getCustomWorkflowTerms() != null) {
            for (String term : nrc.getCustomWorkflowTerms()) {
                for (String normalized : TokenNormalizer.normalize(term)) {
                    vocabulary.addWorkflowTerm(normalized, VocabularySource.USER);
                }
            }
        }
    }

    /**
     * Observe a single request node. No-op for noise / non-workflow
     * requests so the vocabulary does not get polluted with
     * telemetry, static assets, or public-data lookups.
     */
    public void observe(RequestNode node) {
        if (node == null) return;
        if (!isObservantable(node)) return;
        learnFromPath(node);
        learnFromParams(node);
        learnFromResponseData(node);
    }

    /**
     * Observe all steps of a workflow candidate. Used by the
     * analysis pipeline after a candidate is finalized so the
     * vocabulary captures confirmed workflow terms.
     */
    public void observe(WorkflowCandidate candidate) {
        if (candidate == null || candidate.getSteps() == null) return;
        for (RequestNode n : candidate.getSteps()) {
            observe(n);
        }
    }

    public TargetVocabulary snapshot() {
        return vocabulary;
    }

    private boolean isObservantable(RequestNode node) {
        // Auth-bound or state-changing or workflow-relevant
        if (privateContextDetector.hasPrivateContext(node)) return true;
        String m = node.getMethod();
        if (m != null) {
            String upper = m.toUpperCase(Locale.ROOT);
            if (STATE_CHANGING_METHODS.contains(upper)) return true;
        }
        return false;
    }

    private void learnFromPath(RequestNode node) {
        String path = node.getPath();
        if (path == null) return;
        List<String> tokens = TokenNormalizer.normalizePath(path);
        if (tokens.isEmpty()) return;
        boolean stateChanging = isStateChanging(node.getMethod());

        // Find the boundary between path and tail. A numeric
        // segment in the original path marks the start of the
        // "tail" (the part after the object ID). Tokens before
        // the boundary are the object collection (businessNouns).
        // The first token after the boundary is the action verb
        // (on state-changing) or a sub-resource (on GET). Tokens
        // deeper than that are nouns (e.g. /bookings/123/cancel/
        // comment — "comment" is a noun).
        int boundary = findNumericBoundary(path);
        if (boundary < 0) {
            // No numeric ID — treat as a flat path. All tokens
            // are businessNouns except the last, which is a verb
            // on state-changing.
            for (int i = 0; i < tokens.size(); i++) {
                String t = tokens.get(i);
                if (t.isEmpty()) continue;
                if (stateChanging && i == tokens.size() - 1) {
                    vocabulary.addActionVerb(t, VocabularySource.LEARNED);
                } else {
                    vocabulary.addBusinessNoun(t, VocabularySource.LEARNED);
                }
            }
            return;
        }

        for (int i = 0; i < tokens.size(); i++) {
            String t = tokens.get(i);
            if (t.isEmpty()) continue;
            if (i < boundary) {
                // Path side: object collection noun
                vocabulary.addBusinessNoun(t, VocabularySource.LEARNED);
            } else if (i == boundary) {
                // First token after the ID: action verb on
                // state-changing, sub-resource noun on GET.
                if (stateChanging) {
                    vocabulary.addActionVerb(t, VocabularySource.LEARNED);
                } else {
                    vocabulary.addBusinessNoun(t, VocabularySource.LEARNED);
                }
            } else {
                // Deeper tail: always a noun
                vocabulary.addBusinessNoun(t, VocabularySource.LEARNED);
            }
        }
    }

    /**
     * Find the index of the first numeric segment in the path's
     * normalized tokens, or -1 if there is no numeric segment.
     * Numeric segments mark the boundary between the object
     * collection path and the resource/action tail.
     */
    private static int findNumericBoundary(String path) {
        if (path == null) return -1;
        String[] segs = path.split("/");
        int tokIdx = 0;
        for (int i = 0; i < segs.length; i++) {
            String seg = segs[i];
            if (seg.isEmpty()) continue;
            if (isSegmentNumeric(seg)) return tokIdx;
            // Only count segments that survive normalization
            List<String> norm = TokenNormalizer.normalize(seg);
            if (!norm.isEmpty()) tokIdx++;
        }
        return -1;
    }

    private static boolean isSegmentNumeric(String seg) {
        if (seg == null || seg.isEmpty()) return false;
        for (int i = 0; i < seg.length(); i++) {
            if (!Character.isDigit(seg.charAt(i))) return false;
        }
        return true;
    }

    private void learnFromParams(RequestNode node) {
        Map<String, Object> params = node.getExtractedParams();
        if (params == null || params.isEmpty()) return;
        for (String key : params.keySet()) {
            if (key == null) continue;
            // Strip any "param." prefix that some classifiers use
            String cleanKey = key.startsWith("param.") ? key.substring(6) : key;
            for (String token : TokenNormalizer.normalize(cleanKey)) {
                if (SENSITIVE_FIELD_PATTERN.matcher(token).matches()) {
                    vocabulary.addSensitiveField(token, VocabularySource.LEARNED);
                } else {
                    vocabulary.addWorkflowTerm(token, VocabularySource.LEARNED);
                }
            }
        }
    }

    private void learnFromResponseData(RequestNode node) {
        Map<String, Object> data = node.getResponseData();
        if (data == null || data.isEmpty()) return;
        for (String key : data.keySet()) {
            if (key == null) continue;
            for (String token : TokenNormalizer.normalize(key)) {
                if (SENSITIVE_FIELD_PATTERN.matcher(token).matches()) {
                    vocabulary.addSensitiveField(token, VocabularySource.LEARNED);
                } else {
                    vocabulary.addWorkflowTerm(token, VocabularySource.LEARNED);
                }
            }
        }
    }

    private static boolean isStateChanging(String method) {
        if (method == null) return false;
        return STATE_CHANGING_METHODS.contains(method.toUpperCase(Locale.ROOT));
    }

    /** For tests: how many terms the vocabulary currently holds. */
    public int size() {
        return vocabulary.size();
    }

    /** For tests: a set of all learned terms (case-insensitive). */
    public Set<String> allTerms() {
        Set<String> out = new HashSet<>();
        out.addAll(vocabulary.getBusinessNouns());
        out.addAll(vocabulary.getActionVerbs());
        out.addAll(vocabulary.getSensitiveFields());
        out.addAll(vocabulary.getWorkflowTerms());
        return out;
    }
}

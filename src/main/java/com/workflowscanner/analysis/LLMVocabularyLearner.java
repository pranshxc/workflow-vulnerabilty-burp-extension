package com.workflowscanner.analysis;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.workflowscanner.classification.EndpointKey;
import com.workflowscanner.config.ExtensionConfig;
import com.workflowscanner.graph.RequestGraph;
import com.workflowscanner.graph.RequestNode;
import com.workflowscanner.llm.LLMClient;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Realism-upgrade-2 / LLM-assisted vocabulary learning.
 *
 * <p>Runs ONCE (manually or after enough captured traffic) and
 * asks the configured LLM to infer the target application's
 * domain vocabulary from a compact endpoint inventory. The LLM
 * does not see request bodies or PII — only path templates,
 * method names, and a small sample of response keys. The
 * returned terms are merged into the TargetVocabulary with
 * source=LLM_INFERRED (default weight 0.5 — lower than
 * USER, STATIC_SEED, or LEARNED so hallucinations cannot
 * dominate scoring).
 *
 * <p>The prompt explicitly forbids vulnerability speculation.
 * The LLM is asked to identify the domain, not the bugs.
 */
public class LLMVocabularyLearner {

    private static final Pattern TEMPLATE_TOKEN = Pattern.compile("\\{[^}]*\\}");

    private final LLMClient llmClient;
    private final ExtensionConfig config;
    private final ExtensionLogger logger;

    public LLMVocabularyLearner(LLMClient llmClient,
                                 ExtensionConfig config,
                                 ExtensionLogger logger) {
        this.llmClient = llmClient;
        this.config = config;
        this.logger = logger;
    }

    /**
     * Container for the terms the LLM inferred. Empty
     * lists mean "the LLM had nothing to add for that
     * category".
     */
    public static class VocabularyUpdate {
        public final List<String> businessNouns;
        public final List<String> actionVerbs;
        public final List<String> sensitiveFields;
        public final List<String> workflowTerms;
        public final List<String> stateTerms;
        public final List<String> actors;

        public VocabularyUpdate(List<String> businessNouns,
                                 List<String> actionVerbs,
                                 List<String> sensitiveFields,
                                 List<String> workflowTerms,
                                 List<String> stateTerms,
                                 List<String> actors) {
            this.businessNouns = businessNouns;
            this.actionVerbs = actionVerbs;
            this.sensitiveFields = sensitiveFields;
            this.workflowTerms = workflowTerms;
            this.stateTerms = stateTerms;
            this.actors = actors;
        }

        public boolean isEmpty() {
            return businessNouns.isEmpty()
                    && actionVerbs.isEmpty()
                    && sensitiveFields.isEmpty()
                    && workflowTerms.isEmpty()
                    && stateTerms.isEmpty()
                    && actors.isEmpty();
        }

        public int size() {
            return businessNouns.size() + actionVerbs.size()
                    + sensitiveFields.size() + workflowTerms.size()
                    + stateTerms.size() + actors.size();
        }
    }

    /**
     * Ask the LLM to infer the target's domain vocabulary.
     *
     * <p>Builds a compact endpoint inventory from the current
     * graph (path templates, methods, sample response keys),
     * calls the LLM, parses the JSON response, and returns
     * a {@link VocabularyUpdate} the caller can apply.
     *
     * <p>Safe to call with an empty graph — returns an
     * empty update.
     */
    public VocabularyUpdate learnFromEndpointInventory(RequestGraph graph,
                                                       int maxEndpoints) {
        if (graph == null) {
            return emptyUpdate();
        }
        Map<String, RequestNode> nodes = graph.getNodes();
        if (nodes == null || nodes.isEmpty()) {
            return emptyUpdate();
        }

        // Build a deduplicated inventory of path templates.
        Map<String, EndpointRow> inventory = new HashMap<>();
        int sampleBudget = 0;
        for (RequestNode node : nodes.values()) {
            String method = node.getMethod() == null ? "GET" : node.getMethod().toUpperCase(Locale.ROOT);
            String path = node.getPath() == null ? "/" : node.getPath();
            String template = templatize(path);
            String key = method + " " + template;
            EndpointRow row = inventory.computeIfAbsent(key,
                    k -> new EndpointRow(method, template));
            if (sampleBudget < 8 && node.getResponseData() != null
                    && !node.getResponseData().isEmpty()) {
                List<String> keys = new ArrayList<>();
                for (String k : node.getResponseData().keySet()) {
                    if (k != null && !k.isBlank()) keys.add(k);
                }
                if (!keys.isEmpty()) {
                    row.sampleResponseKeys = keys;
                    sampleBudget++;
                }
            }
        }

        if (inventory.isEmpty()) return emptyUpdate();

        // Take the most common N endpoints (here: just first N since
        // we do not have frequency counts).
        List<EndpointRow> rows = new ArrayList<>(inventory.values());
        if (rows.size() > maxEndpoints) {
            rows = rows.subList(0, maxEndpoints);
        }

        String userPrompt = buildUserPrompt(rows);
        String systemPrompt = buildSystemPrompt();

        String raw = llmClient.sendChatCompletion(systemPrompt, userPrompt);
        if (raw == null || raw.isBlank()) {
            log("LLM returned empty response");
            return emptyUpdate();
        }

        return parseResponse(raw);
    }

    /**
     * Apply a vocabulary update to a TargetVocabulary. All terms
     * are added with source=LLM_INFERRED. The vocabulary's
     * add-method is idempotent and re-adding the same term
     * increments the count and keeps the higher weight.
     */
    public static void apply(TargetVocabulary vocab, VocabularyUpdate update) {
        if (vocab == null || update == null) return;
        for (String term : update.businessNouns) {
            for (String t : TokenNormalizer.normalize(term)) {
                vocab.addBusinessNoun(t, VocabularySource.LLM_INFERRED);
            }
        }
        for (String term : update.actionVerbs) {
            for (String t : TokenNormalizer.normalize(term)) {
                vocab.addActionVerb(t, VocabularySource.LLM_INFERRED);
            }
        }
        for (String term : update.sensitiveFields) {
            for (String t : TokenNormalizer.normalize(term)) {
                vocab.addSensitiveField(t, VocabularySource.LLM_INFERRED);
            }
        }
        for (String term : update.workflowTerms) {
            for (String t : TokenNormalizer.normalize(term)) {
                vocab.addWorkflowTerm(t, VocabularySource.LLM_INFERRED);
            }
        }
        // stateTerms and actors are folded into workflowTerms
        // and businessNouns respectively — they are useful
        // for the LLM prompt but not for vocabulary scoring.
        for (String term : update.stateTerms) {
            for (String t : TokenNormalizer.normalize(term)) {
                vocab.addWorkflowTerm(t, VocabularySource.LLM_INFERRED);
            }
        }
        for (String term : update.actors) {
            for (String t : TokenNormalizer.normalize(term)) {
                vocab.addBusinessNoun(t, VocabularySource.LLM_INFERRED);
            }
        }
    }

    private static VocabularyUpdate emptyUpdate() {
        return new VocabularyUpdate(List.of(), List.of(), List.of(),
                List.of(), List.of(), List.of());
    }

    private static String buildSystemPrompt() {
        return "You are a senior application-security analyst learning the domain vocabulary "
                + "of a web application.\n"
                + "\n"
                + "RULES (must follow):\n"
                + "- Do NOT report vulnerabilities. Do NOT speculate about bugs.\n"
                + "- Identify business objects, actors, workflow actions, state transitions, "
                + "and sensitive fields from the inventory below.\n"
                + "- Be conservative. If a term is ambiguous, omit it.\n"
                + "- Use snake_case or lower-case tokens (no spaces, no punctuation).\n"
                + "- Maximum 30 terms per category. Rank by confidence within each category.\n"
                + "\n"
                + "Return STRICT JSON of this exact shape, no markdown, no commentary:\n"
                + "{\n"
                + "  \"business_objects\": [\"reservation\", \"listing\", ...],\n"
                + "  \"actors\": [\"guest\", \"host\", ...],\n"
                + "  \"workflow_actions\": [\"cancel\", \"approve\", ...],\n"
                + "  \"state_terms\": [\"pending\", \"accepted\", ...],\n"
                + "  \"sensitive_fields\": [\"payout_account\", ...],\n"
                + "  \"likely_workflows\": [\n"
                + "    {\"name\": \"reservation booking\", \"endpoints\": [\"/listings\", \"/reservations\"], \"confidence\": 0.82}\n"
                + "  ]\n"
                + "}";
    }

    private static String buildUserPrompt(List<EndpointRow> rows) {
        StringBuilder sb = new StringBuilder();
        sb.append("Endpoint inventory (");
        sb.append(rows.size());
        sb.append(" unique path templates):\n\n");
        int shownKeys = 0;
        for (EndpointRow row : rows) {
            sb.append("- ").append(row.method).append(" ").append(row.template);
            if (row.sampleResponseKeys != null && !row.sampleResponseKeys.isEmpty()) {
                sb.append("  (response keys: ");
                int n = Math.min(5, row.sampleResponseKeys.size());
                for (int i = 0; i < n; i++) {
                    if (i > 0) sb.append(", ");
                    sb.append(row.sampleResponseKeys.get(i));
                }
                if (row.sampleResponseKeys.size() > n) sb.append(", ...");
                sb.append(")");
            }
            sb.append("\n");
            shownKeys++;
        }
        sb.append("\n");
        sb.append("Identify the application domain and return vocabulary JSON.\n");
        return sb.toString();
    }

    /**
     * Parse the LLM response. The LLM is asked to return strict
     * JSON; we extract the well-known arrays defensively. If
     * the response is wrapped in markdown code fences (some
     * LLMs add them), we strip them before parsing.
     */
    static VocabularyUpdate parseResponse(String raw) {
        if (raw == null) return emptyUpdate();
        String json = raw.trim();
        // Strip ```json ... ``` fences if present
        if (json.startsWith("```")) {
            int firstNewline = json.indexOf('\n');
            if (firstNewline > 0) json = json.substring(firstNewline + 1);
            int lastFence = json.lastIndexOf("```");
            if (lastFence > 0) json = json.substring(0, lastFence);
            json = json.trim();
        }
        // Some LLMs prefix with prose. Find the first '{' and last '}'.
        if (!json.startsWith("{")) {
            int firstBrace = json.indexOf('{');
            int lastBrace = json.lastIndexOf('}');
            if (firstBrace >= 0 && lastBrace > firstBrace) {
                json = json.substring(firstBrace, lastBrace + 1);
            }
        }
        try {
            JsonObject obj = JsonParser.parseString(json).getAsJsonObject();
            List<String> businessObjects = readStringArray(obj, "business_objects");
            List<String> actors = readStringArray(obj, "actors");
            List<String> workflowActions = readStringArray(obj, "workflow_actions");
            List<String> stateTerms = readStringArray(obj, "state_terms");
            List<String> sensitiveFields = readStringArray(obj, "sensitive_fields");
            // likely_workflows is informational; we discard it.
            return new VocabularyUpdate(
                    businessObjects, workflowActions, sensitiveFields,
                    List.of(), stateTerms, actors);
        } catch (Exception e) {
            return emptyUpdate();
        }
    }

    private static List<String> readStringArray(JsonObject obj, String key) {
        List<String> out = new ArrayList<>();
        if (!obj.has(key)) return out;
        JsonElement el = obj.get(key);
        if (!el.isJsonArray()) return out;
        JsonArray arr = el.getAsJsonArray();
        for (int i = 0; i < arr.size() && i < 30; i++) {
            JsonElement item = arr.get(i);
            if (item != null && item.isJsonPrimitive()) {
                String s = item.getAsString();
                if (s != null && !s.isBlank()) {
                    String t = s.trim().toLowerCase(Locale.ROOT);
                    if (t.length() >= 2 && t.length() <= 40) out.add(t);
                }
            }
        }
        return out;
    }

    private static String templatize(String path) {
        if (path == null) return "/";
        // Replace numeric, UUID, hex segments with {id} so the
        // inventory shows one row per path family.
        String[] segs = path.split("/");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < segs.length; i++) {
            String seg = segs[i];
            sb.append('/');
            if (isLikelyId(seg)) {
                sb.append("{id}");
            } else {
                sb.append(seg);
            }
        }
        return sb.toString();
    }

    private static boolean isLikelyId(String seg) {
        if (seg == null || seg.isEmpty()) return false;
        if (seg.length() == 36 && seg.charAt(8) == '-') return true; // UUID
        // Pure numeric
        boolean allDigit = true;
        for (int i = 0; i < seg.length(); i++) {
            if (!Character.isDigit(seg.charAt(i))) { allDigit = false; break; }
        }
        if (allDigit && seg.length() >= 2) return true;
        // Long hex
        if (seg.length() >= 10) {
            boolean hex = true;
            for (int i = 0; i < seg.length(); i++) {
                char c = seg.charAt(i);
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
                        || (c >= 'A' && c <= 'F'))) { hex = false; break; }
            }
            if (hex) return true;
        }
        return false;
    }

    private void log(String msg) {
        if (logger != null) {
            logger.log(LogCategory.LLM_REQUEST, LogLevel.INFO, "LLMVocabularyLearner", msg);
        }
    }

    /** Row used for inventory building. */
    static class EndpointRow {
        final String method;
        final String template;
        List<String> sampleResponseKeys;
        EndpointRow(String method, String template) {
            this.method = method;
            this.template = template;
        }
    }
}

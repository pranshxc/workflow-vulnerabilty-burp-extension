package com.workflowscanner.analysis;

import com.workflowscanner.classification.EndpointKey;
import com.workflowscanner.classification.NoiseRulesConfig;
import com.workflowscanner.graph.RequestNode;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;
import com.workflowscanner.workflow.WorkflowCandidate;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Accumulated application-wide context built from all analyzed workflow candidates.
 * Passed into LLM prompts to give the model broader understanding of the application.
 *
 * Built incrementally as candidates are processed.
 */
public class ApplicationModel {

    private final Set<EndpointKey> discoveredEndpoints = new HashSet<>();
    private final Map<String, ObjectType> objectIdParameters = new HashMap<>(); // "order_id" -> ORDER
    private final List<StateTransition> knownStateTransitions = new ArrayList<>();
    private final List<AuthBoundary> authBoundaries = new ArrayList<>();

    // === Realism-upgrade-2: per-target vocabulary ===
    // The vocabulary learner observes each request node and each
    // confirmed workflow candidate, extracts domain-specific terms
    // (business nouns, action verbs, sensitive fields, workflow
    // terms), and stores them in a thread-safe TargetVocabulary.
    // The scorer reads the vocabulary to add structural boosts;
    // the LLM prompt builder reads it for app-context rendering.
    private final VocabularyLearner vocabularyLearner;

    public enum ObjectType {
        USER, ACCOUNT, ORDER, CART, PAYMENT, INVOICE, PRODUCT, ORGANIZATION, ROLE, FILE, UNKNOWN
    }

    public static class StateTransition {
        public final String fromState;
        public final String toState;
        public final String endpoint;

        public StateTransition(String fromState, String toState, String endpoint) {
            this.fromState = fromState;
            this.toState = toState;
            this.endpoint = endpoint;
        }
    }

    public static class AuthBoundary {
        public final String endpoint;
        public final boolean authenticated;

        public AuthBoundary(String endpoint, boolean authenticated) {
            this.endpoint = endpoint;
            this.authenticated = authenticated;
        }
    }

    public void addEndpoint(EndpointKey key) {
        if (key != null) discoveredEndpoints.add(key);
    }

    /**
     * Construct an ApplicationModel. The {@code noiseConfig} is used
     * by the embedded VocabularyLearner to filter noise and to load
     * user-supplied custom vocabulary terms.
     */
    public ApplicationModel(NoiseRulesConfig noiseConfig) {
        this.vocabularyLearner = new VocabularyLearner(noiseConfig);
    }

    /** Default-constructed model with stock noise rules. */
    public ApplicationModel() {
        this(NoiseRulesConfig.withDefaults());
    }

    public void addObjectIdParameter(String paramName, ObjectType type) {
        objectIdParameters.putIfAbsent(paramName.toLowerCase(), type);
    }

    public void addStateTransition(String from, String to, String endpoint) {
        knownStateTransitions.add(new StateTransition(from, to, endpoint));
    }

    public void addAuthBoundary(String endpoint, boolean authenticated) {
        authBoundaries.add(new AuthBoundary(endpoint, authenticated));
    }

    /**
     * Ingest a context-read request (e.g. /api/me, /api/user, /profile).
     * These are not workflow steps, but carry auth/user context useful for LLM prompts.
     * Store the endpoint and extract object IDs from the response.
     *
     * Expected response JSON shape (parsed from extracted params):
     * { "user_id": 123, "role": "admin", "email": "user@example.com", ... }
     */
    public void ingestContextRead(RequestNode node, ExtensionLogger logger) {
        if (node == null) return;
        EndpointKey key = node.getEndpointKey();
        if (key != null) {
            addEndpoint(key);
            if (logger != null) {
                logger.log(LogCategory.ANALYSIS, LogLevel.DEBUG, "ApplicationModel",
                        "Context read: " + key);
            }
        }

        // Extract user context from response fields
        Map<String, Object> responseData = node.getResponseData();
        if (responseData != null) {
            for (Map.Entry<String, Object> entry : responseData.entrySet()) {
                String name = entry.getKey().toLowerCase();
                if (name.endsWith("_id") || name.endsWith("id")) {
                    addObjectIdParameter(name, inferObjectType(name));
                }
                if (name.equals("role") || name.equals("roles")) {
                    addObjectIdParameter(name, ObjectType.ROLE);
                }
            }
        }
    }

    private static ObjectType inferObjectType(String paramName) {
        String lower = paramName.toLowerCase();
        if (lower.contains("user")) return ObjectType.USER;
        if (lower.contains("order")) return ObjectType.ORDER;
        if (lower.contains("payment") || lower.contains("pay")) return ObjectType.PAYMENT;
        if (lower.contains("cart")) return ObjectType.CART;
        if (lower.contains("invoice")) return ObjectType.INVOICE;
        if (lower.contains("product")) return ObjectType.PRODUCT;
        if (lower.contains("account")) return ObjectType.ACCOUNT;
        if (lower.contains("org")) return ObjectType.ORGANIZATION;
        if (lower.contains("file")) return ObjectType.FILE;
        return ObjectType.UNKNOWN;
    }

    /**
     * Build application model context from a list of nodes in a candidate.
     * Learns endpoints per-node, then infers state transitions from adjacent pairs.
     * Also feeds the per-target vocabulary learner.
     */
    public void learnFromCandidate(List<RequestNode> steps) {
        if (steps == null || steps.isEmpty()) return;

        // Phase 1: per-node learning (endpoints, object IDs, auth boundaries)
        for (RequestNode node : steps) {
            if (node.getEndpointKey() != null) {
                addEndpoint(node.getEndpointKey());
            }

            // Learn object ID parameters from path and params
            String path = node.getPath() != null ? node.getPath().toLowerCase() : "";
            if (path.contains("user")) addObjectIdParameter("user_id", ObjectType.USER);
            if (path.contains("order")) addObjectIdParameter("order_id", ObjectType.ORDER);
            if (path.contains("payment") || path.contains("pay"))
                addObjectIdParameter("payment_id", ObjectType.PAYMENT);
            if (path.contains("cart")) addObjectIdParameter("cart_id", ObjectType.CART);
            if (path.contains("invoice")) addObjectIdParameter("invoice_id", ObjectType.INVOICE);
            if (path.contains("product")) addObjectIdParameter("product_id", ObjectType.PRODUCT);
            if (path.contains("account")) addObjectIdParameter("account_id", ObjectType.ACCOUNT);

            // Learn auth boundaries
            boolean isAuth = path.contains("login") || path.contains("signin")
                    || path.contains("auth") || path.contains("token");
            if (isAuth) {
                addAuthBoundary(node.getMethod() + " " + (node.getPath() != null ? node.getPath() : ""),
                        node.getStatusCode() >= 200 && node.getStatusCode() < 300);
            }

            // === Realism-upgrade-2: per-target vocabulary ===
            // Observe this request node for vocabulary learning. The
            // learner filters out noise / static / unauth GETs; only
            // auth-bound, state-changing, or workflow-relevant
            // requests contribute.
            if (vocabularyLearner != null) {
                vocabularyLearner.observe(node);
            }
        }

        // Phase 2: infer adjacent state transitions from consecutive step pairs
        for (int i = 1; i < steps.size(); i++) {
            RequestNode prev = steps.get(i - 1);
            RequestNode curr = steps.get(i);
            inferTransition(prev, curr);
        }
    }

    /**
     * Observe a confirmed workflow candidate. Same as
     * {@link #learnFromCandidate(List)} but signals the
     * candidate-level context to the vocabulary learner (which
     * otherwise observes one node at a time). Confirmed candidates
     * carry higher trust than raw traffic.
     */
    public void learnFromConfirmedCandidate(WorkflowCandidate candidate) {
        if (candidate == null) return;
        learnFromCandidate(candidate.getSteps());
        if (vocabularyLearner != null) {
            vocabularyLearner.observe(candidate);
        }
    }

    /**
     * Get the current snapshot of the target vocabulary. The
     * returned object is thread-safe and is updated as new
     * requests are observed.
     */
    public TargetVocabulary getTargetVocabulary() {
        return vocabularyLearner != null
                ? vocabularyLearner.snapshot()
                : new TargetVocabulary();
    }

    /**
     * Infer a state transition between two adjacent steps in a workflow.
     * The "from state" is the previous step's path family (2 segments),
     * the "to state" is the current step's path family.
     * If domain semantic rules apply (e.g. cart -> checkout), use those
     * instead of raw path family.
     */
    private void inferTransition(RequestNode prev, RequestNode curr) {
        String fromState = extractStateKey(prev);
        String toState = extractStateKey(curr);
        if (fromState == null || toState == null || fromState.equals(toState)) return;

        String endpoint = curr.getMethod() + " " + (curr.getPath() != null ? curr.getPath() : "");

        // Domain semantic rules — recognize known workflow state transitions
        String from = fromState.toLowerCase();
        String to = toState.toLowerCase();
        String semanticFrom = from;
        String semanticTo = to;

        if (from.contains("cart") && to.contains("checkout")) {
            semanticFrom = "cart";
            semanticTo = "checkout";
        } else if ((from.contains("cart") || from.contains("checkout"))
                && (to.contains("payment") || to.contains("pay"))) {
            semanticFrom = from.contains("checkout") ? "checkout" : "cart";
            semanticTo = "payment";
        } else if ((from.contains("payment") || from.contains("pay"))
                && (to.contains("order") || to.contains("confirm") || to.contains("success"))) {
            semanticFrom = "payment";
            semanticTo = "order_confirmed";
        } else if (from.contains("login") && !to.contains("login")) {
            semanticFrom = "login";
            semanticTo = "post_login";
        } else if (from.contains("register") && !to.contains("register")) {
            semanticFrom = "register";
            semanticTo = "post_registration";
        }

        addStateTransition(semanticFrom, semanticTo, endpoint);
    }

    /**
     * Extract a state key from a node: the first 2 path segments.
     * e.g. /cart/items -> "cart/items", /checkout/address -> "checkout/address"
     */
    private String extractStateKey(RequestNode node) {
        if (node == null || node.getPath() == null) return null;
        String path = node.getPath().toLowerCase();
        String[] segments = path.split("/");
        StringBuilder key = new StringBuilder();
        int count = 0;
        for (String seg : segments) {
            if (!seg.isEmpty()) {
                if (key.length() > 0) key.append("/");
                key.append(seg);
                count++;
                if (count >= 2) break;
            }
        }
        return key.length() > 0 ? key.toString() : null;
    }

    /**
     * Build a textual summary of the application model for LLM prompts.
     */
    public String toPromptContext() {
        StringBuilder sb = new StringBuilder();
        sb.append("## Application Context\n");

        if (!discoveredEndpoints.isEmpty()) {
            sb.append("\nKnown API endpoints (").append(discoveredEndpoints.size()).append("):\n");
            // Show most common endpoints first (limit to 20)
            discoveredEndpoints.stream()
                    .limit(20)
                    .forEach(k -> sb.append("- ").append(k).append("\n"));
        }

        if (!objectIdParameters.isEmpty()) {
            sb.append("\nObject ID parameters:\n");
            objectIdParameters.forEach((name, type) ->
                    sb.append("- ").append(name).append(" -> ").append(type).append("\n"));
        }

        if (!knownStateTransitions.isEmpty()) {
            sb.append("\nKnown state transitions:\n");
            knownStateTransitions.forEach(t ->
                    sb.append("- ").append(t.fromState).append(" -> ").append(t.toState)
                            .append(" at ").append(t.endpoint).append("\n"));
        }

        if (!authBoundaries.isEmpty()) {
            sb.append("\nAuth boundaries:\n");
            authBoundaries.forEach(b ->
                    sb.append("- ").append(b.endpoint)
                            .append(b.authenticated ? " (authenticated)" : " (unauthenticated)")
                            .append("\n"));
        }

        // === Realism-upgrade-2: per-target vocabulary ===
        // The learned vocabulary (and user-supplied terms) tell the
        // LLM what this application's domain is. For non-fintech
        // targets (Airbnb-like, HelloFresh-like, healthcare, etc.)
        // the LLM would otherwise have to guess the domain from
        // paths and bodies alone.
        if (vocabularyLearner != null) {
            String vocabCtx = vocabularyLearner.snapshot().toPromptContext();
            if (vocabCtx != null && !vocabCtx.startsWith("(no target")) {
                sb.append("\nTarget vocabulary (learned from this app):\n");
                sb.append(vocabCtx);
            }
        }

        return sb.toString();
    }

    public Set<EndpointKey> getDiscoveredEndpoints() { return discoveredEndpoints; }
    public Map<String, ObjectType> getObjectIdParameters() { return objectIdParameters; }
    public List<StateTransition> getKnownStateTransitions() { return knownStateTransitions; }
    public List<AuthBoundary> getAuthBoundaries() { return authBoundaries; }
}

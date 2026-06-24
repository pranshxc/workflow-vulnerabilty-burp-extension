package com.workflowscanner.analysis;

import com.workflowscanner.classification.EndpointKey;
import com.workflowscanner.graph.RequestNode;

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
     * Build application model context from a list of nodes in a candidate.
     * Learns endpoints per-node, then infers state transitions from adjacent pairs.
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
        }

        // Phase 2: infer adjacent state transitions from consecutive step pairs
        for (int i = 1; i < steps.size(); i++) {
            RequestNode prev = steps.get(i - 1);
            RequestNode curr = steps.get(i);
            inferTransition(prev, curr);
        }
    }

    /**
     * Infer a state transition between two adjacent steps in a workflow.
     * The "from state" is the previous step's path family (2 segments),
     * the "to state" is the current step's path family.
     */
    private void inferTransition(RequestNode prev, RequestNode curr) {
        String fromState = extractStateKey(prev);
        String toState = extractStateKey(curr);
        if (fromState == null || toState == null || fromState.equals(toState)) return;

        String endpoint = curr.getMethod() + " " + (curr.getPath() != null ? curr.getPath() : "");
        addStateTransition(fromState, toState, endpoint);
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

        return sb.toString();
    }

    public Set<EndpointKey> getDiscoveredEndpoints() { return discoveredEndpoints; }
    public Map<String, ObjectType> getObjectIdParameters() { return objectIdParameters; }
    public List<StateTransition> getKnownStateTransitions() { return knownStateTransitions; }
    public List<AuthBoundary> getAuthBoundaries() { return authBoundaries; }
}

package com.workflowscanner.analysis;

import com.workflowscanner.graph.EdgeType;
import com.workflowscanner.graph.RequestEdge;
import com.workflowscanner.graph.RequestNode;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Scores and prioritizes workflow chains for analysis.
 * Higher scores indicate chains more likely to contain vulnerabilities.
 *
 * Scoring heuristics:
 * - State-changing methods (POST, PUT, DELETE, PATCH) score higher
 * - Auth/financial endpoint keywords score higher
 * - Parameter reuse edges (data flowing between steps) score higher
 * - Longer chains = more attack surface
 * - Mixed methods (GET->POST->GET) score higher
 * - Purely static asset chains score lowest / skip
 */
public class ChainPrioritizer {

    private static final Set<String> STATE_CHANGING_METHODS = Set.of("POST", "PUT", "DELETE", "PATCH");

    private static final Set<String> AUTH_KEYWORDS = Set.of(
            "login", "signin", "sign-in", "auth", "oauth", "token", "session",
            "register", "signup", "sign-up", "password", "reset", "verify",
            "logout", "signout", "mfa", "2fa", "otp");

    private static final Set<String> FINANCIAL_KEYWORDS = Set.of(
            "payment", "pay", "checkout", "cart", "order", "purchase",
            "transfer", "transaction", "billing", "invoice", "refund",
            "subscribe", "subscription", "price", "amount", "charge");

    private static final Set<String> STATIC_EXTENSIONS = Set.of(
            ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map");

    /**
     * Score a chain based on vulnerability likelihood heuristics.
     * Returns a score where higher = more interesting.
     */
    public double scoreChain(List<RequestNode> chain, List<RequestEdge> edges) {
        if (chain == null || chain.isEmpty()) return 0.0;

        // Skip purely static asset chains
        if (isStaticAssetChain(chain)) return -1.0;

        double score = 0.0;

        // 1. State-changing methods bonus
        int stateChangingCount = 0;
        Set<String> methods = new HashSet<>();
        for (RequestNode node : chain) {
            String method = node.getMethod() != null ? node.getMethod().toUpperCase() : "GET";
            methods.add(method);
            if (STATE_CHANGING_METHODS.contains(method)) {
                stateChangingCount++;
            }
        }
        score += stateChangingCount * 3.0;

        // 2. Method diversity bonus (mixed methods = workflow pattern)
        if (methods.size() > 1) {
            score += methods.size() * 2.0;
        }

        // 3. Auth/financial endpoint keywords
        for (RequestNode node : chain) {
            String path = node.getPath() != null ? node.getPath().toLowerCase() : "";
            for (String keyword : AUTH_KEYWORDS) {
                if (path.contains(keyword)) { score += 5.0; break; }
            }
            for (String keyword : FINANCIAL_KEYWORDS) {
                if (path.contains(keyword)) { score += 7.0; break; }
            }
        }

        // 4. Parameter reuse edges (data flowing between steps)
        if (edges != null) {
            for (RequestEdge edge : edges) {
                if (edge.getType() == EdgeType.PARAM_REUSE) score += 4.0;
                else if (edge.getType() == EdgeType.RESPONSE_CORRELATION) score += 3.0;
                else if (edge.getType() == EdgeType.REDIRECT) score += 2.0;
            }
        }

        // 5. Chain length bonus (longer = more attack surface, diminishing returns)
        score += Math.min(chain.size() * 1.5, 15.0);

        return score;
    }

    /**
     * Sort chains by priority score (highest first).
     * Filters out static asset chains.
     */
    public List<List<RequestNode>> prioritize(List<List<RequestNode>> chains,
                                               List<List<RequestEdge>> chainEdges) {
        List<ScoredChain> scored = new ArrayList<>();

        for (int i = 0; i < chains.size(); i++) {
            List<RequestNode> chain = chains.get(i);
            List<RequestEdge> edges = i < chainEdges.size() ? chainEdges.get(i) : null;
            double s = scoreChain(chain, edges);
            if (s > 0) {
                scored.add(new ScoredChain(chain, edges, s));
            }
        }

        scored.sort(Comparator.comparingDouble((ScoredChain sc) -> sc.score).reversed());

        List<List<RequestNode>> result = new ArrayList<>();
        for (ScoredChain sc : scored) {
            result.add(sc.chain);
        }
        return result;
    }

    private boolean isStaticAssetChain(List<RequestNode> chain) {
        for (RequestNode node : chain) {
            String path = node.getPath() != null ? node.getPath().toLowerCase() : "";
            boolean isStatic = false;
            for (String ext : STATIC_EXTENSIONS) {
                if (path.endsWith(ext)) { isStatic = true; break; }
            }
            if (!isStatic) return false; // At least one non-static request
        }
        return true; // All requests are static assets
    }

    private static class ScoredChain {
        final List<RequestNode> chain;
        final List<RequestEdge> edges;
        final double score;
        ScoredChain(List<RequestNode> chain, List<RequestEdge> edges, double score) {
            this.chain = chain;
            this.edges = edges;
            this.score = score;
        }
    }
}

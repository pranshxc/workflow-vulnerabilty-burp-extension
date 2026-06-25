package com.workflowscanner.analysis;

import com.workflowscanner.classification.RequestIntent;
import com.workflowscanner.classification.RequestClassification;
import com.workflowscanner.graph.RequestEdge;
import com.workflowscanner.graph.RequestNode;
import com.workflowscanner.workflow.WorkflowCandidate;
import com.workflowscanner.workflow.WorkflowType;

import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Lightweight heuristic that flags findings on endpoints whose
 * resources are public-by-design. The motivating case is blockchain
 * data APIs (wallet balances, token prices, allowances) where
 * querying a public wallet address is not IDOR — the data is
 * intentionally public. Without this rule, the LLM produces IDOR
 * findings on any /balance, /price, /allowance endpoint that takes
 * a wallet address as a path or query parameter, even when the
 * response is just a public on-chain value.
 *
 * <p>The classifier is conservative: a finding is only flagged as
 * PUBLIC_RESOURCE when the path contains a public-resource keyword
 * AND the resource id looks like a blockchain address AND there is
 * no auth-bound ownership edge in the candidate. If any of those
 * three preconditions fail, the finding is left alone.
 *
 * <p>Auth-bound ownership edge: a {@code /me} or similar endpoint
 * in the candidate that names the wallet/account the user owns,
 * or an explicit USER_DEFINED / PARAM_REUSE edge that ties the
 * query parameter to an authenticated resource. Without that, the
 * "ownership" assumption the LLM is making is not supported.
 */
public class PublicResourceClassifier {

    /** Path keywords that are commonly public-resource endpoints. */
    private static final Set<String> PUBLIC_KEYWORDS = Set.of(
            "wallet", "wallets",
            "address", "addresses",
            "balance", "balances",
            "allowance", "allowances",
            "price", "prices",
            "quote", "quotes",
            "swap", "swaps",
            "gasprice", "gas", "gasoracle",
            "token", "tokens",
            "nft", "nfts", "collection", "collections",
            "tx", "txs", "transaction", "transactions",
            "receipt", "receipts",
            "block", "blocks",
            "supply", "totalsupply",
            "owner", "owners"
    );

    /** Resource id keys that, when present, are commonly wallet / token addresses. */
    private static final Set<String> ADDRESS_PARAM_KEYS = Set.of(
            "address", "wallet", "owner", "to", "from", "token",
            "tokenid", "contract", "contractaddress", "asset",
            "user_address", "useraddress", "wallet_address"
    );

    /**
     * Loose pattern that matches most blockchain address shapes:
     * 0x followed by 40 hex chars (Ethereum-style), 30–44 base58 chars
     * (Solana-style), or any 32–44 char base58 / hex string.
     */
    private static final Pattern ADDRESS_LIKE = Pattern.compile(
            "^(0x[0-9a-fA-F]{40}|[1-9A-HJ-NP-Za-km-z]{32,44}|[0-9a-fA-F]{40,64})$");

    /**
     * Pattern for finding blockchain addresses in a URL or path.
     * The path is unanchored so we can find any address segment.
     */
    private static final Pattern ADDRESS_IN_PATH = Pattern.compile(
            "(0x[0-9a-fA-F]{40}|[1-9A-HJ-NP-Za-km-z]{32,44})");

    /** Path keywords that indicate authenticated / user-bound resources. */
    private static final Set<String> AUTH_BOUND_KEYWORDS = Set.of(
            "/me", "/user", "/users", "/account", "/accounts",
            "/profile", "/profiles", "/settings",
            "/my", "/self", "/owner"
    );

    private PublicResourceClassifier() {
        // No instances.
    }

    /**
     * True if this candidate's primary endpoint pattern is a
     * public-resource lookup (e.g. wallet balance) AND there is no
     * evidence of auth-bound ownership in the chain. Public-resource
     * findings should be downgraded or suppressed.
     */
    public static boolean isPublicResourceFinding(WorkflowCandidate candidate,
                                                  List<RequestEdge> supportingEdges) {
        if (candidate == null || candidate.getSteps() == null
                || candidate.getSteps().isEmpty()) {
            return false;
        }

        boolean hasPublicEndpoint = false;
        boolean hasAddressLikeId = false;
        boolean hasAuthBoundContext = false;

        for (RequestNode step : candidate.getSteps()) {
            String path = step.getPath() != null ? step.getPath().toLowerCase() : "";
            String url = step.getUrl() != null ? step.getUrl().toLowerCase() : "";

            // (1) Path matches a public-resource keyword.
            if (!hasPublicEndpoint) {
                for (String keyword : PUBLIC_KEYWORDS) {
                    // Word boundary so "balance" matches /balance, /balance/of, but
                    // does not match "imbalance" or "rebalanced".
                    if (path.matches(".*[/_-]" + java.util.regex.Pattern.quote(keyword) + "[/_-]?.*")
                            || path.endsWith("/" + keyword)
                            || path.equals("/" + keyword)
                            || url.contains("/" + keyword + "?")
                            || url.contains("/" + keyword + "/")) {
                        hasPublicEndpoint = true;
                        break;
                    }
                }
            }

            // (2) Resource id (query / path / body) looks like a blockchain address.
            if (!hasAddressLikeId) {
                if (looksLikeAddressParam(step)) {
                    hasAddressLikeId = true;
                } else if (looksLikeAddressInPath(path) || looksLikeAddressInPath(url)) {
                    hasAddressLikeId = true;
                }
            }

            // (3) Auth-bound context: a /me-style step, an explicit user/account
            // endpoint, or any USER_DEFINED edge that links the candidate to
            // an authenticated user-owned resource.
            if (!hasAuthBoundContext) {
                if (pathContainsAny(path, AUTH_BOUND_KEYWORDS)) {
                    hasAuthBoundContext = true;
                } else {
                    RequestClassification cls = step.getClassification();
                    if (cls != null && cls.getIntent() == RequestIntent.AUTHENTICATION) {
                        hasAuthBoundContext = true;
                    }
                }
            }
        }

        // Check edges for an explicit ownership link. USER_DEFINED edges
        // (manual grouping) and PARAM_REUSE between authenticated
        // resources count.
        if (!hasAuthBoundContext && supportingEdges != null) {
            for (RequestEdge edge : supportingEdges) {
                if (edge.getType() == com.workflowscanner.graph.EdgeType.USER_DEFINED) {
                    hasAuthBoundContext = true;
                    break;
                }
            }
        }

        // Public resource finding only when (1) public endpoint, (2)
        // address-like id, (3) no auth-bound ownership proof. Any
        // single precondition failing means we do not flag it.
        return hasPublicEndpoint && hasAddressLikeId && !hasAuthBoundContext;
    }

    /**
     * Convenience overload that pulls supporting edges off the
     * candidate itself.
     */
    public static boolean isPublicResourceFinding(WorkflowCandidate candidate) {
        return isPublicResourceFinding(candidate,
                candidate != null ? candidate.getSupportingEdges() : null);
    }

    /**
     * Workflow types that imply user-bound state — finding on these
     * is never "public resource" even if the path contains a public
     * keyword. AUTH, PASSWORD_RESET, ROLE_ADMIN, etc. all imply
     * the request is acting on a user-specific account.
     */
    public static boolean isAlwaysAuthBound(WorkflowType type) {
        if (type == null) return false;
        switch (type) {
            case AUTHENTICATION:
            case REGISTRATION:
            case PASSWORD_RESET:
            case ROLE_ADMIN:
            case PROFILE_UPDATE:
            case APPROVAL:
            case INVITATION:
                return true;
            default:
                return false;
        }
    }

    private static boolean looksLikeAddressParam(RequestNode step) {
        if (step.getExtractedParams() == null) return false;
        for (java.util.Map.Entry<String, Object> entry : step.getExtractedParams().entrySet()) {
            String key = entry.getKey() != null ? entry.getKey().toLowerCase() : "";
            // Strip cookie. and set-cookie. prefixes that ParameterExtractor
            // uses internally — they are not address parameters.
            if (key.startsWith("cookie.")) continue;
            if (key.startsWith("set-cookie.")) continue;
            // Look for a key that suggests an address parameter.
            boolean keyMatch = false;
            for (String ak : ADDRESS_PARAM_KEYS) {
                if (key.equals(ak) || key.endsWith("." + ak) || key.contains(ak)) {
                    keyMatch = true;
                    break;
                }
            }
            if (!keyMatch) continue;
            Object value = entry.getValue();
            if (value == null) continue;
            String strValue = value.toString();
            // Path-segment style: e.g. /api/wallet/0xAbC...
            String path = step.getPath();
            if (path != null && path.contains(strValue) && strValue.length() >= 32) {
                return true;
            }
            // Pure value: check the shape directly.
            if (ADDRESS_LIKE.matcher(strValue).matches()) {
                return true;
            }
        }
        return false;
    }

    /**
     * True if the path or URL contains a token that looks like a
     * blockchain address (0x + 40 hex, or 32–44 base58 chars).
     * This is a fallback for cases where the address is part of
     * the URL path itself rather than an extracted parameter.
     */
    private static boolean looksLikeAddressInPath(String pathOrUrl) {
        if (pathOrUrl == null) return false;
        return ADDRESS_IN_PATH.matcher(pathOrUrl).find();
    }

    private static boolean pathContainsAny(String path, Set<String> keywords) {
        if (path == null) return false;
        for (String k : keywords) {
            if (path.contains(k)) return true;
        }
        return false;
    }
}

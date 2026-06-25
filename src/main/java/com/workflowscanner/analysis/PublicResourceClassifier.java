package com.workflowscanner.analysis;

import com.workflowscanner.classification.NoiseRulesConfig;
import com.workflowscanner.classification.PrivateContextDetector;
import com.workflowscanner.classification.RequestClassification;
import com.workflowscanner.classification.RequestIntent;
import com.workflowscanner.classification.StaticNoiseRules;
import com.workflowscanner.graph.RequestEdge;
import com.workflowscanner.graph.RequestNode;
import com.workflowscanner.workflow.WorkflowCandidate;
import com.workflowscanner.workflow.WorkflowType;

import java.util.List;

/**
 * Universal public-resource detector at the candidate level.
 *
 * <p>A <b>public-data lookup candidate</b> is a chain of read-only
 * requests whose endpoints match public-resource patterns and whose
 * chain carries no private context. Examples across targets:
 * <ul>
 *   <li>{@code GET /v1/price/BTC} on a financial portal</li>
 *   <li>{@code GET /api/balance/0x...} on a blockchain explorer</li>
 *   <li>{@code GET /api/products/123} on an e-commerce site (no auth)</li>
 *   <li>{@code GET /weather/London} on a weather API</li>
 *   <li>{@code GET /blog/posts/abc} on a CMS</li>
 *   <li>{@code GET /api/wallet/0x...} on a public wallet viewer</li>
 * </ul>
 *
 * <p>The classifier is conservative: a candidate is flagged
 * PUBLIC_RESOURCE only when <b>all three</b> conditions hold:
 * <ol>
 *   <li>path matches a public-resource pattern;</li>
 *   <li>the chain has no private context (no /me, no Authorization
 *       header, no session cookie, no private response field, no
 *       AUTHENTICATION / CONTEXT_READ step);</li>
 *   <li>no critical workflow type is implied
 *       (AUTHENTICATION, PASSWORD_RESET, ROLE_ADMIN, etc.).</li>
 * </ol>
 *
 * <p>If any condition fails, the candidate is left alone so the
 * downstream gate can decide.
 */
public class PublicResourceClassifier {

    private final NoiseRulesConfig config;
    private final StaticNoiseRules noiseRules;
    private final PrivateContextDetector privateContextDetector;

    public PublicResourceClassifier() {
        this(NoiseRulesConfig.withDefaults());
    }

    public PublicResourceClassifier(NoiseRulesConfig config) {
        NoiseRulesConfig cfg = config != null ? config : NoiseRulesConfig.withDefaults();
        this.config = cfg;
        this.noiseRules = new StaticNoiseRules(cfg);
        this.privateContextDetector = new PrivateContextDetector(cfg);
    }

    /**
     * True if this candidate is a public-data lookup (read-only
     * public resource, no private context) and should be downgraded
     * or suppressed.
     */
    public boolean isPublicResourceFinding(WorkflowCandidate candidate,
                                            List<RequestEdge> supportingEdges) {
        if (candidate == null || candidate.getSteps() == null
                || candidate.getSteps().isEmpty()) {
            return false;
        }

        // (1) Public-resource pattern: at least one step's path
        //     matches a public-resource keyword from the config.
        boolean hasPublicEndpoint = false;
        for (RequestNode step : candidate.getSteps()) {
            String path = step.getPath();
            if (path == null) continue;
            if (noiseRules.isPublicResourcePath(path)) {
                hasPublicEndpoint = true;
                break;
            }
        }
        if (!hasPublicEndpoint) return false;

        // (2) === P1-CORRECTNESS: all steps must be safe reads ===
        // A real public-data candidate is read-only throughout.
        // If any step is a business mutation (POST/PUT/PATCH/DELETE
        // on a non-telemetry path), the candidate is a real
        // business workflow that happens to touch a public
        // endpoint. Suppressing it would hide IDOR / state-change
        // bugs. The exception is known read-only infrastructure
        // methods (OPTIONS, HEAD, GET) which are always safe.
        for (RequestNode step : candidate.getSteps()) {
            String m = step.getMethod() == null ? "GET" : step.getMethod().toUpperCase();
            if ("GET".equals(m) || "HEAD".equals(m) || "OPTIONS".equals(m)) continue;
            // State-changing method on a non-telemetry step is
            // enough to disqualify the candidate from being a
            // pure public-resource lookup.
            RequestClassification cls = step.getClassification();
            if (cls != null) {
                RequestIntent intent = cls.getIntent();
                if (intent == RequestIntent.TELEMETRY_ANALYTICS
                        || intent == RequestIntent.FEATURE_FLAG_CONFIG
                        || intent == RequestIntent.BACKGROUND_POLLING
                        || intent == RequestIntent.HEALTHCHECK
                        || intent == RequestIntent.PREFLIGHT
                        || intent == RequestIntent.STATIC_ASSET
                        || intent == RequestIntent.THIRD_PARTY
                        || intent == RequestIntent.CONTEXT_READ) {
                    continue;
                }
            }
            // Unknown / business intent on a state-changing method
            // — not a public-resource lookup.
            return false;
        }

        // (3) No private context anywhere in the chain.
        //     The detector inspects path, headers, response body,
        //     and classification intent of every step.
        if (privateContextDetector.chainHasPrivateContext(candidate.getSteps())) {
            return false;
        }

        // (4) User-defined edge implies the user explicitly cares
        //     about this chain — do not suppress.
        if (supportingEdges != null) {
            for (RequestEdge edge : supportingEdges) {
                if (edge.getType() == com.workflowscanner.graph.EdgeType.USER_DEFINED) {
                    return false;
                }
            }
        }

        // (5) Critical workflow types are never "public resource"
        //     even if the path contains a public keyword.
        if (isAlwaysAuthBound(candidate.getWorkflowType())) {
            return false;
        }

        return true;
    }

    /**
     * Convenience overload that pulls supporting edges off the
     * candidate itself.
     */
    public boolean isPublicResourceFinding(WorkflowCandidate candidate) {
        return isPublicResourceFinding(candidate,
                candidate != null ? candidate.getSupportingEdges() : null);
    }

    /**
     * Workflow types that imply user-bound state — a finding on
     * these is never "public resource" even if the path contains a
     * public keyword. AUTH, PASSWORD_RESET, ROLE_ADMIN, etc. all
     * imply the request is acting on a user-specific account.
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
}

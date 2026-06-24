package com.workflowscanner.validation;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Lightweight record of a single business-state observation made during a
 * validation test. Produced by the various validators; collected by
 * {@link ValidationResult#addStateCheck(StateCheck)} to drive promotion
 * to {@link ValidationResult.ProofLevel#CONFIRMED}.
 *
 * <p>The model is intentionally simple — no AST, no full JSON parse.
 * The fields capture the four kinds of effects that are usually enough
 * to demonstrate a real business-logic bug:
 *
 * <ul>
 *   <li>New object identifiers that appeared in the test response but
 *       were not present in the original (e.g. new order id, new
 *       payment id, new user id).</li>
 *   <li>Field values that changed between the original and test
 *       responses, especially attacker-controlled values (amount,
 *       role, quantity, balance, status).</li>
 *   <li>Success markers — strings that indicate the server
 *       acknowledged the action in business terms (e.g. "order
 *       confirmed", "payment approved", "role updated to admin").</li>
 *   <li>Access markers — strings that indicate the test reached
 *       another user's resource (a strong IDOR signal).</li>
 * </ul>
 *
 * A {@link StateCheck} reports {@link #isEffectObserved()} as true when
 * at least one of those four buckets is non-empty.
 */
public final class StateCheck {

    private final String followUpUrl;
    private final int beforeStatus;
    private final int afterStatus;
    private final Set<String> newIds = new LinkedHashSet<>();
    private final Set<String> changedFields = new LinkedHashSet<>();
    private final Set<String> successMarkers = new LinkedHashSet<>();
    private final Set<String> accessMarkers = new LinkedHashSet<>();

    public StateCheck(String followUpUrl, int beforeStatus, int afterStatus) {
        this.followUpUrl = followUpUrl;
        this.beforeStatus = beforeStatus;
        this.afterStatus = afterStatus;
    }

    public String getFollowUpUrl() { return followUpUrl; }
    public int getBeforeStatus() { return beforeStatus; }
    public int getAfterStatus() { return afterStatus; }

    public Set<String> getNewIds() { return newIds; }
    public Set<String> getChangedFields() { return changedFields; }
    public Set<String> getSuccessMarkers() { return successMarkers; }
    public Set<String> getAccessMarkers() { return accessMarkers; }

    public boolean statusChanged() {
        return beforeStatus != afterStatus;
    }

    /**
     * True when at least one concrete business effect was observed:
     * a new id appeared, a field value changed, a success marker
     * appeared, or the test reached another user's resource.
     */
    public boolean isEffectObserved() {
        return !newIds.isEmpty()
                || !changedFields.isEmpty()
                || !successMarkers.isEmpty()
                || !accessMarkers.isEmpty();
    }

    /**
     * Strong effect: a new identifier, a changed business field, or a
     * status change. This is the level of evidence we require to
     * promote a finding to {@link ValidationResult.ProofLevel#CONFIRMED}.
     * Marker-only evidence (a success or access string that newly
     * appeared) does not count as strong and only upgrades to PROBABLE.
     */
    public boolean hasStrongEffect() {
        return !newIds.isEmpty()
                || !changedFields.isEmpty()
                || statusChanged();
    }

    /**
     * One-line human-readable summary used in the validation report.
     */
    public String summarize() {
        StringBuilder sb = new StringBuilder();
        if (followUpUrl != null && !followUpUrl.isEmpty()) {
            sb.append(followUpUrl);
        }
        sb.append(" [").append(beforeStatus).append("->").append(afterStatus).append(']');
        if (!newIds.isEmpty()) sb.append(" newIds=").append(newIds);
        if (!changedFields.isEmpty()) sb.append(" changed=").append(changedFields);
        if (!successMarkers.isEmpty()) sb.append(" success=").append(successMarkers);
        if (!accessMarkers.isEmpty()) sb.append(" access=").append(accessMarkers);
        return sb.toString();
    }
}

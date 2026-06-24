package com.workflowscanner.validation;

/**
 * Result of a single parameter mutation attempt inside
 * {@link RequestReplayer}. The replayer is responsible for populating
 * this honestly: if the parameter was not found, or the body did not
 * contain it, {@link #applied} is false and {@link #reason} explains
 * why.
 *
 * <p>This exists to prevent the silent "the test replayed the original
 * request unchanged" failure mode that the old regex-based replayer
 * could fall into. Validation logic should refuse to treat a replay as
 * meaningful when {@code applied} is false.
 */
public final class MutationResult {

    public enum Location {
        QUERY,
        FORM_BODY,
        JSON_BODY,
        HEADER,
        UNKNOWN
    }

    private final boolean applied;
    private final Location location;
    private final String paramName;
    private final String oldValue;
    private final String newValue;
    private final String reason;

    private MutationResult(boolean applied, Location location, String paramName,
                           String oldValue, String newValue, String reason) {
        this.applied = applied;
        this.location = location;
        this.paramName = paramName;
        this.oldValue = oldValue;
        this.newValue = newValue;
        this.reason = reason;
    }

    public static MutationResult applied(Location location, String paramName,
                                         String oldValue, String newValue) {
        return new MutationResult(true, location, paramName, oldValue, newValue, null);
    }

    public static MutationResult notApplied(Location location, String paramName, String reason) {
        return new MutationResult(false, location, paramName, null, null, reason);
    }

    public boolean isApplied() { return applied; }
    public Location getLocation() { return location; }
    public String getParamName() { return paramName; }
    public String getOldValue() { return oldValue; }
    public String getNewValue() { return newValue; }
    public String getReason() { return reason; }

    @Override
    public String toString() {
        if (applied) {
            return "Mutation[" + location + " " + paramName + ": '" + oldValue
                    + "' -> '" + newValue + "']";
        }
        return "Mutation[NOT APPLIED " + location + " " + paramName + ": " + reason + "]";
    }
}

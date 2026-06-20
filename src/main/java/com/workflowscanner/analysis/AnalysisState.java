package com.workflowscanner.analysis;

/**
 * State machine for analysis lifecycle.
 */
public enum AnalysisState {
    QUEUED,
    ANALYZING,
    COMPLETE,
    FAILED,
    CANCELLED
}

package com.workflowscanner.llm;

import java.util.HashMap;
import java.util.Map;

/**
 * A test suggested by the LLM to validate a potential vulnerability.
 * Contains enough information to replay the request with modifications.
 */
public class SuggestedTest {

    private String testName;
    private String method;
    private String url;
    private Map<String, String> modifications;
    private String expectedBehavior;

    public SuggestedTest() {
        this.modifications = new HashMap<>();
    }

    public String getTestName() { return testName; }
    public void setTestName(String testName) { this.testName = testName; }

    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public Map<String, String> getModifications() { return modifications; }
    public void setModifications(Map<String, String> modifications) {
        this.modifications = modifications != null ? modifications : new HashMap<>();
    }

    public String getExpectedBehavior() { return expectedBehavior; }
    public void setExpectedBehavior(String expectedBehavior) { this.expectedBehavior = expectedBehavior; }

    @Override
    public String toString() {
        return String.format("%s: %s %s", testName, method, url);
    }
}

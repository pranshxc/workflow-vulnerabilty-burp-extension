package com.workflowscanner.llm;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Parses LLM JSON responses into structured LLMAnalysisResult objects.
 * Handles malformed responses gracefully.
 */
public class LLMResponseParser {

    private static final Gson GSON = new Gson();

    /**
     * Parse the raw API response body into an LLMAnalysisResult.
     *
     * @param rawResponse The full API response JSON
     * @param logger      Logger for error reporting
     * @return Parsed result, or null if unparseable
     */
    public static LLMAnalysisResult parse(String rawResponse, ExtensionLogger logger) {
        if (rawResponse == null || rawResponse.isEmpty()) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "LLMResponseParser",
                    "Empty response from LLM");
            return null;
        }

        try {
            // Extract the content from the chat completion response
            JsonObject root = JsonParser.parseString(rawResponse).getAsJsonObject();

            // Extract usage info for token tracking
            if (root.has("usage")) {
                JsonObject usage = root.getAsJsonObject("usage");
                if (usage.has("total_tokens")) {
                    // Token count available for stats
                }
            }

            // Get the assistant's message content
            String content = extractContent(root);
            if (content == null) {
                logger.log(LogCategory.ERROR, LogLevel.ERROR, "LLMResponseParser",
                        "No content in LLM response", rawResponse);
                return null;
            }

            // Parse the JSON content from the assistant's message
            return parseAnalysisJson(content, logger);

        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "LLMResponseParser",
                    "Failed to parse LLM response", e);
            return null;
        }
    }

    /**
     * Extract the assistant message content from the API response.
     */
    private static String extractContent(JsonObject root) {
        try {
            JsonArray choices = root.getAsJsonArray("choices");
            if (choices == null || choices.isEmpty()) return null;

            JsonObject firstChoice = choices.get(0).getAsJsonObject();
            JsonObject message = firstChoice.getAsJsonObject("message");
            if (message == null) return null;

            JsonElement content = message.get("content");
            return content != null ? content.getAsString() : null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Parse the analysis JSON from the assistant's message content.
     */
    private static LLMAnalysisResult parseAnalysisJson(String content, ExtensionLogger logger) {
        try {
            JsonObject json = JsonParser.parseString(content).getAsJsonObject();

            LLMAnalysisResult result = new LLMAnalysisResult();

            // Required fields
            result.setVerdict(getStringOrDefault(json, "verdict", "SAFE"));
            result.setConfidence(getDoubleOrDefault(json, "confidence", 0.0));

            // Optional fields
            result.setVulnerabilityType(getStringOrNull(json, "vulnerability_type"));
            result.setReasoning(getStringOrNull(json, "reasoning"));
            result.setAttackScenario(getStringOrNull(json, "attack_scenario"));
            result.setChainContextUpdate(getStringOrNull(json, "chain_context_update"));

            // Affected parameters
            if (json.has("affected_parameters") && json.get("affected_parameters").isJsonArray()) {
                List<String> params = new ArrayList<>();
                for (JsonElement el : json.getAsJsonArray("affected_parameters")) {
                    if (el.isJsonPrimitive()) params.add(el.getAsString());
                }
                result.setAffectedParameters(params);
            }

            // Suggested tests
            if (json.has("suggested_tests") && json.get("suggested_tests").isJsonArray()) {
                List<SuggestedTest> tests = new ArrayList<>();
                for (JsonElement el : json.getAsJsonArray("suggested_tests")) {
                    if (el.isJsonObject()) {
                        tests.add(parseSuggestedTest(el.getAsJsonObject()));
                    }
                }
                result.setSuggestedTests(tests);
            }

            // Validate verdict
            String verdict = result.getVerdict().toUpperCase();
            if (!"VULNERABLE".equals(verdict) && !"SUSPICIOUS".equals(verdict) && !"SAFE".equals(verdict)) {
                logger.log(LogCategory.LLM_RESPONSE, LogLevel.WARN, "LLMResponseParser",
                        "Unknown verdict '" + result.getVerdict() + "', defaulting to SAFE");
                result.setVerdict("SAFE");
            } else {
                result.setVerdict(verdict);
            }

            return result;

        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "LLMResponseParser",
                    "Failed to parse analysis JSON", content);
            return null;
        }
    }

    private static SuggestedTest parseSuggestedTest(JsonObject json) {
        SuggestedTest test = new SuggestedTest();
        test.setTestName(getStringOrNull(json, "test_name"));
        test.setMethod(getStringOrNull(json, "method"));
        test.setUrl(getStringOrNull(json, "url"));
        test.setExpectedBehavior(getStringOrNull(json, "expected_behavior"));

        if (json.has("modifications") && json.get("modifications").isJsonObject()) {
            Map<String, String> mods = new HashMap<>();
            for (Map.Entry<String, JsonElement> entry : json.getAsJsonObject("modifications").entrySet()) {
                if (entry.getValue().isJsonPrimitive()) {
                    mods.put(entry.getKey(), entry.getValue().getAsString());
                }
            }
            test.setModifications(mods);
        }

        return test;
    }

    /**
     * Extract token usage from the API response.
     */
    public static long extractTokenUsage(String rawResponse) {
        try {
            JsonObject root = JsonParser.parseString(rawResponse).getAsJsonObject();
            if (root.has("usage")) {
                JsonObject usage = root.getAsJsonObject("usage");
                if (usage.has("total_tokens")) {
                    return usage.get("total_tokens").getAsLong();
                }
            }
        } catch (Exception ignored) {}
        return 0;
    }

    // --- Utility ---

    private static String getStringOrNull(JsonObject json, String key) {
        if (!json.has(key) || json.get(key).isJsonNull()) return null;
        try { return json.get(key).getAsString(); } catch (Exception e) { return null; }
    }

    private static String getStringOrDefault(JsonObject json, String key, String defaultValue) {
        String val = getStringOrNull(json, key);
        return val != null ? val : defaultValue;
    }

    private static double getDoubleOrDefault(JsonObject json, String key, double defaultValue) {
        if (!json.has(key) || json.get(key).isJsonNull()) return defaultValue;
        try { return json.get(key).getAsDouble(); } catch (Exception e) { return defaultValue; }
    }
}

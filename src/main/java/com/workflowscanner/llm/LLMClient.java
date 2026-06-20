package com.workflowscanner.llm;

import com.workflowscanner.config.ExtensionConfig;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicLong;

/**
 * OpenAI-compatible HTTP client for LLM-based workflow vulnerability analysis.
 *
 * Features:
 * - Java HttpClient (no external HTTP dependencies)
 * - Configurable base URL, model, API key, temperature
 * - Retry logic with exponential backoff (max 3 retries)
 * - Rate limiting awareness (429 handling)
 * - Timeout handling (configurable, default 60s)
 * - Full request/response logging (no redaction)
 * - Async execution via CompletableFuture
 */
public class LLMClient {

    private final ExtensionConfig config;
    private final ExtensionLogger logger;
    private final HttpClient httpClient;

    private final AtomicLong totalRequests = new AtomicLong(0);
    private final AtomicLong totalTokensUsed = new AtomicLong(0);
    private final AtomicLong totalErrors = new AtomicLong(0);
    private volatile String lastError;

    public LLMClient(ExtensionConfig config, ExtensionLogger logger) {
        this.config = config;
        this.logger = logger;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .build();
    }

    /**
     * Send a chat completion request to the LLM.
     * Includes retry logic with exponential backoff.
     *
     * @param systemPrompt The system prompt
     * @param userMessage  The user message (node context + request data)
     * @return Raw JSON response body, or null on failure
     */
    public String sendChatCompletion(String systemPrompt, String userMessage) {
        String requestBody = buildRequestBody(systemPrompt, userMessage);
        String endpoint = config.getLlmBaseUrl().replaceAll("/+$", "") + "/chat/completions";

        logger.log(LogCategory.LLM_REQUEST, LogLevel.INFO, "LLMClient",
                "Sending chat completion to " + config.getLlmModelId(),
                requestBody);

        long startTime = System.currentTimeMillis();
        int maxRetries = config.getLlmMaxRetries();

        for (int attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                totalRequests.incrementAndGet();

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(endpoint))
                        .header("Content-Type", "application/json")
                        .header("Authorization", "Bearer " + config.getLlmApiKey())
                        .timeout(Duration.ofSeconds(config.getLlmTimeoutSeconds()))
                        .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                        .build();

                HttpResponse<String> response = httpClient.send(request,
                        HttpResponse.BodyHandlers.ofString());

                long latency = System.currentTimeMillis() - startTime;

                if (response.statusCode() == 200) {
                    logger.log(LogCategory.LLM_RESPONSE, LogLevel.INFO, "LLMClient",
                            "Response received (" + latency + "ms, attempt " + (attempt + 1) + ")",
                            response.body());
                    return response.body();
                }

                if (response.statusCode() == 429) {
                    // Rate limited - wait and retry
                    long waitMs = getRetryAfterMs(response, attempt);
                    logger.log(LogCategory.LLM_RESPONSE, LogLevel.WARN, "LLMClient",
                            "Rate limited (429). Waiting " + waitMs + "ms before retry "
                                    + (attempt + 1) + "/" + maxRetries);
                    Thread.sleep(waitMs);
                    continue;
                }

                if (response.statusCode() >= 500) {
                    // Server error - retry with backoff
                    long waitMs = (long) Math.pow(2, attempt) * 1000;
                    logger.log(LogCategory.LLM_RESPONSE, LogLevel.WARN, "LLMClient",
                            "Server error (" + response.statusCode() + "). Retrying in "
                                    + waitMs + "ms (attempt " + (attempt + 1) + "/" + maxRetries + ")",
                            response.body());
                    Thread.sleep(waitMs);
                    continue;
                }

                // Client error (4xx) - don't retry
                lastError = "HTTP " + response.statusCode() + ": " + response.body();
                totalErrors.incrementAndGet();
                logger.log(LogCategory.LLM_RESPONSE, LogLevel.ERROR, "LLMClient",
                        "Client error: " + response.statusCode(), response.body());
                return null;

            } catch (java.net.http.HttpTimeoutException e) {
                lastError = "Timeout after " + config.getLlmTimeoutSeconds() + "s";
                totalErrors.incrementAndGet();
                logger.log(LogCategory.ERROR, LogLevel.ERROR, "LLMClient",
                        "Request timed out (attempt " + (attempt + 1) + "/" + maxRetries + ")");
                if (attempt < maxRetries) {
                    try { Thread.sleep((long) Math.pow(2, attempt) * 1000); } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        return null;
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return null;
            } catch (Exception e) {
                lastError = e.getMessage();
                totalErrors.incrementAndGet();
                logger.log(LogCategory.ERROR, LogLevel.ERROR, "LLMClient",
                        "Request failed (attempt " + (attempt + 1) + "/" + maxRetries + ")", e);
                if (attempt < maxRetries) {
                    try { Thread.sleep((long) Math.pow(2, attempt) * 1000); } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        return null;
                    }
                }
            }
        }

        logger.log(LogCategory.ERROR, LogLevel.ERROR, "LLMClient",
                "All " + (maxRetries + 1) + " attempts failed.");
        return null;
    }

    /**
     * Send a chat completion asynchronously.
     */
    public CompletableFuture<String> sendChatCompletionAsync(String systemPrompt, String userMessage) {
        return CompletableFuture.supplyAsync(() -> sendChatCompletion(systemPrompt, userMessage));
    }

    /**
     * Test the LLM connection with current configuration.
     * Sends a minimal request to verify credentials and model availability.
     *
     * @return A status message (success info or error description)
     */
    public String testConnection() {
        if (!isConfigured()) {
            return "Not configured: API key or base URL missing";
        }

        logger.log(LogCategory.LLM_REQUEST, LogLevel.INFO, "LLMClient",
                "Testing connection to " + config.getLlmBaseUrl()
                        + " with model " + config.getLlmModelId());

        String response = sendChatCompletion(
                "You are a helpful assistant. Respond with a brief JSON object.",
                "Respond with: {\"status\": \"ok\", \"model\": \"your_model_name\"}");

        if (response != null) {
            String msg = "Connected successfully to " + config.getLlmModelId();
            logger.log(LogCategory.LLM_RESPONSE, LogLevel.INFO, "LLMClient", msg);
            return msg;
        } else {
            String msg = "Connection failed: " + (lastError != null ? lastError : "unknown error");
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "LLMClient", msg);
            return msg;
        }
    }

    /**
     * Check if the client is configured (has API key and base URL).
     */
    public boolean isConfigured() {
        return config.getLlmApiKey() != null && !config.getLlmApiKey().isEmpty()
                && config.getLlmBaseUrl() != null && !config.getLlmBaseUrl().isEmpty();
    }

    // --- Internal ---

    private String buildRequestBody(String systemPrompt, String userMessage) {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        sb.append("\"model\":\"").append(escapeJson(config.getLlmModelId())).append("\",");
        sb.append("\"messages\":[");
        sb.append("{\"role\":\"system\",\"content\":\"").append(escapeJson(systemPrompt)).append("\"},");
        sb.append("{\"role\":\"user\",\"content\":\"").append(escapeJson(userMessage)).append("\"}");
        sb.append("],");
        sb.append("\"temperature\":").append(config.getLlmTemperature()).append(',');
        sb.append("\"response_format\":{\"type\":\"json_object\"}");
        sb.append('}');
        return sb.toString();
    }

    private long getRetryAfterMs(HttpResponse<String> response, int attempt) {
        // Try to parse Retry-After header
        var retryAfter = response.headers().firstValue("Retry-After");
        if (retryAfter.isPresent()) {
            try {
                return Long.parseLong(retryAfter.get()) * 1000;
            } catch (NumberFormatException ignored) {}
        }
        // Exponential backoff fallback
        return (long) Math.pow(2, attempt + 1) * 1000;
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    // --- Statistics ---

    public long getTotalRequests() { return totalRequests.get(); }
    public long getTotalTokensUsed() { return totalTokensUsed.get(); }
    public long getTotalErrors() { return totalErrors.get(); }
    public String getLastError() { return lastError; }
    public void addTokensUsed(long tokens) { totalTokensUsed.addAndGet(tokens); }
}

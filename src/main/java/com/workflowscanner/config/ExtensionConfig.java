package com.workflowscanner.config;

import burp.api.montoya.MontoyaApi;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration POJO for the Workflow Vulnerability Scanner.
 * Serializable to/from JSON for persistence via Burp's persistence API.
 */
public class ExtensionConfig {

    private static final String PERSISTENCE_KEY = "workflow_vuln_scanner_config";
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    // --- LLM Configuration ---
    private String llmBaseUrl = "https://api.openai.com/v1";
    private String llmModelId = "gpt-4";
    private String llmApiKey = "";
    private double llmTemperature = 0.2;
    private int llmTimeoutSeconds = 60;
    private int llmMaxRetries = 3;
    private int llmMaxContextTokens = 8000;

    // --- Graph Data ---
    private String graphDataDirectory = "";
    private int graphAutoSaveIntervalSeconds = 60;

    // --- Backfill ---
    private int backfillLimit = 500;
    private boolean backfillInScopeOnly = true;

    // --- Scope Filter ---
    private List<String> scopeFilterPatterns = new ArrayList<>();

    // --- Analysis ---
    private int analysisConcurrency = 1;
    private boolean autoAnalyzeNewChains = false;
    private String validationProfile = "standard"; // conservative, standard, aggressive

    // --- Logging ---
    private int logRingBufferSize = 10000;
    private boolean fileLoggingEnabled = false;
    private String logFileDirectory = "";

    // --- Request Pipeline ---
    private int pipelineQueueCapacity = 5000;

    // --- Constructors ---

    public ExtensionConfig() {
        // Defaults set above
    }

    // --- Persistence ---

    /**
     * Load configuration from Burp's persistence API.
     * Falls back to defaults if no saved config exists.
     */
    public static ExtensionConfig load(MontoyaApi api) {
        try {
            String json = api.persistence().preferences().getString(PERSISTENCE_KEY);
            if (json != null && !json.isEmpty()) {
                ExtensionConfig loaded = GSON.fromJson(json, ExtensionConfig.class);
                if (loaded != null) {
                    return loaded;
                }
            }
        } catch (Exception e) {
            api.logging().logToOutput("[WARN] Could not load saved config, using defaults: " + e.getMessage());
        }
        return new ExtensionConfig();
    }

    /**
     * Save configuration to Burp's persistence API.
     */
    public void save(MontoyaApi api) {
        try {
            String json = GSON.toJson(this);
            api.persistence().preferences().setString(PERSISTENCE_KEY, json);
        } catch (Exception e) {
            api.logging().logToOutput("[ERROR] Could not save config: " + e.getMessage());
        }
    }

    /**
     * Serialize to JSON string.
     */
    public String toJson() {
        return GSON.toJson(this);
    }

    /**
     * Deserialize from JSON string.
     */
    public static ExtensionConfig fromJson(String json) {
        return GSON.fromJson(json, ExtensionConfig.class);
    }

    /**
     * Reset all settings to defaults.
     */
    public void resetToDefaults() {
        ExtensionConfig defaults = new ExtensionConfig();
        this.llmBaseUrl = defaults.llmBaseUrl;
        this.llmModelId = defaults.llmModelId;
        this.llmApiKey = defaults.llmApiKey;
        this.llmTemperature = defaults.llmTemperature;
        this.llmTimeoutSeconds = defaults.llmTimeoutSeconds;
        this.llmMaxRetries = defaults.llmMaxRetries;
        this.llmMaxContextTokens = defaults.llmMaxContextTokens;
        this.graphDataDirectory = defaults.graphDataDirectory;
        this.graphAutoSaveIntervalSeconds = defaults.graphAutoSaveIntervalSeconds;
        this.backfillLimit = defaults.backfillLimit;
        this.backfillInScopeOnly = defaults.backfillInScopeOnly;
        this.scopeFilterPatterns = new ArrayList<>(defaults.scopeFilterPatterns);
        this.analysisConcurrency = defaults.analysisConcurrency;
        this.autoAnalyzeNewChains = defaults.autoAnalyzeNewChains;
        this.validationProfile = defaults.validationProfile;
        this.logRingBufferSize = defaults.logRingBufferSize;
        this.fileLoggingEnabled = defaults.fileLoggingEnabled;
        this.logFileDirectory = defaults.logFileDirectory;
        this.pipelineQueueCapacity = defaults.pipelineQueueCapacity;
    }

    // --- Getters and Setters ---

    public String getLlmBaseUrl() { return llmBaseUrl; }
    public void setLlmBaseUrl(String llmBaseUrl) { this.llmBaseUrl = llmBaseUrl; }

    public String getLlmModelId() { return llmModelId; }
    public void setLlmModelId(String llmModelId) { this.llmModelId = llmModelId; }

    public String getLlmApiKey() { return llmApiKey; }
    public void setLlmApiKey(String llmApiKey) { this.llmApiKey = llmApiKey; }

    public double getLlmTemperature() { return llmTemperature; }
    public void setLlmTemperature(double llmTemperature) { this.llmTemperature = llmTemperature; }

    public int getLlmTimeoutSeconds() { return llmTimeoutSeconds; }
    public void setLlmTimeoutSeconds(int llmTimeoutSeconds) { this.llmTimeoutSeconds = llmTimeoutSeconds; }

    public int getLlmMaxRetries() { return llmMaxRetries; }
    public void setLlmMaxRetries(int llmMaxRetries) { this.llmMaxRetries = llmMaxRetries; }

    public int getLlmMaxContextTokens() { return llmMaxContextTokens; }
    public void setLlmMaxContextTokens(int llmMaxContextTokens) { this.llmMaxContextTokens = llmMaxContextTokens; }

    public String getGraphDataDirectory() { return graphDataDirectory; }
    public void setGraphDataDirectory(String graphDataDirectory) { this.graphDataDirectory = graphDataDirectory; }

    public int getGraphAutoSaveIntervalSeconds() { return graphAutoSaveIntervalSeconds; }
    public void setGraphAutoSaveIntervalSeconds(int s) { this.graphAutoSaveIntervalSeconds = s; }

    public int getBackfillLimit() { return backfillLimit; }
    public void setBackfillLimit(int backfillLimit) { this.backfillLimit = backfillLimit; }

    public boolean isBackfillInScopeOnly() { return backfillInScopeOnly; }
    public void setBackfillInScopeOnly(boolean backfillInScopeOnly) { this.backfillInScopeOnly = backfillInScopeOnly; }

    public List<String> getScopeFilterPatterns() { return scopeFilterPatterns; }
    public void setScopeFilterPatterns(List<String> scopeFilterPatterns) {
        this.scopeFilterPatterns = scopeFilterPatterns != null ? scopeFilterPatterns : new ArrayList<>();
    }

    public int getAnalysisConcurrency() { return analysisConcurrency; }
    public void setAnalysisConcurrency(int analysisConcurrency) { this.analysisConcurrency = analysisConcurrency; }

    public boolean isAutoAnalyzeNewChains() { return autoAnalyzeNewChains; }
    public void setAutoAnalyzeNewChains(boolean autoAnalyzeNewChains) { this.autoAnalyzeNewChains = autoAnalyzeNewChains; }

    public String getValidationProfile() { return validationProfile; }
    public void setValidationProfile(String validationProfile) { this.validationProfile = validationProfile; }

    public int getLogRingBufferSize() { return logRingBufferSize; }
    public void setLogRingBufferSize(int logRingBufferSize) { this.logRingBufferSize = logRingBufferSize; }

    public boolean isFileLoggingEnabled() { return fileLoggingEnabled; }
    public void setFileLoggingEnabled(boolean fileLoggingEnabled) { this.fileLoggingEnabled = fileLoggingEnabled; }

    public String getLogFileDirectory() { return logFileDirectory; }
    public void setLogFileDirectory(String logFileDirectory) { this.logFileDirectory = logFileDirectory; }

    public int getPipelineQueueCapacity() { return pipelineQueueCapacity; }
    public void setPipelineQueueCapacity(int pipelineQueueCapacity) { this.pipelineQueueCapacity = pipelineQueueCapacity; }
}

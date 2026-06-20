package com.workflowscanner.config;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Validates extension configuration before operations.
 * Returns clear error messages for invalid settings.
 */
public class ConfigValidator {

    /**
     * Validate LLM configuration.
     * @return List of error messages (empty if valid)
     */
    public static List<String> validateLLMConfig(ExtensionConfig config) {
        List<String> errors = new ArrayList<>();

        if (config.getLlmBaseUrl() == null || config.getLlmBaseUrl().trim().isEmpty()) {
            errors.add("LLM Base URL is required.");
        } else if (!config.getLlmBaseUrl().startsWith("http")) {
            errors.add("LLM Base URL must start with http:// or https://");
        }

        if (config.getLlmModelId() == null || config.getLlmModelId().trim().isEmpty()) {
            errors.add("LLM Model ID is required.");
        }

        if (config.getLlmApiKey() == null || config.getLlmApiKey().trim().isEmpty()) {
            errors.add("LLM API Key is required.");
        }

        if (config.getLlmTimeoutSeconds() < 5 || config.getLlmTimeoutSeconds() > 300) {
            errors.add("LLM timeout must be between 5 and 300 seconds.");
        }

        return errors;
    }

    /**
     * Validate graph data directory.
     * @return List of error messages (empty if valid)
     */
    public static List<String> validateGraphDirectory(ExtensionConfig config) {
        List<String> errors = new ArrayList<>();
        String dir = config.getGraphDataDirectory();

        if (dir != null && !dir.trim().isEmpty()) {
            File dirFile = new File(dir);
            if (dirFile.exists() && !dirFile.isDirectory()) {
                errors.add("Graph data path exists but is not a directory: " + dir);
            } else if (dirFile.exists() && !dirFile.canWrite()) {
                errors.add("Graph data directory is not writable: " + dir);
            }
            // If it doesn't exist, it will be created on save
        }

        return errors;
    }

    /**
     * Validate scope filter patterns.
     * @return List of error messages (empty if valid)
     */
    public static List<String> validateScopePatterns(ExtensionConfig config) {
        List<String> errors = new ArrayList<>();

        if (config.getScopeFilterPatterns() != null) {
            for (int i = 0; i < config.getScopeFilterPatterns().size(); i++) {
                String pattern = config.getScopeFilterPatterns().get(i);
                if (pattern == null || pattern.trim().isEmpty()) continue;

                try {
                    // Convert glob to regex and validate
                    String regex = globToRegex(pattern.trim());
                    Pattern.compile(regex);
                } catch (PatternSyntaxException e) {
                    errors.add("Invalid scope pattern at line " + (i + 1)
                            + " ('" + pattern + "'): " + e.getMessage());
                }
            }
        }

        return errors;
    }

    /**
     * Validate all configuration.
     * @return List of all error messages (empty if everything is valid)
     */
    public static List<String> validateAll(ExtensionConfig config) {
        List<String> errors = new ArrayList<>();
        errors.addAll(validateGraphDirectory(config));
        errors.addAll(validateScopePatterns(config));
        // LLM config is optional (only needed for analysis)
        return errors;
    }

    private static String globToRegex(String glob) {
        StringBuilder regex = new StringBuilder("^(?i)");
        for (int i = 0; i < glob.length(); i++) {
            char c = glob.charAt(i);
            switch (c) {
                case '*': regex.append(".*"); break;
                case '?': regex.append('.'); break;
                case '.': regex.append("\\."); break;
                default: regex.append(c); break;
            }
        }
        regex.append('$');
        return regex.toString();
    }
}

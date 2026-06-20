# Workflow Vulnerability Scanner — Burp Suite Extension

A Burp Suite extension that detects **multi-step workflow vulnerabilities** by building a request graph, analyzing chains with an LLM, and validating findings via request replay.

## Features

- **Request Graph** — Automatically builds a directed graph of HTTP request relationships (redirects, referrers, parameter reuse, response correlation)
- **LLM-Powered Analysis** — Sends workflow chains to an OpenAI-compatible LLM for vulnerability analysis using attacker mental models (step skipping, value manipulation, race conditions, etc.)
- **Automated Validation** — Confirms findings by replaying requests with mutations
- **Burp Integration** — Reports findings as native Burp scanner issues with full evidence
- **Three Data Sources** — Live proxy traffic, proxy history backfill, and context menu selection

## Requirements

- **Java 17+**
- **Burp Suite Professional** (with Montoya API support)
- **Gradle 8.7+** (wrapper included)

## Building

```bash
# Clone the repository
git clone https://gitlab.com/xcpransh15-group/workflow-vulnerabilty-burp-extension.git
cd workflow-vulnerabilty-burp-extension

# Build the fat JAR
./gradlew shadowJar

# The JAR will be at:
# build/libs/workflow-vuln-scanner-1.0.0.jar
```

## Installation

1. Build the JAR (see above)
2. Open Burp Suite → Extensions → Add
3. Select "Java" as the extension type
4. Browse to `build/libs/workflow-vuln-scanner-1.0.0.jar`
5. Click "Next" — the extension loads and registers a "Workflow Vulnerability Scanner" tab

## Configuration

After loading, go to the **Workflow Vulnerability Scanner** tab → **Settings**:

1. **LLM Configuration** — Set your OpenAI-compatible API base URL, model ID, and API key
2. **Graph Data Directory** — Set a directory for persisting graph data between sessions
3. **Scope Filter** — Add glob patterns to limit scanning to target hosts (e.g., `*.example.com`)
4. **Backfill** — Configure how many historical proxy requests to import

## Project Structure

```
src/main/java/com/workflowscanner/
├── WorkflowVulnScanner.java      # Extension entry point (Montoya API)
├── config/
│   └── ExtensionConfig.java      # Settings POJO with JSON persistence
├── logging/
│   ├── ExtensionLogger.java      # Thread-safe ring buffer logger
│   ├── LogCategory.java          # Log categories (LLM, GRAPH, ANALYSIS, etc.)
│   ├── LogLevel.java             # Log levels (DEBUG, INFO, WARN, ERROR)
│   └── LogEntry.java             # Log entry model
├── data/
│   ├── CapturedRequest.java      # Unified request/response model
│   ├── RequestPipeline.java      # Thread-safe request queue
│   ├── ProxyListener.java        # Live proxy traffic capture
│   ├── ContextMenuProvider.java  # Right-click context menu
│   ├── ScopeFilter.java          # Glob-based scope filtering
│   └── BackfillService.java      # Proxy history backfill
├── graph/
│   ├── RequestGraph.java         # Core graph data structure
│   ├── RequestNode.java          # Graph node (request/response)
│   ├── RequestEdge.java          # Graph edge (relationship)
│   ├── EdgeType.java             # Edge type enum
│   └── GraphBuilder.java         # Graph construction & persistence
├── llm/
│   ├── LLMClient.java            # OpenAI-compatible API client
│   ├── LLMContextManager.java    # Rolling context management
│   ├── LLMAnalysisResult.java    # Parsed LLM response
│   ├── NodeAnalysisContext.java   # Per-node analysis context
│   └── SuggestedTest.java        # LLM-suggested validation test
├── analysis/
│   ├── AnalysisEngine.java       # Chain analysis orchestrator
│   ├── ChainVerdict.java         # Chain-level verdict
│   └── ChainPrioritizer.java     # Chain scoring & prioritization
├── validation/
│   ├── ValidationEngine.java     # Request replay & confirmation
│   └── ValidationResult.java     # Validation test result
├── advisory/
│   └── AdvisoryManager.java      # Burp scanner issue creation
└── ui/
    └── MainTabPanel.java         # Main UI tab with sub-panels
```

## Architecture

```
[Proxy/Backfill/Context Menu] → [Scope Filter] → [Request Pipeline]
    → [Graph Builder] → [Chain Prioritizer] → [Analysis Engine + LLM]
    → [Validation Engine] → [Advisory Layer → Burp Issues]
```

## License

MIT

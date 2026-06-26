package com.workflowscanner.classification;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Universal, target-agnostic noise-rule configuration.
 *
 * <p>Every rule group below applies to any web target — banking apps,
 * SaaS dashboards, e-commerce, blockchain, government portals, etc.
 * The defaults are deliberately broad so that low-signal traffic
 * (telemetry, feature flags, public lookups) is suppressed regardless
 * of the host. Users may override or extend the lists for target
 * specific noise.
 *
 * <p><b>Design rules:</b>
 * <ul>
 *   <li>No host names, no path fragments unique to one product.</li>
 *   <li>No blockchain-only regexes (no 0x+40hex, no base58).</li>
 *   <li>No "if host contains X" branches anywhere in the pipeline.</li>
 *   <li>Every list is exposed via getters/setters so the config is
 *       serializable and the user can audit it from the UI.</li>
 * </ul>
 *
 * <p>The interaction model is:
 * <pre>
 *   telemetry / feature-flag / polling / infrastructure-host
 *      -> suppress in classifier (intent = TELEMETRY_ANALYTICS /
 *         FEATURE_FLAG_CONFIG / BACKGROUND_POLLING)
 *
 *   public-resource path + no private-context + read-only
 *      -> suppress as public resource (intent = PUBLIC_DATA_LOOKUP)
 *
 *   public-resource path + private-context OR state-changing
 *      -> treat as business request (intent = BUSINESS_READ /
 *         BUSINESS_ACTION)
 *
 *   private-resource path
 *      -> treat as private request (intent = BUSINESS_READ /
 *         BUSINESS_ACTION)
 * </pre>
 */
public class NoiseRulesConfig {

    // ---------------------------------------------------------------
    // Telemetry / analytics / RUM path patterns.
    //
    // A path that contains one of these substrings is classified
    // as TELEMETRY_ANALYTICS and is never a workflow candidate.
    // These are universal — they appear on every product that
    // ships an analytics or observability SDK.
    // ---------------------------------------------------------------
    private List<String> telemetryPathPatterns = Collections.unmodifiableList(Arrays.asList(
            // Generic instrumentation
            "/collect", "/metrics", "/telemetry", "/analytics",
            "/beacon", "/rum", "/faro", "/sentry", "/datadog",
            "/amplitude", "/hotjar", "/mixpanel", "/segment",
            "/newrelic", "/nr-data", "/rollbar", "/bugsnag",
            "/raygun", "/airbrake", "/logrocket", "/fullstory",
            "/loggly", "/papertrail", "/track", "/tracker",
            "/pixel", "/pageview", "/impression", "/visit",
            // Common analytics-SDK endpoint fragments
            "/log_event", "/log-event", "/event-stream",
            "/events/track", "/crash-report", "/error-tracking",
            "/session-replay", "/heatmap"
    ));

    // ---------------------------------------------------------------
    // Hosts known to be third-party observability / feature-flag /
    // analytics vendors. Substring match against the request host.
    // ---------------------------------------------------------------
    private List<String> telemetryHostPatterns = Collections.unmodifiableList(Arrays.asList(
            // Google / Facebook / generic ad-tech
            "google-analytics", "googletagmanager", "doubleclick",
            "facebook.com", "fbsbx.com",
            // Heatmap / session replay
            "hotjar.com", "fullstory.com", "crazyegg.com",
            // Error tracking / APM
            "sentry.io", "datadoghq.com", "appdynamics.com",
            "newrelic.com", "nr-data.net", "nr-data.io",
            // Product analytics
            "mixpanel.com", "amplitude.com", "segment.io", "segment.com",
            "optimizely.com",
            // Feature flag services
            "unleash", "launchdarkly", "split.io", "statsig",
            "app.launchdarkly", "cdn.launchdarkly", "events.launchdarkly",
            "statsigapi", "api.statsig",
            "api.amplitude", "api2.amplitude", "api.segment",
            "api.mixpanel", "api.hotjar", "script.hotjar",
            // RUM / Faro / Sentry ingest
            "browser-intake-datadoghq", "public-trace.datadoghq",
            "rum-collector", "faro-collector",
            "ingest.sentry", "browser.sentry-cdn"
    ));

    // ---------------------------------------------------------------
    // Feature-flag / config / experimentation endpoints.
    //
    // These are not business actions even when the path lives on
    // the primary application host (e.g. /api/feature-flags,
    // /api/client/features).
    // ---------------------------------------------------------------
    private List<String> featureFlagPathPatterns = Collections.unmodifiableList(Arrays.asList(
            "/feature-flags", "/feature_flags", "/featureflag",
            "/feature-flag", "/flags", "/launchdarkly", "/ld-",
            "/split", "/unleash", "/experiments", "/ab-tests",
            "/ab_tests", "/a-b-test", "/variant", "/variants",
            "/api/client/features", "/api/features",
            "/feature-config", "/flags.json", "/flags.yaml",
            "/flags.yml", "/bootstrap", "/config/feature"
    ));

    // ---------------------------------------------------------------
    // Background-polling path patterns.
    //
    // A path that contains one of these substrings is classified
    // as BACKGROUND_POLLING. These are universal — every SPA, mobile
    // app, or dashboard periodically hits one of these.
    // ---------------------------------------------------------------
    private List<String> pollingPathPatterns = Collections.unmodifiableList(Arrays.asList(
            "/notifications", "/notification",
            "/messages/unread", "/unread-count", "/unread_count",
            "/heartbeat", "/poll", "/events",
            "/session/refresh", "/token/refresh",
            "/keepalive", "/keep-alive",
            "/presence", "/online", "/typing",
            "/sse", "/websocket", "/ws",
            "/config", "/configuration", "/featureflag", "/feature-flag"
    ));

    // ---------------------------------------------------------------
    // Public-resource path patterns.
    //
    // A request whose path contains one of these substrings AND
    // whose chain carries no private context is treated as a
    // public-data lookup and is never a workflow candidate. The
    // lists are intentionally generic: financial, weather, stock,
    // catalog, blog, lookup, search, address lookup, etc.
    // ---------------------------------------------------------------
    private List<String> publicResourcePathPatterns = Collections.unmodifiableList(Arrays.asList(
            // Finance / markets / rates / prices / gas
            "/price/", "/prices/", "/quote/", "/quotes/",
            "/rate/", "/rates/", "/exchange-rate", "/fx/",
            "/stock/", "/stocks/", "/market-data", "/marketcap/",
            "/chart/", "/finance/chart", "/finance/quote",
            // Gas (blockchain transaction cost, cloud cost gas,
            // fuel cost, etc.) — universal public data.
            "/gas-price", "/gasprice", "/gas-oracle", "/gasoracle",
            "/fees/gas", "/api/gas", "/v1/gas", "/v2/gas",
            // Weather / location
            "/weather/", "/forecast/",
            // Catalog / search / lookup
            "/products/", "/items/", "/catalog/",
            "/search/", "/lookup/", "/public/",
            // Content (blog, news, articles)
            "/blog/posts/", "/articles/", "/news/",
            // User-generated content with public visibility
            "/posts/", "/comments/",
            // Public identifiers / address / token
            // (works for blockchain wallets, public profile
            //  handles, public organization slugs, etc.)
            "/balance/", "/balances/", "/wallet/", "/wallets/",
            "/address/", "/addresses/", "/token/", "/tokens/",
            "/public-key/", "/public_key/"
    ));

    // ---------------------------------------------------------------
    // Private / user-bound path patterns.
    //
    // If any step in a candidate's chain matches one of these
    // substrings, the candidate is considered to have private
    // context — even if it also touches a public-resource keyword.
    // This is what stops the gate from suppressing real
    // authenticated /me/balance or /account/orders findings.
    // ---------------------------------------------------------------
    private List<String> privateResourcePathPatterns = Collections.unmodifiableList(Arrays.asList(
            // Self / current user
            "/me", "/my", "/self", "/owner",
            // Account / profile / settings
            "/account", "/accounts", "/profile", "/profiles",
            "/settings", "/preferences", "/preference",
            // Billing / invoice / subscription
            "/billing", "/invoice", "/invoices",
            "/subscription", "/plan",
            // Admin / tenant / org / workspace / team
            "/admin", "/tenant", "/org", "/organization",
            "/workspace", "/team", "/member", "/members",
            "/staff", "/internal/",
            // User-specific resources
            "/user/", "/users/", "/customer/",
            // Private dashboards
            "/dashboard", "/private/", "/internal-api/",
            // Document / file (private)
            "/document/", "/documents/", "/file/", "/files/",
            "/attachment", "/attachments"
    ));

    // ---------------------------------------------------------------
    // Cookie names that are infrastructure / anti-bot / tracking.
    //
    // Edges (PARAM_REUSE / RESPONSE_CORRELATION) are never created
    // on these. Substring match against the cookie name; trailing
    // wildcards are added automatically.
    //
    // <p><b>DO NOT add application session cookies here.</b>
    // JSESSIONID, PHPSESSID, ASP.NET_SessionId, etc. are
    // <i>authentication</i> cookies and belong in
    // {@link #authSessionCookieNames} instead. Putting them here
    // would cause the PrivateContextDetector to misclassify
    // authenticated requests as public-resource lookups.
    // ---------------------------------------------------------------
    private List<String> infrastructureCookieNames = Collections.unmodifiableList(Arrays.asList(
            // Cloudflare
            "__cf_bm", "cf_clearance", "_cfuid", "_cflb", "cf_bm",
            // Akamai / Imperva / Incapsula
            "ak_bmsc", "bm_sz", "incap_ses_", "visid_incap",
            "nlbi_", "reese84", "reese_script",
            // PerimeterX
            "_pxvid", "_px3", "_pxde", "pxcts", "_pxhd",
            // AWS ELB / F5
            "awsalb", "awsalbcors", "awselb",
            // Google Analytics
            "_ga", "_gid", "_gat", "_gcl_",
            // Hotjar
            "_hj", "_hjid",
            // Amplitude / Segment / Mixpanel
            "amplitude_id", "amplitude_", "ajs_", "ajs_anonymous_id",
            "mp_", "rl_", "rl_anonymous_id",
            // Datadog / RUM
            "_dd_s",
            // Optimizely
            "optimizely_"
    ));

    // ---------------------------------------------------------------
    // Cookie names that indicate an authenticated session.
    //
    // Presence of any of these in a request's Cookie header makes
    // the request auth-bound for private-context detection. These
    // are universal — they appear in Java (JSESSIONID), PHP
    // (PHPSESSID), .NET (ASP.NET_SessionId), Express
    // (connect.sid), generic frameworks (session, sid, token,
    // auth, jwt, access_token, refresh_token, id_token), and
    // many SaaS products.
    //
    // <p>Match semantics: a cookie name matches if it equals the
    // pattern or starts with the pattern (so {@code session}
    // matches {@code session}, {@code session_id},
    // {@code sessionId}, etc.).
    // ---------------------------------------------------------------
    private List<String> authSessionCookieNames = Collections.unmodifiableList(Arrays.asList(
            // Java
            "jsessionid", "jsessionidsso",
            // PHP
            "phpsessid",
            // .NET
            "asp.net_sessionid", "aspsessionid",
            // Express / connect
            "connect.sid", "connect.sid.sig",
            // Generic session / sid
            "session", "sessionid", "session_id", "session-id",
            "sid", "sess",
            // Generic auth / token
            "auth", "authentication",
            "token", "access_token", "access-token", "accesstoken",
            "refresh_token", "refresh-token", "refreshtoken",
            "id_token", "id-token", "idtoken",
            "bearer", "jwt",
            // Common SaaS session cookies
            "logged_in", "loggedin", "user_session", "user-session",
            "x-xsrf-token", "csrf_token", "csrf-token"
    ));

    // ---------------------------------------------------------------
    // Request header names that indicate auth / identity.
    //
    // If a request carries any of these headers, the request is
    // considered auth-bound for private-context detection.
    // ---------------------------------------------------------------
    private List<String> privateRequestHeaders = Collections.unmodifiableList(Arrays.asList(
            "authorization",
            "cookie",
            "x-auth-token", "x-api-key", "x-session-token",
            "x-user-id", "x-tenant-id", "x-account-id",
            "x-csrf-token", "x-xsrf-token"
    ));

    // ---------------------------------------------------------------
    // Response field names that indicate private / sensitive data.
    //
    // If a response body contains any of these field names, the
    // step is considered to carry private context.
    // ---------------------------------------------------------------
    private List<String> privateResponseFields = Collections.unmodifiableList(Arrays.asList(
            "email", "phone", "ssn", "address",
            "billing", "invoice", "subscription", "plan",
            "role", "permission", "tenant_id", "organization_id",
            "workspace_id", "account_id", "user_id",
            "api_key", "secret", "password_hash"
    ));

    // ---------------------------------------------------------------
    // Context-read path patterns (auth context, retained for the
    // ApplicationModel). Only safe methods (GET/HEAD) on these
    // paths are context reads; POST/PUT/PATCH/DELETE are real
    // workflow actions and must NOT be classified as context reads.
    // ---------------------------------------------------------------
    private List<String> contextReadPaths = Collections.unmodifiableList(Arrays.asList(
            "/api/me", "/api/v1/me", "/api/v2/me",
            "/api/current-user", "/api/current_user",
            "/api/session", "/api/v1/session",
            "/api/auth/me", "/api/auth/session"
    ));

    // ---------------------------------------------------------------
    // Health-check path patterns. Universal across web frameworks.
    // ---------------------------------------------------------------
    private List<String> healthCheckPaths = Collections.unmodifiableList(Arrays.asList(
            "/health", "/healthz", "/ready", "/readyz",
            "/live", "/livez", "/ping", "/pong", "/status",
            "/_ah/health", "/actuator/health", "/actuator/info",
            "/__lb", "/lbcheck", "/elb-status", "/nginx_status"
    ));

    // ---------------------------------------------------------------
    // Workflow-state token keywords.
    //
    // Substring match. If a cookie or parameter name contains
    // one of these substrings (e.g. "payment_token",
    // "invite_token", "checkout_state", "reset_code",
    // "flow_step", "wizard_state", "transaction_id",
    // "approval_token", "order_state", "cart_token"), the
    // request is treated as carrying a business workflow
    // token, NOT as an auth/session cookie, and the
    // RelationshipDetector creates PARAM_REUSE /
    // RESPONSE_CORRELATION edges for it.
    //
    // The list works in tandem with the exact-match
    // auth-session skip set in RelationshipDetector:
    //
    //   1. If the name is an infrastructure/tracking cookie
    //      (in infrastructureCookieNames), skip the edge.
    //   2. If the name EXACTLY matches an auth-session name
    //      (access_token, refresh_token, id_token, jwt,
    //      session, sessionid, jsessionid, phpsessid,
    //      connect.sid, asp.net_sessionid), skip the edge.
    //   3. If the name contains a workflow-state keyword
    //      from this list, allow the edge.
    //   4. Otherwise, skip (fail-safe: unknown = auth).
    //
    // This preserves real workflow-token edges (payment,
    // checkout, invite, reset, approval, etc.) while still
    // suppressing auth/infra cookies. Universal — applies
    // to any web app that uses standard workflow tokens.
    // ---------------------------------------------------------------
    private List<String> workflowStateKeywords = Collections.unmodifiableList(Arrays.asList(
            "payment", "checkout", "invite", "invitation",
            "reset", "approval", "approve",
            "flow", "wizard", "state",
            "transaction", "order", "cart",
            "register", "signup", "verification",
            "receipt", "ticket", "case", "claim"
    ));

    // ---------------------------------------------------------------
    // Realism-upgrade-2 / per-target user vocabulary
    //
    // The static seed lists above are coarse. For non-fintech
    // targets (Airbnb, HelloFresh, healthcare, education, etc.) the
    // user can supply their own terms in four categories. These
    // are loaded into the TargetVocabulary at extension startup
    // with source=USER (highest weight). Adding a term here makes
    // the learner treat it as learned on the very first request
    // — no traffic is required.
    //
    // Default values are empty: this is a pure opt-in extension
    // point. Static seeds and learned terms still cover the
    // common case.
    // ---------------------------------------------------------------
    private List<String> customBusinessNouns = Collections.emptyList();
    private List<String> customActionVerbs = Collections.emptyList();
    private List<String> customSensitiveFields = Collections.emptyList();
    private List<String> customWorkflowTerms = Collections.emptyList();

    // ---------------------------------------------------------------
    // Realism-upgrade-2 / Issue 2: separate LLM-inferred storage
    //
    // The LLM vocabulary learner writes to these lists (not the
    // custom* lists) so that LLM-inferred terms keep their
    // LLM_INFERRED source (default weight 0.5) even after the
    // user saves settings. The custom* lists remain USER-source
    // (weight 1.0) and are reserved for terms the user has
    // explicitly chosen.
    //
    // Promotion: the SettingsPanel exposes these lists in a
    // read-only section with a "Promote to user" button per
    // area. Until the user promotes, LLM-inferred terms are
    // applied at runtime with the lower LLM weight so a
    // hallucination cannot dominate scoring.
    // ---------------------------------------------------------------
    private List<String> llmInferredBusinessNouns = Collections.emptyList();
    private List<String> llmInferredActionVerbs = Collections.emptyList();
    private List<String> llmInferredSensitiveFields = Collections.emptyList();
    private List<String> llmInferredWorkflowTerms = Collections.emptyList();

    // ---------------------------------------------------------------
    // Getters / setters. Lists are exposed as mutable copies so
    // tests and user overrides can append without altering the
    // shared defaults. Use {@link #withDefaults()} to get a
    // fresh copy.
    // ---------------------------------------------------------------

    public List<String> getTelemetryPathPatterns() {
        return new ArrayList<>(telemetryPathPatterns);
    }

    public void setTelemetryPathPatterns(List<String> v) {
        this.telemetryPathPatterns = v != null ? Collections.unmodifiableList(new ArrayList<>(v))
                : Collections.emptyList();
    }

    public List<String> getTelemetryHostPatterns() {
        return new ArrayList<>(telemetryHostPatterns);
    }

    public void setTelemetryHostPatterns(List<String> v) {
        this.telemetryHostPatterns = v != null ? Collections.unmodifiableList(new ArrayList<>(v))
                : Collections.emptyList();
    }

    public List<String> getFeatureFlagPathPatterns() {
        return new ArrayList<>(featureFlagPathPatterns);
    }

    public void setFeatureFlagPathPatterns(List<String> v) {
        this.featureFlagPathPatterns = v != null ? Collections.unmodifiableList(new ArrayList<>(v))
                : Collections.emptyList();
    }

    public List<String> getPollingPathPatterns() {
        return new ArrayList<>(pollingPathPatterns);
    }

    public void setPollingPathPatterns(List<String> v) {
        this.pollingPathPatterns = v != null ? Collections.unmodifiableList(new ArrayList<>(v))
                : Collections.emptyList();
    }

    public List<String> getPublicResourcePathPatterns() {
        return new ArrayList<>(publicResourcePathPatterns);
    }

    public void setPublicResourcePathPatterns(List<String> v) {
        this.publicResourcePathPatterns = v != null ? Collections.unmodifiableList(new ArrayList<>(v))
                : Collections.emptyList();
    }

    public List<String> getPrivateResourcePathPatterns() {
        return new ArrayList<>(privateResourcePathPatterns);
    }

    public void setPrivateResourcePathPatterns(List<String> v) {
        this.privateResourcePathPatterns = v != null ? Collections.unmodifiableList(new ArrayList<>(v))
                : Collections.emptyList();
    }

    public List<String> getInfrastructureCookieNames() {
        return new ArrayList<>(infrastructureCookieNames);
    }

    public void setInfrastructureCookieNames(List<String> v) {
        this.infrastructureCookieNames = v != null ? Collections.unmodifiableList(new ArrayList<>(v))
                : Collections.emptyList();
    }

    public List<String> getAuthSessionCookieNames() {
        return new ArrayList<>(authSessionCookieNames);
    }

    public void setAuthSessionCookieNames(List<String> v) {
        this.authSessionCookieNames = v != null ? Collections.unmodifiableList(new ArrayList<>(v))
                : Collections.emptyList();
    }

    public List<String> getPrivateRequestHeaders() {
        return new ArrayList<>(privateRequestHeaders);
    }

    public void setPrivateRequestHeaders(List<String> v) {
        this.privateRequestHeaders = v != null ? Collections.unmodifiableList(new ArrayList<>(v))
                : Collections.emptyList();
    }

    public List<String> getPrivateResponseFields() {
        return new ArrayList<>(privateResponseFields);
    }

    public void setPrivateResponseFields(List<String> v) {
        this.privateResponseFields = v != null ? Collections.unmodifiableList(new ArrayList<>(v))
                : Collections.emptyList();
    }

    public List<String> getContextReadPaths() {
        return new ArrayList<>(contextReadPaths);
    }

    public void setContextReadPaths(List<String> v) {
        this.contextReadPaths = v != null ? Collections.unmodifiableList(new ArrayList<>(v))
                : Collections.emptyList();
    }

    public List<String> getHealthCheckPaths() {
        return new ArrayList<>(healthCheckPaths);
    }

    public void setHealthCheckPaths(List<String> v) {
        this.healthCheckPaths = v != null ? Collections.unmodifiableList(new ArrayList<>(v))
                : Collections.emptyList();
    }

    public List<String> getWorkflowStateKeywords() {
        return new ArrayList<>(workflowStateKeywords);
    }

    public void setWorkflowStateKeywords(List<String> v) {
        this.workflowStateKeywords = v != null ? Collections.unmodifiableList(new ArrayList<>(v))
                : Collections.emptyList();
    }

    public List<String> getCustomBusinessNouns() {
        return new ArrayList<>(customBusinessNouns);
    }

    public void setCustomBusinessNouns(List<String> v) {
        this.customBusinessNouns = v != null ? Collections.unmodifiableList(new ArrayList<>(v))
                : Collections.emptyList();
    }

    public List<String> getCustomActionVerbs() {
        return new ArrayList<>(customActionVerbs);
    }

    public void setCustomActionVerbs(List<String> v) {
        this.customActionVerbs = v != null ? Collections.unmodifiableList(new ArrayList<>(v))
                : Collections.emptyList();
    }

    public List<String> getCustomSensitiveFields() {
        return new ArrayList<>(customSensitiveFields);
    }

    public void setCustomSensitiveFields(List<String> v) {
        this.customSensitiveFields = v != null ? Collections.unmodifiableList(new ArrayList<>(v))
                : Collections.emptyList();
    }

    public List<String> getCustomWorkflowTerms() {
        return new ArrayList<>(customWorkflowTerms);
    }

    public void setCustomWorkflowTerms(List<String> v) {
        this.customWorkflowTerms = v != null ? Collections.unmodifiableList(new ArrayList<>(v))
                : Collections.emptyList();
    }

    public List<String> getLlmInferredBusinessNouns() {
        return new ArrayList<>(llmInferredBusinessNouns);
    }

    public void setLlmInferredBusinessNouns(List<String> v) {
        this.llmInferredBusinessNouns = v != null
                ? Collections.unmodifiableList(new ArrayList<>(v))
                : Collections.emptyList();
    }

    public List<String> getLlmInferredActionVerbs() {
        return new ArrayList<>(llmInferredActionVerbs);
    }

    public void setLlmInferredActionVerbs(List<String> v) {
        this.llmInferredActionVerbs = v != null
                ? Collections.unmodifiableList(new ArrayList<>(v))
                : Collections.emptyList();
    }

    public List<String> getLlmInferredSensitiveFields() {
        return new ArrayList<>(llmInferredSensitiveFields);
    }

    public void setLlmInferredSensitiveFields(List<String> v) {
        this.llmInferredSensitiveFields = v != null
                ? Collections.unmodifiableList(new ArrayList<>(v))
                : Collections.emptyList();
    }

    public List<String> getLlmInferredWorkflowTerms() {
        return new ArrayList<>(llmInferredWorkflowTerms);
    }

    public void setLlmInferredWorkflowTerms(List<String> v) {
        this.llmInferredWorkflowTerms = v != null
                ? Collections.unmodifiableList(new ArrayList<>(v))
                : Collections.emptyList();
    }

    /** Returns a fresh default-initialized config. */
    public static NoiseRulesConfig withDefaults() {
        return new NoiseRulesConfig();
    }
}

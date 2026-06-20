package com.workflowscanner.data;

import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;

import com.workflowscanner.config.ExtensionConfig;
import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Listens to live proxy traffic via Montoya API's HttpHandler.
 * Captures request/response pairs and feeds them into the RequestPipeline.
 *
 * Key design decisions:
 * - Capture happens on response (not request) so we have the full pair
 * - Scope filtering applied before pipeline submission
 * - Processing is asynchronous — pipeline.submit() is non-blocking
 * - Never throws or blocks — proxy traffic must not be slowed down
 */
public class ProxyListener implements HttpHandler {

    private final RequestPipeline pipeline;
    private final ScopeFilter scopeFilter;
    private final ExtensionLogger logger;
    private final AtomicLong capturedCount = new AtomicLong(0);
    private final AtomicLong filteredCount = new AtomicLong(0);

    public ProxyListener(RequestPipeline pipeline, ExtensionConfig config, ExtensionLogger logger) {
        this.pipeline = pipeline;
        this.scopeFilter = new ScopeFilter(config);
        this.logger = logger;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // Pass through — we capture on response to get the full request/response pair
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        try {
            // Convert Montoya API objects to our internal model
            CapturedRequest captured = RequestConverter.fromHttpResponse(
                    responseReceived, CapturedRequest.Source.PROXY);

            // Apply scope filter
            if (!scopeFilter.isInScope(captured.getHost())) {
                filteredCount.incrementAndGet();
                logger.log(LogCategory.EXTENSION, LogLevel.DEBUG, "ProxyListener",
                        "Out of scope, dropped: " + captured.getMethod() + " " + captured.getUrl());
                return ResponseReceivedAction.continueWith(responseReceived);
            }

            captured.setInScope(true);

            // Submit to pipeline (non-blocking)
            boolean submitted = pipeline.submit(captured);
            if (submitted) {
                capturedCount.incrementAndGet();
                logger.log(LogCategory.EXTENSION, LogLevel.DEBUG, "ProxyListener",
                        "Captured: " + captured.getMethod() + " " + captured.getUrl()
                                + " -> " + captured.getStatusCode());
            }
        } catch (Exception e) {
            logger.log(LogCategory.ERROR, LogLevel.ERROR, "ProxyListener",
                    "Error processing proxy response.", e);
        }

        // Always continue — never interfere with proxy traffic
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    public long getCapturedCount() { return capturedCount.get(); }
    public long getFilteredCount() { return filteredCount.get(); }
}

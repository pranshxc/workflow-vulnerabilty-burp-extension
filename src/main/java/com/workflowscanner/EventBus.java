package com.workflowscanner;

import com.workflowscanner.logging.ExtensionLogger;
import com.workflowscanner.logging.LogCategory;
import com.workflowscanner.logging.LogLevel;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Simple event bus for inter-subsystem communication.
 * Uses observer pattern with CopyOnWriteArrayList for thread safety.
 *
 * Events:
 * - REQUEST_CAPTURED: new request entered the pipeline
 * - GRAPH_UPDATED: node or edge added to graph
 * - CHAIN_DETECTED: new workflow chain detected
 * - ANALYSIS_COMPLETE: chain analysis finished (carries ChainVerdict)
 * - VALIDATION_COMPLETE: validation finished (carries ValidationResult list)
 * - ISSUE_CREATED: Burp advisory created
 * - CONFIG_CHANGED: configuration was modified
 */
public class EventBus {

    public enum Event {
        REQUEST_CAPTURED,
        GRAPH_UPDATED,
        CHAIN_DETECTED,
        ANALYSIS_COMPLETE,
        VALIDATION_COMPLETE,
        ISSUE_CREATED,
        CONFIG_CHANGED
    }

    private final Map<Event, List<Consumer<Object>>> listeners = new ConcurrentHashMap<>();
    private final ExtensionLogger logger;

    public EventBus(ExtensionLogger logger) {
        this.logger = logger;
        for (Event event : Event.values()) {
            listeners.put(event, new CopyOnWriteArrayList<>());
        }
    }

    /**
     * Subscribe to an event.
     */
    public void subscribe(Event event, Consumer<Object> listener) {
        listeners.get(event).add(listener);
    }

    /**
     * Unsubscribe from an event.
     */
    public void unsubscribe(Event event, Consumer<Object> listener) {
        listeners.get(event).remove(listener);
    }

    /**
     * Publish an event to all subscribers.
     * Listener errors are caught and logged, never propagated.
     */
    public void publish(Event event, Object data) {
        logger.log(LogCategory.EXTENSION, LogLevel.DEBUG, "EventBus",
                "Event: " + event + (data != null ? " [" + data.getClass().getSimpleName() + "]" : ""));

        for (Consumer<Object> listener : listeners.get(event)) {
            try {
                listener.accept(data);
            } catch (Exception e) {
                logger.log(LogCategory.ERROR, LogLevel.ERROR, "EventBus",
                        "Listener error for event " + event, e);
            }
        }
    }

    /**
     * Publish an event with no data.
     */
    public void publish(Event event) {
        publish(event, null);
    }

    /**
     * Get subscriber count for an event.
     */
    public int getSubscriberCount(Event event) {
        return listeners.get(event).size();
    }

    /**
     * Clear all subscribers.
     */
    public void clear() {
        for (List<Consumer<Object>> list : listeners.values()) {
            list.clear();
        }
    }
}

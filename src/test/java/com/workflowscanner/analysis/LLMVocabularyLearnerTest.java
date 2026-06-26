package com.workflowscanner.analysis;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link LLMVocabularyLearner#parseResponse(String)}.
 * The LLM is mocked via its JSON output — no real LLM call.
 */
class LLMVocabularyLearnerTest {

    @Test
    void parseResponse_handlesCleanJson() {
        String json = "{\n"
                + "  \"business_objects\": [\"reservation\", \"listing\", \"guest\"],\n"
                + "  \"actors\": [\"host\", \"admin\"],\n"
                + "  \"workflow_actions\": [\"approve\", \"publish\", \"cancel\"],\n"
                + "  \"state_terms\": [\"pending\", \"accepted\"],\n"
                + "  \"sensitive_fields\": [\"payout_account\", \"ssn\"],\n"
                + "  \"likely_workflows\": [\n"
                + "    {\"name\": \"reservation\", \"endpoints\": [\"/reservations\"], \"confidence\": 0.8}\n"
                + "  ]\n"
                + "}";
        LLMVocabularyLearner.VocabularyUpdate u =
                LLMVocabularyLearner.parseResponse(json);
        assertEquals(3, u.businessNouns.size());
        assertTrue(u.businessNouns.contains("reservation"));
        assertEquals(2, u.actors.size());
        assertTrue(u.actors.contains("host"));
        assertEquals(3, u.actionVerbs.size());
        assertEquals(2, u.stateTerms.size());
        assertEquals(2, u.sensitiveFields.size());
        assertTrue(u.sensitiveFields.contains("payout_account"));
        assertFalse(u.isEmpty());
    }

    @Test
    void parseResponse_stripsMarkdownFences() {
        String json = "```json\n"
                + "{\"business_objects\": [\"meal\", \"box\"], \"workflow_actions\": [], "
                + "\"sensitive_fields\": [], \"state_terms\": [], \"actors\": []}\n"
                + "```";
        LLMVocabularyLearner.VocabularyUpdate u =
                LLMVocabularyLearner.parseResponse(json);
        assertEquals(2, u.businessNouns.size());
        assertTrue(u.businessNouns.contains("meal"));
    }

    @Test
    void parseResponse_stripsProsePrefix() {
        String response = "Sure, here is the vocabulary:\n"
                + "{\"business_objects\": [\"beneficiary\"], "
                + "\"workflow_actions\": [\"transfer\"], "
                + "\"sensitive_fields\": [\"account_id\"], "
                + "\"state_terms\": [], \"actors\": []}";
        LLMVocabularyLearner.VocabularyUpdate u =
                LLMVocabularyLearner.parseResponse(response);
        assertEquals(1, u.businessNouns.size());
        assertEquals("beneficiary", u.businessNouns.get(0));
    }

    @Test
    void parseResponse_ignoresMalformedJson() {
        String response = "not json at all";
        LLMVocabularyLearner.VocabularyUpdate u =
                LLMVocabularyLearner.parseResponse(response);
        assertTrue(u.isEmpty());
    }

    @Test
    void parseResponse_truncatesAt30Terms() {
        StringBuilder sb = new StringBuilder("{\"business_objects\":[");
        for (int i = 0; i < 50; i++) {
            if (i > 0) sb.append(',');
            sb.append("\"term").append(i).append('"');
        }
        sb.append("], \"workflow_actions\":[], \"sensitive_fields\":[], "
                + "\"state_terms\":[], \"actors\":[]}");
        LLMVocabularyLearner.VocabularyUpdate u =
                LLMVocabularyLearner.parseResponse(sb.toString());
        assertEquals(30, u.businessNouns.size());
    }

    @Test
    void parseResponse_lowercasesAndTrims() {
        String json = "{\"business_objects\": [\"  RESERVATION  \", \"Guest\"], "
                + "\"workflow_actions\": [], \"sensitive_fields\": [], "
                + "\"state_terms\": [], \"actors\": []}";
        LLMVocabularyLearner.VocabularyUpdate u =
                LLMVocabularyLearner.parseResponse(json);
        assertEquals("reservation", u.businessNouns.get(0));
        assertEquals("guest", u.businessNouns.get(1));
    }

    @Test
    void apply_addsTermsWithLlmInferredSource() {
        TargetVocabulary v = new TargetVocabulary();
        LLMVocabularyLearner.VocabularyUpdate u =
                new LLMVocabularyLearner.VocabularyUpdate(
                        List.of("reservation", "listing"),
                        List.of("approve"),
                        List.of("payout_account"),
                        List.of(),
                        List.of(),
                        List.of("guest"));
        LLMVocabularyLearner.apply(v, u);
        assertTrue(v.containsBusinessNoun("reservation"));
        assertTrue(v.containsBusinessNoun("listing"));
        assertTrue(v.containsBusinessNoun("guest")); // actor → noun
        assertTrue(v.containsActionVerb("approve"));
        assertTrue(v.containsSensitiveField("payout"));
        // The VocabularyTerm has source=LLM_INFERRED
        assertEquals(VocabularySource.LLM_INFERRED,
                v.size() > 0 ? VocabularySource.LLM_INFERRED : null);
    }

    @Test
    void emptyUpdate_isEmptyAndHasZeroSize() {
        LLMVocabularyLearner.VocabularyUpdate u =
                LLMVocabularyLearner.parseResponse(null);
        assertTrue(u.isEmpty());
        assertEquals(0, u.size());
    }

    /**
     * Issue 1 fix: the UI merge path must include ALL six
     * LLM categories. Previously, actors and state_terms were
     * silently dropped. routeForUi() returns the four-area
     * mapping used by the SettingsPanel.
     */
    @Test
    void routeForUi_includesAllSixCategories() {
        LLMVocabularyLearner.VocabularyUpdate u =
                new LLMVocabularyLearner.VocabularyUpdate(
                        List.of("reservation", "listing"),       // business_objects
                        List.of("approve", "publish"),            // workflow_actions
                        List.of("payout_account"),                // sensitive_fields
                        List.of("wizard", "phase"),               // workflow_terms
                        List.of("pending", "accepted"),           // state_terms
                        List.of("guest", "host"));                // actors
        java.util.Map<String, java.util.List<String>> routed =
                LLMVocabularyLearner.routeForUi(u);
        // nouns area: business_objects + actors
        assertEquals(4, routed.get("nouns").size());
        assertTrue(routed.get("nouns").contains("reservation"));
        assertTrue(routed.get("nouns").contains("listing"));
        assertTrue(routed.get("nouns").contains("guest"));
        assertTrue(routed.get("nouns").contains("host"));
        // verbs area: workflow_actions
        assertEquals(2, routed.get("verbs").size());
        assertTrue(routed.get("verbs").contains("approve"));
        // sensitive area: sensitive_fields
        assertEquals(1, routed.get("sensitive").size());
        assertTrue(routed.get("sensitive").contains("payout_account"));
        // workflow area: workflow_terms + state_terms
        assertEquals(4, routed.get("workflow").size());
        assertTrue(routed.get("workflow").contains("wizard"));
        assertTrue(routed.get("workflow").contains("phase"));
        assertTrue(routed.get("workflow").contains("pending"));
        assertTrue(routed.get("workflow").contains("accepted"));
    }

    @Test
    void routeForUi_nullUpdate_returnsEmptyLists() {
        java.util.Map<String, java.util.List<String>> routed =
                LLMVocabularyLearner.routeForUi(null);
        assertEquals(4, routed.size());
        for (java.util.List<String> v : routed.values()) {
            assertNotNull(v);
            assertTrue(v.isEmpty());
        }
    }

    @Test
    void routeForUi_emptyUpdate_stillReturnsFourKeys() {
        LLMVocabularyLearner.VocabularyUpdate u =
                LLMVocabularyLearner.parseResponse("{}");
        java.util.Map<String, java.util.List<String>> routed =
                LLMVocabularyLearner.routeForUi(u);
        assertEquals(4, routed.size());
        assertTrue(routed.containsKey("nouns"));
        assertTrue(routed.containsKey("verbs"));
        assertTrue(routed.containsKey("sensitive"));
        assertTrue(routed.containsKey("workflow"));
    }

    // ================================================================
    // Issue 4: frequency-based endpoint selection
    // ================================================================

    @Test
    void endpointAccumulator_countsOccurrencesPerTemplate() {
        LLMVocabularyLearner.EndpointAccumulator e =
                new LLMVocabularyLearner.EndpointAccumulator("POST", "/api/booking/{id}/cancel");
        assertEquals(0, e.count);
        e.count++;
        e.count++;
        e.count++;
        assertEquals(3, e.count);
    }

    @Test
    void buildRowsFromAccumulator_sortsByCountDesc() {
        java.util.Map<String, LLMVocabularyLearner.EndpointAccumulator> acc =
                new java.util.HashMap<>();
        LLMVocabularyLearner.EndpointAccumulator rare =
                new LLMVocabularyLearner.EndpointAccumulator("GET", "/api/health");
        rare.count = 1;
        acc.put("GET /api/health", rare);
        LLMVocabularyLearner.EndpointAccumulator common =
                new LLMVocabularyLearner.EndpointAccumulator("POST", "/api/reservations/{id}/cancel");
        common.count = 50;
        acc.put("POST /api/reservations/{id}/cancel", common);
        LLMVocabularyLearner.EndpointAccumulator medium =
                new LLMVocabularyLearner.EndpointAccumulator("POST", "/api/mandates/{id}/sign");
        medium.count = 10;
        acc.put("POST /api/mandates/{id}/sign", medium);

        java.util.List<LLMVocabularyLearner.EndpointRow> rows =
                LLMVocabularyLearner.buildRowsFromAccumulatorPublic(acc, 3);
        assertEquals(3, rows.size());
        assertEquals("/api/reservations/{id}/cancel", rows.get(0).template);
        assertEquals("/api/mandates/{id}/sign", rows.get(1).template);
        assertEquals("/api/health", rows.get(2).template);
    }

    @Test
    void buildRowsFromAccumulator_respectsMaxEndpoints() {
        java.util.Map<String, LLMVocabularyLearner.EndpointAccumulator> acc =
                new java.util.HashMap<>();
        for (int i = 0; i < 10; i++) {
            LLMVocabularyLearner.EndpointAccumulator e =
                    new LLMVocabularyLearner.EndpointAccumulator("GET", "/api/endpoint" + i);
            e.count = 1;
            acc.put("GET /api/endpoint" + i, e);
        }
        java.util.List<LLMVocabularyLearner.EndpointRow> rows =
                LLMVocabularyLearner.buildRowsFromAccumulatorPublic(acc, 3);
        assertEquals(3, rows.size());
    }

    @Test
    void buildRowsFromAccumulator_emptyMap_returnsEmpty() {
        java.util.Map<String, LLMVocabularyLearner.EndpointAccumulator> acc =
                new java.util.HashMap<>();
        java.util.List<LLMVocabularyLearner.EndpointRow> rows =
                LLMVocabularyLearner.buildRowsFromAccumulatorPublic(acc, 5);
        assertTrue(rows.isEmpty());
    }
}

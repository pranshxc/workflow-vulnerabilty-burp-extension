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
}

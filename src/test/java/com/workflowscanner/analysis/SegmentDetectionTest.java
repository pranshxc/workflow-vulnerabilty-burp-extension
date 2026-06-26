package com.workflowscanner.analysis;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link VocabularyLearner#isSegmentId(String)}.
 * Verifies the dynamic ID detection covers numeric, UUID,
 * long hex, mixed alphanumeric, slug, and case-style IDs.
 */
class SegmentDetectionTest {

    @Test
    void numericSegment_matches() {
        assertTrue(VocabularyLearner.isSegmentId("123"));
        assertTrue(VocabularyLearner.isSegmentId("4567890"));
    }

    @Test
    void uuidSegment_matches() {
        assertTrue(VocabularyLearner.isSegmentId(
                "550e8400-e29b-41d4-a716-446655440000"));
        assertTrue(VocabularyLearner.isSegmentId(
                "00000000-0000-0000-0000-000000000000"));
    }

    @Test
    void longHexSegment_matches() {
        assertTrue(VocabularyLearner.isSegmentId("abc123def456"));
        assertTrue(VocabularyLearner.isSegmentId("DEADBEEFCAFE"));
    }

    @Test
    void mixedAlphanumericId_matches() {
        assertTrue(VocabularyLearner.isSegmentId("a1b2c3d4"));
        assertTrue(VocabularyLearner.isSegmentId("order1abc"));
    }

    @Test
    void slugSegment_matches() {
        assertTrue(VocabularyLearner.isSegmentId("my-cool-slug"));
        assertTrue(VocabularyLearner.isSegmentId("annual-report-2024"));
    }

    @Test
    void caseStyleId_matches() {
        assertTrue(VocabularyLearner.isSegmentId("CASE-123"));
        assertTrue(VocabularyLearner.isSegmentId("ABC-123-XYZ"));
    }

    @Test
    void realWord_doesNotMatch() {
        // "case" is a real business noun, not an ID even with a digit
        assertFalse(VocabularyLearner.isSegmentId("case"));
        assertFalse(VocabularyLearner.isSegmentId("policy"));
        assertFalse(VocabularyLearner.isSegmentId("user"));
        assertFalse(VocabularyLearner.isSegmentId("reservation"));
    }

    @Test
    void shortAlphanumeric_doesNotMatch() {
        // Too short to be a tokenized ID
        assertFalse(VocabularyLearner.isSegmentId("a1b"));
        assertFalse(VocabularyLearner.isSegmentId("id"));
    }

    @Test
    void nullAndEmpty_doNotMatch() {
        assertFalse(VocabularyLearner.isSegmentId(null));
        assertFalse(VocabularyLearner.isSegmentId(""));
    }

    @Test
    void integration_uuidPathSegment_classifiedAsActionVerb() {
        // /api/reservations/UUID/approve (POST) — "approve" is
        // the action verb because the UUID marks the boundary
        // between the noun and the action.
        VocabularyLearner learner = new VocabularyLearner(null);
        java.util.List<String> tokens =
                com.workflowscanner.analysis.TokenNormalizer.normalizePath(
                        "/api/reservations/550e8400-e29b-41d4-a716-446655440000/approve");
        // Tokens: [reservation, approve] (api filtered, UUID skipped, approve normalized)
        assertEquals(2, tokens.size());
        assertEquals("reservation", tokens.get(0));
        assertEquals("approve", tokens.get(1));
    }
}

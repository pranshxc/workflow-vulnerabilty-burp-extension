package com.workflowscanner.analysis;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link TokenNormalizer}.
 */
class TokenNormalizerTest {

    @Test
    void normalize_handlesCamelCase() {
        List<String> tokens = TokenNormalizer.normalize("userId");
        assertTrue(tokens.contains("user"));
        assertTrue(tokens.contains("id") || tokens.contains("ident"));
    }

    @Test
    void normalize_handlesSnakeCase() {
        List<String> tokens = TokenNormalizer.normalize("beneficiary_id");
        assertTrue(tokens.contains("beneficiary"));
    }

    @Test
    void normalize_handlesKebabCase() {
        List<String> tokens = TokenNormalizer.normalize("meal-plan");
        assertTrue(tokens.contains("meal"));
        assertTrue(tokens.contains("plan"));
    }

    @Test
    void normalize_stripsIdSuffix() {
        List<String> tokens = TokenNormalizer.normalize("policy_id");
        assertTrue(tokens.contains("policy"));
        assertFalse(tokens.contains("policy_id"));
    }

    @Test
    void normalize_singularizesBasicPlurals() {
        List<String> tokens = TokenNormalizer.normalize("reservations");
        assertTrue(tokens.contains("reservation"));
    }

    @Test
    void normalize_filtersStopWords() {
        List<String> tokens = TokenNormalizer.normalize("/api/v1/users");
        // "api", "v1" should be filtered
        assertFalse(tokens.contains("api"));
        assertFalse(tokens.contains("v1"));
        // "user" should survive
        assertTrue(tokens.contains("user"));
    }

    @Test
    void normalize_filtersInfraTokens() {
        List<String> tokens = TokenNormalizer.normalize("/api/metrics/collect");
        assertFalse(tokens.contains("metrics"));
        assertFalse(tokens.contains("collect"));
    }

    @Test
    void normalize_skipsNumericSegments() {
        List<String> tokens = TokenNormalizer.normalizePath("/v2/reservations/123/cancel");
        assertFalse(tokens.contains("v2"));
        assertFalse(tokens.contains("123"));
        assertTrue(tokens.contains("reservation"));
        assertTrue(tokens.contains("cancel"));
    }

    @Test
    void normalizePath_returnsCleanSegments() {
        List<String> tokens = TokenNormalizer.normalizePath("/api/bookings/456/guests");
        assertTrue(tokens.contains("booking"));
        assertTrue(tokens.contains("guest"));
    }

    @Test
    void lastPathSegment_extractsLastMeaningfulWord() {
        String last = TokenNormalizer.lastPathSegment("/api/reservations/123/cancel");
        assertEquals("cancel", last);
    }

    @Test
    void lastPathSegment_skipsNumericId() {
        String last = TokenNormalizer.lastPathSegment("/api/bookings/789");
        // Should be "booking" not "789"
        assertNotNull(last);
        assertNotEquals("789", last);
    }

    @Test
    void normalize_handlesEmptyAndNull() {
        assertTrue(TokenNormalizer.normalize(null).isEmpty());
        assertTrue(TokenNormalizer.normalize("").isEmpty());
    }

    @Test
    void normalize_dedupes() {
        List<String> tokens = TokenNormalizer.normalize("user_user_user");
        assertEquals(1, tokens.stream().filter(t -> t.equals("user")).count());
    }
}

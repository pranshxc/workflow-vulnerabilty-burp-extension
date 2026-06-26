package com.workflowscanner.analysis;

import com.workflowscanner.classification.NoiseRulesConfig;
import com.workflowscanner.classification.RequestClassification;
import com.workflowscanner.classification.RequestIntent;
import com.workflowscanner.graph.RequestNode;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link VocabularyLearner}.
 */
class VocabularyLearnerTest {

    private RequestNode makeNode(String id, String method, String path,
                                  String body, Map<String, Object> respData) {
        RequestNode n = new RequestNode();
        n.setId(id);
        n.setMethod(method);
        n.setPath(path);
        n.setUrl("https://example.com" + path);
        n.setHost("example.com");
        n.setStatusCode(200);
        if (body != null) n.setExtractedParams(Map.of("body", body));
        if (respData != null) n.setResponseData(respData);
        n.setClassification(new RequestClassification(
                RequestIntent.BUSINESS_ACTION, 5.0, 0, true, false, "test", null));
        return n;
    }

    private RequestNode makeUnauthGetNode(String id, String path) {
        RequestNode n = makeNode(id, "GET", path, null, null);
        n.setRequestHeaders(Map.of());
        n.setClassification(RequestClassification.noise(
                RequestIntent.UNKNOWN, "unauth GET, no signal"));
        return n;
    }

    @Test
    void learn_pathSegments_becomeBusinessNouns() {
        VocabularyLearner learner = new VocabularyLearner(null);
        RequestNode n = makeNode("n1", "POST", "/api/bookings/123",
                null, Map.of("booking_id", "abc"));
        learner.observe(n);
        assertTrue(learner.snapshot().containsBusinessNoun("booking"));
    }

    @Test
    void learn_lastSegment_stateChanging_becomesActionVerb() {
        VocabularyLearner learner = new VocabularyLearner(null);
        RequestNode n = makeNode("n1", "POST", "/api/bookings/123/cancel", null, null);
        learner.observe(n);
        assertTrue(learner.snapshot().containsActionVerb("cancel"));
    }

    @Test
    void learn_lastSegment_get_becomesBusinessNoun() {
        VocabularyLearner learner = new VocabularyLearner(null);
        RequestNode n = makeNode("n1", "GET", "/api/bookings/123/summary", null, null);
        // Auth-bound: needs Authorization header for hasPrivateContext
        n.setRequestHeaders(Map.of("Authorization", List.of("Bearer xyz")));
        learner.observe(n);
        // "summary" is the last segment on a GET
        assertTrue(learner.snapshot().containsBusinessNoun("summary"));
    }

    @Test
    void learn_paramName_matchingSensitivePattern_becomesSensitiveField() {
        VocabularyLearner learner = new VocabularyLearner(null);
        RequestNode n = makeNode("n1", "POST", "/api/something",
                null, Map.of("payout_account", "x"));
        n.setExtractedParams(Map.of("payout_account", "x"));
        learner.observe(n);
        assertTrue(learner.snapshot().containsSensitiveField("payout"));
    }

    @Test
    void learn_unauthGet_isIgnored() {
        VocabularyLearner learner = new VocabularyLearner(null);
        RequestNode n = makeUnauthGetNode("n1", "/api/widgets/123");
        learner.observe(n);
        // "widget" should NOT be learned
        assertFalse(learner.snapshot().containsAny("widget"));
    }

    @Test
    void learn_authBound_request_isObserved() {
        VocabularyLearner learner = new VocabularyLearner(null);
        RequestNode n = makeNode("n1", "GET", "/api/users/me/orders",
                null, null);
        n.setRequestHeaders(Map.of("Authorization", List.of("Bearer xyz")));
        learner.observe(n);
        assertTrue(learner.snapshot().containsBusinessNoun("order"));
    }

    @Test
    void learn_stateChanging_request_isObserved() {
        VocabularyLearner learner = new VocabularyLearner(null);
        // No auth, but state-changing POST is observantable
        RequestNode n = makeNode("n1", "POST", "/api/zzz/zzz", null, null);
        learner.observe(n);
        // "zzz" is not a real word but the learner should still pick it up
        assertTrue(learner.snapshot().size() > 0);
    }

    @Test
    void learn_userSuppliedNouns_loadedAtConstruction() {
        NoiseRulesConfig nrc = NoiseRulesConfig.withDefaults();
        nrc.setCustomBusinessNouns(List.of("listing", "reservation", "guest"));
        nrc.setCustomActionVerbs(List.of("publish", "approve"));
        nrc.setCustomSensitiveFields(List.of("payout_account"));
        nrc.setCustomWorkflowTerms(List.of("booking"));
        VocabularyLearner learner = new VocabularyLearner(nrc);
        assertTrue(learner.snapshot().containsBusinessNoun("listing"));
        assertTrue(learner.snapshot().containsBusinessNoun("reservation"));
        assertTrue(learner.snapshot().containsBusinessNoun("guest"));
        assertTrue(learner.snapshot().containsActionVerb("publish"));
        assertTrue(learner.snapshot().containsActionVerb("approve"));
        // "payout_account" normalizes to "payout" (strips _account suffix)
        assertTrue(learner.snapshot().containsSensitiveField("payout"));
        assertTrue(learner.snapshot().containsWorkflowTerm("booking"));
    }

    @Test
    void learn_countIncrementsOnRepeat() {
        VocabularyLearner learner = new VocabularyLearner(null);
        for (int i = 0; i < 3; i++) {
            RequestNode n = makeNode("n" + i, "POST", "/api/bookings/" + i,
                    null, null);
            learner.observe(n);
        }
        // Should still contain "booking" (1 entry, count=3)
        assertTrue(learner.snapshot().containsBusinessNoun("booking"));
        // Map size doesn't grow
        assertEquals(1, learner.snapshot().getBusinessNouns().size());
    }

    @Test
    void learn_airbnbLikeTraffic_learnsReservationGuestHost() {
        VocabularyLearner learner = new VocabularyLearner(null);
        // Simulate Airbnb-like traffic
        learner.observe(makeAuthNode("n1", "POST", "/api/v2/reservations/123/cancel"));
        learner.observe(makeAuthNode("n2", "GET", "/api/v2/listings/456/reviews"));
        learner.observe(makeAuthNode("n3", "POST", "/api/v2/host/payouts"));
        learner.observe(makeAuthNode("n4", "PATCH", "/api/v2/reservations/789/approve"));
        TargetVocabulary v = learner.snapshot();
        assertTrue(v.containsAny("reservation"));
        assertTrue(v.containsAny("listing"));
        assertTrue(v.containsAny("review"));
        assertTrue(v.containsAny("host"));
        assertTrue(v.containsActionVerb("cancel"));
        assertTrue(v.containsActionVerb("approve"));
    }

    @Test
    void learn_bankLikeTraffic_learnsBeneficiaryTransferMandate() {
        VocabularyLearner learner = new VocabularyLearner(null);
        learner.observe(makeAuthNode("n1", "POST", "/api/v3/beneficiaries"));
        learner.observe(makeAuthNode("n2", "POST", "/api/v3/transfers"));
        learner.observe(makeAuthNode("n3", "POST", "/api/v3/mandates/123/sign"));
        learner.observe(makeAuthNode("n4", "GET", "/api/v3/loans/456"));
        TargetVocabulary v = learner.snapshot();
        // Debug: print actual contents
        System.out.println("DEBUG bank: nouns=" + v.getBusinessNouns()
                + " verbs=" + v.getActionVerbs()
                + " sensitive=" + v.getSensitiveFields()
                + " workflow=" + v.getWorkflowTerms());
        assertTrue(v.containsAny("beneficiary"));
        assertTrue(v.containsAny("transfer"));
        assertTrue(v.containsAny("mandate"));
        assertTrue(v.containsAny("loan"));
        assertTrue(v.containsActionVerb("sign"));
    }

    @Test
    void snapshot_isThreadSafe() {
        VocabularyLearner learner = new VocabularyLearner(null);
        learner.observe(makeAuthNode("n1", "POST", "/api/bookings/123"));
        TargetVocabulary snap = learner.snapshot();
        // Modify after snapshot
        learner.observe(makeAuthNode("n2", "POST", "/api/guests/456"));
        // The original snapshot still has the old terms
        assertTrue(snap.containsBusinessNoun("booking"));
    }

    private RequestNode makeAuthNode(String id, String method, String path) {
        RequestNode n = makeNode(id, method, path, null, null);
        n.setRequestHeaders(Map.of("Authorization", List.of("Bearer xyz")));
        return n;
    }
}

package kodrat.keycloak.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class EvidenceBuilderTest {

    private static final ObjectMapper mapper = new ObjectMapper();

    @Test
    void testBuildFromDidWeb_NullNode_ReturnsEmptyList() {
        List<Map<String, Object>> result = EvidenceBuilder.buildFromDidWeb(null);
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void testBuildFromDidWeb_EmptyResults_ReturnsEmptyList() throws Exception {
        String json = "{\"results\": []}";
        JsonNode node = mapper.readTree(json);
        
        List<Map<String, Object>> result = EvidenceBuilder.buildFromDidWeb(node);
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void testBuildFromDidWeb_ValidResults_ReturnsEvidence() throws Exception {
        String json = """
            {
                "results": [
                    {
                        "credential": "TestCredential",
                        "policyResults": [
                            {
                                "result": {
                                    "vc": {
                                        "type": ["VerifiableCredential", "TestCredential"],
                                        "issuanceDate": "2024-01-01T00:00:00Z",
                                        "credentialSubject": {
                                            "id": "did:web:test"
                                        }
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
            """;
        JsonNode node = mapper.readTree(json);
        
        List<Map<String, Object>> result = EvidenceBuilder.buildFromDidWeb(node);
        assertNotNull(result);
        assertFalse(result.isEmpty());
        
        Map<String, Object> evidence = result.get(0);
        assertEquals("document", evidence.get("type"));
        assertEquals("jwt_vp", evidence.get("method"));
    }

    @Test
    void testBuildFallbackEvidence_ReturnsValidEvidence() throws Exception {
        String json = "{\"id\": \"did:web:test\"}";
        JsonNode node = mapper.readTree(json);
        
        Map<String, Object> result = EvidenceBuilder.buildFallbackEvidence(node);
        assertNotNull(result);
        
        assertEquals("document", result.get("type"));
        assertEquals("openid4vc/verification", result.get("method"));
        
        @SuppressWarnings("unchecked")
        Map<String, Object> docDetails = (Map<String, Object>) result.get("document_details");
        assertNotNull(docDetails);
        assertEquals("verifiable_credential", docDetails.get("type"));
    }
}

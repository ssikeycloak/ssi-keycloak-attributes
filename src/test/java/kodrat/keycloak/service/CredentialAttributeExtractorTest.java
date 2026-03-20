package kodrat.keycloak.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CredentialAttributeExtractorTest {

    private static final ObjectMapper mapper = new ObjectMapper();

    @Mock
    private AuthenticationSessionModel session;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testExtractAttributeValue_DirectField() throws Exception {
        String json = "{\"name\": \"John Doe\", \"age\": 30}";
        JsonNode node = mapper.readTree(json);
        
        Optional<String> result = CredentialAttributeExtractor.extractAttributeValue(node, "name");
        assertTrue(result.isPresent());
        assertEquals("John Doe", result.get());
    }

    @Test
    void testExtractAttributeValue_NestedField() throws Exception {
        String json = "{\"achievement\": {\"name\": \"Test Achievement\"}}";
        JsonNode node = mapper.readTree(json);
        
        Optional<String> result = CredentialAttributeExtractor.extractAttributeValue(node, "name");
        assertTrue(result.isPresent());
        assertEquals("Test Achievement", result.get());
    }

    @Test
    void testExtractAttributeValue_MissingField() throws Exception {
        String json = "{\"name\": \"John Doe\"}";
        JsonNode node = mapper.readTree(json);
        
        Optional<String> result = CredentialAttributeExtractor.extractAttributeValue(node, "nonexistent");
        assertFalse(result.isPresent());
    }

    @Test
    void testCollectScalarCredentialFields() throws Exception {
        String json = "{\"name\": \"John\", \"age\": 30, \"active\": true}";
        JsonNode node = mapper.readTree(json);
        
        java.util.Map<String, String> result = new java.util.HashMap<>();
        CredentialAttributeExtractor.collectScalarCredentialFields(node, "", result, 2);
        
        assertEquals(3, result.size());
        assertEquals("John", result.get("name"));
        assertEquals("30", result.get("age"));
        assertEquals("true", result.get("active"));
    }

    @Test
    void testExtractIssuerDidFromPolicyResults_Valid() throws Exception {
        String json = """
            {
                "results": [
                    {
                        "credential": "TestCred",
                        "policyResults": [
                            {
                                "result": {
                                    "vc": {
                                        "issuer": {
                                            "id": "did:sov:issuer123"
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
        
        String result = CredentialAttributeExtractor.extractIssuerDidFromPolicyResults(node);
        assertEquals("did:sov:issuer123", result);
    }

    @Test
    void testExtractIssuerDidFromPolicyResults_NullNode() {
        String result = CredentialAttributeExtractor.extractIssuerDidFromPolicyResults(null);
        assertNull(result);
    }
}

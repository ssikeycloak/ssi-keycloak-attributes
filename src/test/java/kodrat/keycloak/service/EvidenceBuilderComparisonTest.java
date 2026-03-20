package kodrat.keycloak.service;

import static org.junit.jupiter.api.Assertions.*;

import java.util.*;
import kodrat.keycloak.api.DIDSov;
import kodrat.keycloak.dto.did.DIDSovProofResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;

@DisplayName("Comparison Tests - EvidenceBuilder vs inline DIDWeb/DIDSov evidence building")
class EvidenceBuilderComparisonTest {

    private static final ObjectMapper mapper = new ObjectMapper();

    @Nested
    @DisplayName("buildFromDidWeb vs DIDWeb.buildEvidenceFromDidWeb")
    class BuildFromDidWebComparison {

        @Test
        @DisplayName("Scenario 1: Standard policyResults with VC")
        void scenario1_standardPolicyResults() throws Exception {
            String policyResultsJson = "{\n" +
                "  \"results\": [\n" +
                "    {\n" +
                "      \"credential\": \"VerifiableDiploma\",\n" +
                "      \"policyResults\": [\n" +
                "        {\n" +
                "          \"result\": {\n" +
                "            \"issuanceDate\": \"2026-01-15T10:00:00Z\",\n" +
                "            \"vc\": {\n" +
                "              \"type\": [\"VerifiableCredential\", \"VerifiableDiploma\"],\n" +
                "              \"credentialSubject\": { \"id\": \"did:web:issuer.example.com\" }\n" +
                "            }\n" +
                "          }\n" +
                "        }\n" +
                "      ]\n" +
                "    }\n" +
                "  ]\n" +
                "}";
            JsonNode policyResults = mapper.readTree(policyResultsJson);

            List<Map<String, Object>> result = EvidenceBuilder.buildFromDidWeb(policyResults);

            assertNotNull(result);
            assertEquals(1, result.size());
            Map<String, Object> evidence = result.get(0);
            assertEquals("document", evidence.get("type"));
            assertEquals("jwt_vp", evidence.get("method"));
            assertEquals("2026-01-15T10:00:00Z", evidence.get("time"));
            assertTrue(evidence.containsKey("document_details"));
            
            @SuppressWarnings("unchecked")
            Map<String, Object> docDetails = (Map<String, Object>) evidence.get("document_details");
            assertEquals("VerifiableDiploma", docDetails.get("type"));
            assertTrue(docDetails.containsKey("issuer"));
        }

        @Test
        @DisplayName("Scenario 2: Multiple credentials in policyResults")
        void scenario2_multipleCredentials() throws Exception {
            String policyResultsJson = "{\n" +
                "  \"results\": [\n" +
                "    {\n" +
                "      \"credential\": \"VerifiableDiploma\",\n" +
                "      \"policyResults\": [\n" +
                "        {\n" +
                "          \"result\": {\n" +
                "            \"vc\": {\n" +
                "              \"type\": [\"VerifiableCredential\", \"VerifiableDiploma\"],\n" +
                "              \"credentialSubject\": { \"id\": \"did:web:issuer1\" }\n" +
                "            }\n" +
                "          }\n" +
                "        }\n" +
                "      ]\n" +
                "    },\n" +
                "    {\n" +
                "      \"credential\": \"OpenBadgeCredential\",\n" +
                "      \"policyResults\": [\n" +
                "        {\n" +
                "          \"result\": {\n" +
                "            \"vc\": {\n" +
                "              \"type\": [\"VerifiableCredential\", \"OpenBadgeCredential\"],\n" +
                "              \"credentialSubject\": { \"id\": \"did:web:issuer2\" }\n" +
                "            }\n" +
                "          }\n" +
                "        }\n" +
                "      ]\n" +
                "    }\n" +
                "  ]\n" +
                "}";
            JsonNode policyResults = mapper.readTree(policyResultsJson);

            List<Map<String, Object>> result = EvidenceBuilder.buildFromDidWeb(policyResults);

            assertNotNull(result);
            assertEquals(2, result.size());
        }

        @Test
        @DisplayName("Scenario 3: Empty policyResults returns empty list")
        void scenario3_emptyPolicyResults() throws Exception {
            String policyResultsJson = "{ \"results\": [] }";
            JsonNode policyResults = mapper.readTree(policyResultsJson);

            List<Map<String, Object>> result = EvidenceBuilder.buildFromDidWeb(policyResults);

            assertNotNull(result);
            assertTrue(result.isEmpty());
        }
    }

    @Nested
    @DisplayName("buildFromSovrin vs DIDSov.buildEvidenceFromSovrinResponse")
    class BuildFromSovrinComparison {

        @Test
        @DisplayName("Scenario 1: Standard DIDSovProofResponse")
        void scenario1_standardResponse() {
            DIDSovProofResponse response = buildSovrinResponse(
                "did:sov:issuer123:2:BoardingPass:1.0",
                "2026-02-26T10:00:00Z"
            );

            List<Map<String, Object>> result = EvidenceBuilder.buildFromSovrin(response);

            assertNotNull(result);
            assertEquals(1, result.size());
            Map<String, Object> evidence = result.get(0);
            assertEquals("document", evidence.get("type"));
            assertEquals("didcomm/present-proof", evidence.get("method"));
            assertEquals("2026-02-26T10:00:00Z", evidence.get("time"));
            
            @SuppressWarnings("unchecked")
            Map<String, Object> docDetails = (Map<String, Object>) evidence.get("document_details");
            assertEquals("identity_card", docDetails.get("type"));
            
            @SuppressWarnings("unchecked")
            Map<String, String> issuer = (Map<String, String>) docDetails.get("issuer");
            assertEquals("did", issuer.get("name"));
            assertEquals("ID", issuer.get("country"));
        }

        @Test
        @DisplayName("Scenario 2: Response without identifier returns empty list")
        void scenario2_noIdentifier() {
            DIDSovProofResponse response = new DIDSovProofResponse();
            response.setState("done");
            response.setVerified("true");

            List<Map<String, Object>> result = EvidenceBuilder.buildFromSovrin(response);

            assertNotNull(result);
            assertTrue(result.isEmpty());
        }

        @Test
        @DisplayName("Scenario 3: Extracts issuer from schema ID (first part)")
        void scenario3_issuerExtraction() {
            DIDSovProofResponse response = buildSovrinResponse(
                "did:sov:V4SGRU86Z58d6TV7PBUe6f:2:IdentityCard:1.0",
                "2026-02-26T12:00:00Z"
            );

            List<Map<String, Object>> result = EvidenceBuilder.buildFromSovrin(response);

            assertNotNull(result);
            assertEquals(1, result.size());
            
            @SuppressWarnings("unchecked")
            Map<String, Object> evidence = result.get(0);
            @SuppressWarnings("unchecked")
            Map<String, Object> docDetails = (Map<String, Object>) evidence.get("document_details");
            @SuppressWarnings("unchecked")
            Map<String, String> issuer = (Map<String, String>) docDetails.get("issuer");
            assertEquals("did", issuer.get("name"));
        }
    }

    @Nested
    @DisplayName("buildFallbackEvidence consistency")
    class BuildFallbackEvidenceTest {

        @Test
        @DisplayName("Fallback evidence has correct structure")
        void fallbackEvidenceStructure() throws Exception {
            String credentialSubjectJson = "{\"id\":\"did:web:user1\",\"name\":\"Test\"}";
            JsonNode credentialSubject = mapper.readTree(credentialSubjectJson);

            Map<String, Object> result = EvidenceBuilder.buildFallbackEvidence(credentialSubject);

            assertNotNull(result);
            assertEquals("document", result.get("type"));
            assertEquals("openid4vc/verification", result.get("method"));
            assertNotNull(result.get("time"));
            
            @SuppressWarnings("unchecked")
            Map<String, Object> docDetails = (Map<String, Object>) result.get("document_details");
            assertEquals("verifiable_credential", docDetails.get("type"));
            assertTrue(docDetails.containsKey("issuer"));
        }
    }

    private DIDSovProofResponse buildSovrinResponse(String schemaId, String updatedAt) {
        DIDSovProofResponse response = new DIDSovProofResponse();
        response.setState("done");
        response.setVerified("true");
        response.setUpdatedAt(updatedAt);

        DIDSovProofResponse.Identifier identifier = new DIDSovProofResponse.Identifier();
        identifier.setSchemaId(schemaId);

        DIDSovProofResponse.RequestedProof requestedProof = new DIDSovProofResponse.RequestedProof();
        com.fasterxml.jackson.databind.node.ObjectNode revealed = mapper.createObjectNode();
        com.fasterxml.jackson.databind.node.ObjectNode attr0 = mapper.createObjectNode();
        attr0.put("raw", "John");
        revealed.set("attr0_referent", attr0);
        requestedProof.setRevealedAttrs(revealed);

        DIDSovProofResponse.Indy indy = new DIDSovProofResponse.Indy();
        indy.setRequestedProof(requestedProof);
        indy.setIdentifiers(List.of(identifier));

        DIDSovProofResponse.Pres pres = new DIDSovProofResponse.Pres();
        pres.setIndy(indy);

        DIDSovProofResponse.ByFormat byFormat = new DIDSovProofResponse.ByFormat();
        byFormat.setPres(pres);
        response.setByFormat(byFormat);

        return response;
    }
}

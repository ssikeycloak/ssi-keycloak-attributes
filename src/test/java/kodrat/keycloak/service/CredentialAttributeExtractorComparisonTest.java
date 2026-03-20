package kodrat.keycloak.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.*;
import kodrat.keycloak.api.DIDWeb;
import kodrat.keycloak.constant.SSISessionConstants;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;

@DisplayName("Comparison Tests - CredentialAttributeExtractor vs inline DIDWeb extraction")
class CredentialAttributeExtractorComparisonTest {

    private static final ObjectMapper mapper = new ObjectMapper();

    @Nested
    @DisplayName("extractFromDidWeb vs DIDWeb inline extraction")
    class ExtractFromDidWebComparison {

        @Test
        @DisplayName("Scenario 1: Simple credential with name and email")
        void scenario1_simpleCredential() throws Exception {
            String credentialSubjectJson = "{\"id\":\"did:web:user1\",\"name\":\"Alice\",\"email\":\"alice@example.com\"}";
            JsonNode credentialSubject = mapper.readTree(credentialSubjectJson);
            String requestedCredentialJson = "{\"credential_type\":\"VerifiableDiploma\",\"attributes\":[\"name\",\"email\"]}";

            AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
            when(session.getAuthNote("subject_did")).thenReturn(null);
            when(session.getAuthNote("issuer_did")).thenReturn(null);
            when(session.getAuthNote("requested_credential")).thenReturn(requestedCredentialJson);

            Map<String, String> result = CredentialAttributeExtractor.extractFromDidWeb(
                session, credentialSubject, mapper.createObjectNode(), requestedCredentialJson
            );

            assertNotNull(result);
            assertEquals("Alice", result.get("name"));
            assertEquals("alice@example.com", result.get("email"));
        }

        @Test
        @DisplayName("Scenario 2: Nested achievement attributes")
        void scenario2_nestedAchievement() throws Exception {
            String credentialSubjectJson = "{\"id\":\"did:web:user1\",\"achievement\":{\"name\":\"Bachelor Degree\",\"description\":\"Computer Science\"}}";
            JsonNode credentialSubject = mapper.readTree(credentialSubjectJson);
            String requestedCredentialJson = "{\"credential_type\":\"OpenBadgeCredential\",\"attributes\":[\"achievement.name\",\"achievement.description\"]}";

            AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
            when(session.getAuthNote("subject_did")).thenReturn(null);
            when(session.getAuthNote("issuer_did")).thenReturn(null);
            when(session.getAuthNote("requested_credential")).thenReturn(requestedCredentialJson);

            Map<String, String> result = CredentialAttributeExtractor.extractFromDidWeb(
                session, credentialSubject, mapper.createObjectNode(), requestedCredentialJson
            );

            assertNotNull(result);
            assertEquals("Bachelor Degree", result.get("achievement.name"));
            assertEquals("Computer Science", result.get("achievement.description"));
        }

        @Test
        @DisplayName("Scenario 3: Subject DID validation passes")
        void scenario3_subjectDidValidationPasses() throws Exception {
            String credentialSubjectJson = "{\"id\":\"did:web:expected\",\"name\":\"Bob\"}";
            JsonNode credentialSubject = mapper.readTree(credentialSubjectJson);
            String requestedCredentialJson = "{\"credential_type\":\"VerifiableDiploma\",\"attributes\":[\"name\"]}";

            AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
            when(session.getAuthNote("subject_did")).thenReturn("did:web:expected");
            when(session.getAuthNote("issuer_did")).thenReturn(null);
            when(session.getAuthNote("requested_credential")).thenReturn(requestedCredentialJson);

            Map<String, String> result = CredentialAttributeExtractor.extractFromDidWeb(
                session, credentialSubject, mapper.createObjectNode(), requestedCredentialJson
            );

            assertNotNull(result);
            assertEquals("Bob", result.get("name"));
        }

        @Test
        @DisplayName("Scenario 4: Subject DID validation fails")
        void scenario4_subjectDidValidationFails() throws Exception {
            String credentialSubjectJson = "{\"id\":\"did:web:wrong\",\"name\":\"Bob\"}";
            JsonNode credentialSubject = mapper.readTree(credentialSubjectJson);
            String requestedCredentialJson = "{\"credential_type\":\"VerifiableDiploma\",\"attributes\":[\"name\"]}";

            AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
            when(session.getAuthNote("subject_did")).thenReturn("did:web:expected");
            when(session.getAuthNote("issuer_did")).thenReturn(null);
            when(session.getAuthNote("requested_credential")).thenReturn(requestedCredentialJson);

            Map<String, String> result = CredentialAttributeExtractor.extractFromDidWeb(
                session, credentialSubject, mapper.createObjectNode(), requestedCredentialJson
            );

            assertNull(result);
            verify(session).setAuthNote(eq("ssi_failure_reason"), eq("subject_did_mismatch"));
        }

        @Test
        @DisplayName("Scenario 5: Issuer DID validation from policyResults")
        void scenario5_issuerDidValidation() throws Exception {
            String credentialSubjectJson = "{\"id\":\"did:web:user1\",\"name\":\"Charlie\"}";
            JsonNode credentialSubject = mapper.readTree(credentialSubjectJson);
            String policyResultsJson = "{\"results\":[{\"credential\":\"VerifiableDiploma\",\"policyResults\":[{\"result\":{\"vc\":{\"issuer\":{\"id\":\"did:web:expected\"}}}}]}]}";
            JsonNode policyResults = mapper.readTree(policyResultsJson);
            String requestedCredentialJson = "{\"credential_type\":\"VerifiableDiploma\",\"attributes\":[\"name\"]}";

            AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
            when(session.getAuthNote("subject_did")).thenReturn(null);
            when(session.getAuthNote("issuer_did")).thenReturn("did:web:expected");
            when(session.getAuthNote("requested_credential")).thenReturn(requestedCredentialJson);

            Map<String, String> result = CredentialAttributeExtractor.extractFromDidWeb(
                session, credentialSubject, policyResults, requestedCredentialJson
            );

            assertNotNull(result);
            assertEquals("Charlie", result.get("name"));
        }

        @Test
        @DisplayName("Scenario 6: Fallback extraction when no attributes requested")
        void scenario6_fallbackExtraction() throws Exception {
            String credentialSubjectJson = "{\"id\":\"did:web:user1\",\"name\":\"Dave\",\"email\":\"dave@test.com\",\"age\":30}";
            JsonNode credentialSubject = mapper.readTree(credentialSubjectJson);
            String requestedCredentialJson = "{\"credential_type\":\"VerifiableDiploma\",\"attributes\":[]}";

            AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
            when(session.getAuthNote("subject_did")).thenReturn(null);
            when(session.getAuthNote("issuer_did")).thenReturn(null);
            when(session.getAuthNote("requested_credential")).thenReturn(requestedCredentialJson);

            Map<String, String> result = CredentialAttributeExtractor.extractFromDidWeb(
                session, credentialSubject, mapper.createObjectNode(), requestedCredentialJson
            );

            assertNotNull(result);
            assertTrue(result.size() > 0);
        }
    }

    @Nested
    @DisplayName("Attribute extraction edge cases")
    class EdgeCases {

        @Test
        @DisplayName("Empty credential subject returns empty map")
        void emptyCredentialSubject() throws Exception {
            String credentialSubjectJson = "{}";
            JsonNode credentialSubject = mapper.readTree(credentialSubjectJson);
            String requestedCredentialJson = "{\"credential_type\":\"VerifiableDiploma\",\"attributes\":[]}";

            AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
            when(session.getAuthNote("subject_did")).thenReturn(null);
            when(session.getAuthNote("issuer_did")).thenReturn(null);
            when(session.getAuthNote("requested_credential")).thenReturn(requestedCredentialJson);

            Map<String, String> result = CredentialAttributeExtractor.extractFromDidWeb(
                session, credentialSubject, mapper.createObjectNode(), requestedCredentialJson
            );

            assertNotNull(result);
            assertTrue(result.isEmpty());
        }

        @Test
        @DisplayName("Missing id field with subject_did configured fails validation")
        void missingIdWithSubjectDidConfigured() throws Exception {
            String credentialSubjectJson = "{\"name\":\"Eve\"}";
            JsonNode credentialSubject = mapper.readTree(credentialSubjectJson);
            String requestedCredentialJson = "{\"credential_type\":\"VerifiableDiploma\",\"attributes\":[\"name\"]}";

            AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
            when(session.getAuthNote("subject_did")).thenReturn("did:web:expected");
            when(session.getAuthNote("issuer_did")).thenReturn(null);
            when(session.getAuthNote("requested_credential")).thenReturn(requestedCredentialJson);

            Map<String, String> result = CredentialAttributeExtractor.extractFromDidWeb(
                session, credentialSubject, mapper.createObjectNode(), requestedCredentialJson
            );

            assertNull(result);
            verify(session).setAuthNote(eq("ssi_failure_reason"), eq("subject_id_missing"));
        }
    }
}

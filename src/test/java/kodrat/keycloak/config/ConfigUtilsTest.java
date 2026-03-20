package kodrat.keycloak.config;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import kodrat.keycloak.constant.SSISessionConstants;

import java.util.List;
import java.util.Map;

/**
 * Characterization tests for ConfigUtils.
 * Tests config parsing, schema_id/schemaId compatibility, and attribute extraction.
 */
class ConfigUtilsTest {

    @Test
    void getDIDMethod_fromContext_returnsConfiguredValue() {
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        AuthenticatorConfigModel config = mock(AuthenticatorConfigModel.class);
        when(context.getAuthenticatorConfig()).thenReturn(config);
        when(config.getConfig()).thenReturn(Map.of("did_method", "web"));

        String result = ConfigUtils.getDIDMethod(context);
        assertEquals("web", result);
    }

    @Test
    void getDIDMethod_fromSession_returnsAuthNoteValue() {
        AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
        when(session.getAuthNote(SSISessionConstants.DID_METHOD)).thenReturn("sov");

        String result = ConfigUtils.getDIDMethod(session);
        assertEquals("sov", result);
    }

    @Test
    void getSchemaId_withSchemaIdField_returnsValue() {
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        AuthenticatorConfigModel config = mock(AuthenticatorConfigModel.class);
        when(context.getAuthenticatorConfig()).thenReturn(config);
        when(config.getConfig()).thenReturn(Map.of(
            "proof_request_json", "{\"schema_id\":\"schema123\",\"attributes\":[\"name\"]}"
        ));

        String result = ConfigUtils.getSchemaId(context);
        assertEquals("schema123", result);
    }

    @Test
    void getSchemaId_withSchemaIdCamelCase_returnsValue() {
        // Now supports camelCase for backward compatibility
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        AuthenticatorConfigModel config = mock(AuthenticatorConfigModel.class);
        when(context.getAuthenticatorConfig()).thenReturn(config);
        when(config.getConfig()).thenReturn(Map.of(
            "proof_request_json", "{\"schemaId\":\"schema123\",\"attributes\":[\"name\"]}"
        ));

        String result = ConfigUtils.getSchemaId(context);
        // Now supports both schema_id and schemaId
        assertEquals("schema123", result);
    }

    @Test
    void getSchemaId_prefersSnakeCase_overCamelCase() {
        // When both present, snake_case takes precedence
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        AuthenticatorConfigModel config = mock(AuthenticatorConfigModel.class);
        when(context.getAuthenticatorConfig()).thenReturn(config);
        when(config.getConfig()).thenReturn(Map.of(
            "proof_request_json", "{\"schema_id\":\"snake_case_value\",\"schemaId\":\"camelCaseValue\",\"attributes\":[\"name\"]}"
        ));

        String result = ConfigUtils.getSchemaId(context);
        assertEquals("snake_case_value", result);
    }

    @Test
    void getSchemaId_withEmptyJson_returnsNull() {
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        AuthenticatorConfigModel config = mock(AuthenticatorConfigModel.class);
        when(context.getAuthenticatorConfig()).thenReturn(config);
        when(config.getConfig()).thenReturn(Map.of("proof_request_json", ""));

        String result = ConfigUtils.getSchemaId(context);
        assertNull(result);
    }

    @Test
    void getSchemaId_withInvalidJson_returnsNull() {
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        AuthenticatorConfigModel config = mock(AuthenticatorConfigModel.class);
        when(context.getAuthenticatorConfig()).thenReturn(config);
        when(config.getConfig()).thenReturn(Map.of("proof_request_json", "invalid json"));

        // New behavior: returns null gracefully instead of throwing exception
        assertNull(ConfigUtils.getSchemaId(context));
    }

    @Test
    void getRequestedAttributes_withValidConfig_returnsAttributes() {
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        AuthenticatorConfigModel config = mock(AuthenticatorConfigModel.class);
        when(context.getAuthenticatorConfig()).thenReturn(config);
        when(config.getConfig()).thenReturn(Map.of(
            "proof_request_json", "{\"schema_id\":\"schema123\",\"attributes\":[\"name\",\"email\"]}"
        ));

        List<String> result = ConfigUtils.getRequestedAttributes(context);
        assertEquals(List.of("name", "email"), result);
    }

    @Test
    void getRequestedAttributes_withNoConfig_returnsDefaults() {
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        AuthenticatorConfigModel config = mock(AuthenticatorConfigModel.class);
        when(context.getAuthenticatorConfig()).thenReturn(config);
        when(config.getConfig()).thenReturn(Map.of());

        List<String> result = ConfigUtils.getRequestedAttributes(context);
        assertEquals(List.of("name", "NIK", "email", "phone"), result);
    }

    @Test
    void getRequestedAttributes_withInvalidJson_returnsDefaults() {
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        AuthenticatorConfigModel config = mock(AuthenticatorConfigModel.class);
        when(context.getAuthenticatorConfig()).thenReturn(config);
        when(config.getConfig()).thenReturn(Map.of(
            "proof_request_json", "invalid json"
        ));

        List<String> result = ConfigUtils.getRequestedAttributes(context);
        assertEquals(List.of("name", "NIK", "email", "phone"), result);
    }

    @Test
    void getSSIEndpoint_fromContext_returnsConfiguredValue() {
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        AuthenticatorConfigModel config = mock(AuthenticatorConfigModel.class);
        when(context.getAuthenticatorConfig()).thenReturn(config);
        when(config.getConfig()).thenReturn(Map.of("ssi_endpoint", "https://ssi.example.com"));

        String result = ConfigUtils.getSSIEndpoint(context);
        assertEquals("https://ssi.example.com", result);
    }

    @Test
    void getSSIEndpoint_fromSession_returnsAuthNoteValue() {
        AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
        when(session.getAuthNote(SSISessionConstants.SSI_ENDPOINT)).thenReturn("https://ssi.example.com");

        String result = ConfigUtils.getSSIEndpoint(session);
        assertEquals("https://ssi.example.com", result);
    }

    @Test
    void getBearerToken_fromContext_returnsConfiguredValue() {
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        AuthenticatorConfigModel config = mock(AuthenticatorConfigModel.class);
        when(context.getAuthenticatorConfig()).thenReturn(config);
        when(config.getConfig()).thenReturn(Map.of("ssi_bearer_token", "secret-token"));

        String result = ConfigUtils.getBearerToken(context);
        assertEquals("secret-token", result);
    }

    @Test
    void getBearerToken_fromSession_returnsAuthNoteValue() {
        AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
        when(session.getAuthNote(SSISessionConstants.SSI_BEARER_TOKEN)).thenReturn("secret-token");

        String result = ConfigUtils.getBearerToken(session);
        assertEquals("secret-token", result);
    }

    @Test
    void getBearerToken_fromContext_supportsLegacySsiTokenKey() {
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        AuthenticatorConfigModel config = mock(AuthenticatorConfigModel.class);
        when(context.getAuthenticatorConfig()).thenReturn(config);
        when(config.getConfig()).thenReturn(Map.of("ssi_token", "legacy-token"));

        String result = ConfigUtils.getBearerToken(context);
        assertEquals("legacy-token", result);
    }

    @Test
    void getBearerToken_fromSession_supportsLegacySsiTokenNote() {
        AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
        when(session.getAuthNote(SSISessionConstants.SSI_BEARER_TOKEN)).thenReturn(null);
        when(session.getAuthNote(SSISessionConstants.SSI_TOKEN)).thenReturn("legacy-token");

        String result = ConfigUtils.getBearerToken(session);
        assertEquals("legacy-token", result);
    }

    @Test
    void getProofRequestJson_withValidConfig_returnsJsonNode() {
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        AuthenticatorConfigModel config = mock(AuthenticatorConfigModel.class);
        when(context.getAuthenticatorConfig()).thenReturn(config);
        when(config.getConfig()).thenReturn(Map.of(
            "proof_request_json", "{\"schema_id\":\"schema123\",\"attributes\":[\"name\"]}"
        ));

        JsonNode result = ConfigUtils.getProofRequestJson(context);
        assertNotNull(result);
        assertEquals("schema123", result.get("schema_id").asText());
    }

    @Test
    void getProofRequestJson_withEmptyConfig_returnsNull() {
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        AuthenticatorConfigModel config = mock(AuthenticatorConfigModel.class);
        when(context.getAuthenticatorConfig()).thenReturn(config);
        when(config.getConfig()).thenReturn(Map.of());

        JsonNode result = ConfigUtils.getProofRequestJson(context);
        assertNull(result);
    }

    @Test
    void getCredentialType_withValidConfig_returnsType() {
        Map<String, String> config = Map.of(
            "requested_credential", "{\"credential_type\":\"EducationalID\",\"attributes\":[\"name\"]}"
        );

        String result = ConfigUtils.getCredentialType(config);
        assertEquals("EducationalID", result);
    }

    @Test
    void getCredentialType_withEmptyConfig_returnsDefault() {
        Map<String, String> config = Map.of();

        String result = ConfigUtils.getCredentialType(config);
        assertEquals("VerifiableDiploma", result);
    }

    @Test
    void getCredentialType_withInvalidJson_returnsDefault() {
        Map<String, String> config = Map.of("requested_credential", "invalid json");

        String result = ConfigUtils.getCredentialType(config);
        assertEquals("VerifiableDiploma", result);
    }

    // ==== extractSchemaId (String) tests ====

    @Test
    void extractSchemaId_fromString_withSchemaIdSnakeCase_returnsValue() {
        String json = "{\"schema_id\":\"test_schema_123\",\"attributes\":[\"name\"]}";
        assertEquals("test_schema_123", ConfigUtils.extractSchemaId(json));
    }

    @Test
    void extractSchemaId_fromString_withSchemaIdCamelCase_returnsValue() {
        String json = "{\"schemaId\":\"testSchema456\",\"attributes\":[\"name\"]}";
        assertEquals("testSchema456", ConfigUtils.extractSchemaId(json));
    }

    @Test
    void extractSchemaId_fromString_prefersSnakeCase_returnsSnakeCase() {
        String json = "{\"schema_id\":\"snake_case\",\"schemaId\":\"camelCase\"}";
        assertEquals("snake_case", ConfigUtils.extractSchemaId(json));
    }

    @Test
    void extractSchemaId_fromString_withNullInput_returnsNull() {
        assertNull(ConfigUtils.extractSchemaId((String) null));
    }

    @Test
    void extractSchemaId_fromString_withEmptyInput_returnsNull() {
        assertNull(ConfigUtils.extractSchemaId(""));
    }

    @Test
    void extractSchemaId_fromString_withInvalidJson_returnsNull() {
        assertNull(ConfigUtils.extractSchemaId("not valid json"));
    }

    @Test
    void extractSchemaId_fromString_withNoSchemaField_returnsNull() {
        String json = "{\"attributes\":[\"name\"]}";
        assertNull(ConfigUtils.extractSchemaId(json));
    }

    // ==== extractSchemaId (JsonNode) tests ====

    @Test
    void extractSchemaId_fromJsonNode_withSchemaIdSnakeCase_returnsValue() throws Exception {
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        JsonNode node = mapper.readTree("{\"schema_id\":\"node_schema\"}");
        assertEquals("node_schema", ConfigUtils.extractSchemaId(node));
    }

    @Test
    void extractSchemaId_fromJsonNode_withSchemaIdCamelCase_returnsValue() throws Exception {
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        JsonNode node = mapper.readTree("{\"schemaId\":\"nodeSchema\"}");
        assertEquals("nodeSchema", ConfigUtils.extractSchemaId(node));
    }

    @Test
    void extractSchemaId_fromJsonNode_withNullInput_returnsNull() {
        assertNull(ConfigUtils.extractSchemaId((JsonNode) null));
    }
}

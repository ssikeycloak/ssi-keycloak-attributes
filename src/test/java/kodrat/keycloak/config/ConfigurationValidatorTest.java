package kodrat.keycloak.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;

import java.util.HashMap;
import java.util.Map;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ConfigurationValidatorTest {

    @Mock
    private AuthenticationFlowContext context;

    @Mock
    private AuthenticatorConfigModel config;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testValidate_NullContext_ReturnsError() {
        ConfigurationValidator.ValidationResult result = ConfigurationValidator.validate(null);
        assertFalse(result.isValid());
        assertTrue(result.getErrors().size() > 0);
    }

    @Test
    void testValidate_NullConfig_ReturnsError() {
        when(context.getAuthenticatorConfig()).thenReturn(null);
        ConfigurationValidator.ValidationResult result = ConfigurationValidator.validate(context);
        assertFalse(result.isValid());
    }

    @Test
    void testValidate_EmptyConfig_ReturnsError() {
        when(context.getAuthenticatorConfig()).thenReturn(config);
        when(config.getConfig()).thenReturn(new HashMap<>());
        
        ConfigurationValidator.ValidationResult result = ConfigurationValidator.validate(context);
        assertFalse(result.isValid());
    }

    @Test
    void testValidate_ValidMinimalConfig() {
        Map<String, String> configMap = new HashMap<>();
        configMap.put("ssi_endpoint", "https://agent.example.com");
        
        when(context.getAuthenticatorConfig()).thenReturn(config);
        when(config.getConfig()).thenReturn(configMap);
        
        ConfigurationValidator.ValidationResult result = ConfigurationValidator.validate(context);
        assertTrue(result.isValid() || result.getErrors().contains("DID method not specified"));
    }

    @Test
    void testValidate_InvalidEndpointUrl_ReturnsError() {
        Map<String, String> configMap = new HashMap<>();
        configMap.put("ssi_endpoint", "not-a-valid-url");
        
        when(context.getAuthenticatorConfig()).thenReturn(config);
        when(config.getConfig()).thenReturn(configMap);
        
        ConfigurationValidator.ValidationResult result = ConfigurationValidator.validate(context);
        assertFalse(result.isValid());
    }

    @Test
    void testValidate_HttpEndpoint_Warns() {
        Map<String, String> configMap = new HashMap<>();
        configMap.put("ssi_endpoint", "http://localhost:8000");
        
        when(context.getAuthenticatorConfig()).thenReturn(config);
        when(config.getConfig()).thenReturn(configMap);
        
        ConfigurationValidator.ValidationResult result = ConfigurationValidator.validate(context);
        assertFalse(result.getWarnings().isEmpty());
    }

    @Test
    void testValidationResult_Getters() {
        ConfigurationValidator.ValidationResult result = new ConfigurationValidator.ValidationResult(
            true, 
            java.util.Collections.emptyList(), 
            java.util.Collections.singletonList("warning1")
        );
        
        assertTrue(result.isValid());
        assertFalse(result.getWarnings().isEmpty());
        assertEquals("warning1", result.getWarningMessage());
    }
}

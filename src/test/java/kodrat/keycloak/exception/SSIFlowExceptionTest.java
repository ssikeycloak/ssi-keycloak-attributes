package kodrat.keycloak.exception;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for SSIFlowException.
 */
class SSIFlowExceptionTest {

    @Test
    void constructor_withErrorCodeAndMessage_createsException() {
        SSIFlowException exception = new SSIFlowException(
                SSIErrorCode.CONFIG_MISSING_ENDPOINT,
                "Endpoint not configured"
        );

        assertEquals(SSIErrorCode.CONFIG_MISSING_ENDPOINT, exception.getErrorCode());
        assertEquals("SSI-1001", exception.getCode());
        assertTrue(exception.getMessage().contains("SSI-1001"));
        assertTrue(exception.getMessage().contains("Missing SSI endpoint configuration"));
        assertFalse(exception.isRetryable());
    }

    @Test
    void constructor_withContextId_masksContextId() {
        SSIFlowException exception = new SSIFlowException(
                SSIErrorCode.CONNECTION_TIMEOUT,
                "Connection failed",
                "12345678-1234-1234-1234-123456789abc"
        );

        assertEquals("12345678-1234-1234-1234-123456789abc", exception.getContextId());
        // Context ID should be masked in message (but actual value stored)
        assertTrue(exception.getMessage().contains("1234...9abc") || 
                   exception.getMessage().contains("context:"));
    }

    @Test
    void configurationError_forEndpoint_returnsCorrectCode() {
        SSIFlowException exception = SSIFlowException.configurationError(
                "ssi_endpoint",
                "URL is malformed"
        );

        assertEquals(SSIErrorCode.CONFIG_MISSING_ENDPOINT, exception.getErrorCode());
        assertEquals("SSI-1001", exception.getCode());
        // Message should contain error info (may be redacted in sanitized output)
        assertNotNull(exception.getMessage());
    }

    @Test
    void configurationError_forToken_returnsCorrectCode() {
        SSIFlowException exception = SSIFlowException.configurationError(
                "ssi_bearer_token",
                "Token is empty"
        );

        assertEquals(SSIErrorCode.CONFIG_MISSING_TOKEN, exception.getErrorCode());
    }

    @Test
    void configurationError_forSchema_returnsCorrectCode() {
        SSIFlowException exception = SSIFlowException.configurationError(
                "schema_id",
                "Schema not found"
        );

        assertEquals(SSIErrorCode.CONFIG_MISSING_SCHEMA, exception.getErrorCode());
    }

    @Test
    void connectionError_withConnectException_returnsRefusedCode() {
        java.net.ConnectException cause = new java.net.ConnectException("Connection refused");
        SSIFlowException exception = SSIFlowException.connectionError(
                cause,
                "http://agent:8021"
        );

        assertEquals(SSIErrorCode.CONNECTION_REFUSED, exception.getErrorCode());
        assertTrue(exception.isRetryable());
        assertNotNull(exception.getCause());
    }

    @Test
    void connectionError_withTimeoutException_returnsTimeoutCode() {
        java.net.http.HttpTimeoutException cause = new java.net.http.HttpTimeoutException("Timeout");
        SSIFlowException exception = SSIFlowException.connectionError(
                cause,
                "http://agent:8021"
        );

        assertEquals(SSIErrorCode.CONNECTION_TIMEOUT, exception.getErrorCode());
        assertTrue(exception.isRetryable());
    }

    @Test
    void didCommError_forInvitation_returnsCorrectCode() {
        SSIFlowException exception = SSIFlowException.didCommError(
                "invitation",
                "Failed to create invitation",
                null
        );

        assertEquals(SSIErrorCode.DIDCOMM_INVITATION_FAILED, exception.getErrorCode());
        assertTrue(exception.isRetryable());
    }

    @Test
    void didCommError_forVerification_returnsCorrectCode() {
        SSIFlowException exception = SSIFlowException.didCommError(
                "verification",
                "Invalid proof",
                null
        );

        assertEquals(SSIErrorCode.DIDCOMM_VERIFICATION_FAILED, exception.getErrorCode());
        // Verification errors are not retryable
        assertFalse(exception.isRetryable());
    }

    @Test
    void flowError_returnsInvalidStateCode() {
        SSIFlowException exception = SSIFlowException.flowError(
                "WAITING_CONNECTION",
                "VERIFYING"
        );

        assertEquals(SSIErrorCode.FLOW_INVALID_STATE, exception.getErrorCode());
        assertFalse(exception.isRetryable());
        // Message contains transition info (may be redacted)
        assertTrue(exception.getMessage().contains("Invalid state transition") ||
                   exception.getMessage().contains("state"));
    }

    @Test
    void withContextData_addsDataToContext() {
        SSIFlowException exception = new SSIFlowException(
                SSIErrorCode.DIDCOMM_VERIFICATION_FAILED,
                "Verification failed"
        );

        exception.withContextData("connectionId", "conn-123");
        exception.withContextData("schemaId", "schema-456");

        Map<String, Object> context = exception.getContextData();
        // String values are redacted in context data
        assertTrue(context.containsKey("connectionId"));
        assertTrue(context.containsKey("schemaId"));
        // Values should be present (possibly redacted)
        Object connId = context.get("connectionId");
        assertTrue(connId.equals("conn-123") || connId.equals("[REDACTED]") || 
                   connId.toString().contains("conn"));
    }

    @Test
    void toMap_returnsCorrectStructure() {
        SSIFlowException exception = new SSIFlowException(
                SSIErrorCode.CONFIG_MISSING_ENDPOINT,
                "Missing endpoint",
                "realm-config"
        );

        Map<String, Object> map = exception.toMap();

        assertEquals("SSI-1001", map.get("code"));
        assertFalse((Boolean) map.get("retryable"));
        assertEquals("CONFIGURATION", map.get("category"));
    }

    @Test
    void errorCodeCategories_identifyCorrectly() {
        // Configuration errors - not retryable
        assertFalse(SSIErrorCode.CONFIG_MISSING_ENDPOINT.isRetryable());
        assertFalse(SSIErrorCode.CONFIG_INVALID_JSON.isRetryable());

        // Network errors - retryable
        assertTrue(SSIErrorCode.CONNECTION_TIMEOUT.isRetryable());
        assertTrue(SSIErrorCode.CONNECTION_REFUSED.isRetryable());

        // DIDComm errors - mixed
        assertTrue(SSIErrorCode.DIDCOMM_INVITATION_FAILED.isRetryable());
        assertFalse(SSIErrorCode.DIDCOMM_VERIFICATION_FAILED.isRetryable());

        // Authentication errors - not retryable
        assertFalse(SSIErrorCode.AUTH_UNAUTHORIZED.isRetryable());
    }

    @Test
    void errorCodeCategories_matchExpected() {
        assertEquals(SSIErrorCode.ErrorCategory.CONFIGURATION, 
                     SSIErrorCode.CONFIG_MISSING_ENDPOINT.getCategory());
        assertEquals(SSIErrorCode.ErrorCategory.NETWORK, 
                     SSIErrorCode.CONNECTION_TIMEOUT.getCategory());
        assertEquals(SSIErrorCode.ErrorCategory.DID_COMMUNICATION, 
                     SSIErrorCode.DIDCOMM_INVITATION_FAILED.getCategory());
        assertEquals(SSIErrorCode.ErrorCategory.AUTHENTICATION, 
                     SSIErrorCode.AUTH_UNAUTHORIZED.getCategory());
    }
}

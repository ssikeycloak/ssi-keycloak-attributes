package kodrat.keycloak.service;

import kodrat.keycloak.constant.SSISessionConstants;
import kodrat.keycloak.constant.SSIStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Integration tests for SSI failure-retry-recovery scenarios.
 * Tests the centralized reset service and state management.
 */
class SSIStateResetServiceTest {

    private AuthenticationSessionModel mockSession;
    private Map<String, String> authNotes;

    @BeforeEach
    void setUp() {
        mockSession = mock(AuthenticationSessionModel.class);
        authNotes = new HashMap<>();
        
        // Mock auth note operations
        when(mockSession.getAuthNote(anyString())).thenAnswer(invocation -> {
            String key = invocation.getArgument(0);
            return authNotes.get(key);
        });
        
        doAnswer(invocation -> {
            String key = invocation.getArgument(0);
            String value = invocation.getArgument(1);
            authNotes.put(key, value);
            return null;
        }).when(mockSession).setAuthNote(anyString(), anyString());
        
        doAnswer(invocation -> {
            String key = invocation.getArgument(0);
            authNotes.remove(key);
            return null;
        }).when(mockSession).removeAuthNote(anyString());
        
        when(mockSession.getTabId()).thenReturn("test-tab-123");
    }

    @Test
    @DisplayName("Scenario 1: Invalid state -> retry -> reset -> new flow")
    void scenario_invalidToRetryReset() {
        // Setup: session in invalid state
        authNotes.put(SSISessionConstants.SSI_STATUS, SSIStatus.INVALID.getValue());
        authNotes.put(SSISessionConstants.PRES_EX_ID, "old-pres-ex-id");
        authNotes.put(SSISessionConstants.CONNECTION_ID, "old-conn-id");
        authNotes.put(SSISessionConstants.SSI_FLOW_ID, "old-flow-id");
        
        // Act: reset for retry
        String newFlowId = SSIStateResetService.resetForRetry(mockSession);
        
        // Assert: all transient notes cleared
        assertNull(authNotes.get(SSISessionConstants.SSI_STATUS));
        assertNull(authNotes.get(SSISessionConstants.PRES_EX_ID));
        assertNull(authNotes.get(SSISessionConstants.CONNECTION_ID));
        
        // Assert: new flow ID assigned
        assertNotNull(newFlowId);
        assertNotEquals("old-flow-id", newFlowId);
        assertEquals(newFlowId, authNotes.get(SSISessionConstants.SSI_FLOW_ID));
    }

    @Test
    @DisplayName("Scenario 2: Timeout state -> retry -> waiting-connection")
    void scenario_timeoutToRetryToWaiting() {
        // Setup: session timed out
        authNotes.put(SSISessionConstants.SSI_STATUS, SSIStatus.WAITING_CONNECTION.getValue());
        authNotes.put(SSISessionConstants.INVITATION_URL, "old-invitation-url");
        
        // Act: reset for retry
        String newFlowId = SSIStateResetService.resetForRetry(mockSession);
        
        // Assert: transient state cleared
        assertNull(authNotes.get(SSISessionConstants.SSI_STATUS));
        assertNull(authNotes.get(SSISessionConstants.INVITATION_URL));
        
        // Assert: new flow ID for new attempt
        assertNotNull(newFlowId);
        assertTrue(newFlowId.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"));
    }

    @Test
    @DisplayName("Scenario 3: All transient keys are cleared and new flow ID assigned")
    void scenario_allTransientKeysCleared() {
        // Setup: populate all transient notes
        for (String key : SSIStateResetService.getTransientNoteKeys()) {
            authNotes.put(key, "value-" + key);
        }
        
        // Act: reset
        SSIStateResetService.resetTransientFlowState(mockSession);
        
        // Assert: all transient notes except flow_id are cleared
        // Note: ssi_flow_id is cleared then immediately set with new value
        for (String key : SSIStateResetService.getTransientNoteKeys()) {
            if (SSISessionConstants.SSI_FLOW_ID.equals(key)) {
                // flow_id should have new value, not old value
                assertNotNull(authNotes.get(key), "flow_id should be set");
                assertNotEquals("value-" + key, authNotes.get(key), "flow_id should be new value");
            } else {
                assertNull(authNotes.get(key), "Key should be cleared: " + key);
            }
        }
    }

    @Test
    @DisplayName("Scenario 4: Multiple retries generate unique flow IDs")
    void scenario_multipleRetriesUniqueFlowIds() {
        // Act: multiple resets
        String flowId1 = SSIStateResetService.resetTransientFlowState(mockSession);
        String flowId2 = SSIStateResetService.resetTransientFlowState(mockSession);
        String flowId3 = SSIStateResetService.resetTransientFlowState(mockSession);
        
        // Assert: all unique
        assertNotEquals(flowId1, flowId2);
        assertNotEquals(flowId2, flowId3);
        assertNotEquals(flowId1, flowId3);
    }

    @Test
    @DisplayName("Scenario 5: Reset preserves config notes (endpoint, bearer token)")
    void scenario_resetPreservesConfigNotes() {
        // Setup: config notes that should NOT be cleared
        // Note: These are not in TRANSIENT_AUTH_NOTES, so they should persist
        authNotes.put("ssi_endpoint", "https://agent.example.com");
        authNotes.put("ssi_bearer_token", "secret-token");
        authNotes.put(SSISessionConstants.DID_METHOD, "sov");
        
        // Also set transient notes
        authNotes.put(SSISessionConstants.SSI_STATUS, SSIStatus.INVALID.getValue());
        
        // Act: reset
        SSIStateResetService.resetTransientFlowState(mockSession);
        
        // Assert: config notes preserved
        assertEquals("https://agent.example.com", authNotes.get("ssi_endpoint"));
        assertEquals("secret-token", authNotes.get("ssi_bearer_token"));
        assertEquals("sov", authNotes.get(SSISessionConstants.DID_METHOD));
        
        // Assert: transient notes cleared
        assertNull(authNotes.get(SSISessionConstants.SSI_STATUS));
    }

    @Test
    @DisplayName("Scenario 6: Verified claims are cleared on retry (privacy)")
    void scenario_verifiedClaimsClearedOnRetry() {
        // Setup: verified claims from previous attempt
        authNotes.put(SSISessionConstants.VERIFIED_CLAIMS, "{\"name\":\"John\",\"NIK\":\"123456\"}");
        authNotes.put(SSISessionConstants.SSI_STATUS, SSIStatus.DONE.getValue());
        
        // Act: reset for retry
        SSIStateResetService.resetForRetry(mockSession);
        
        // Assert: verified claims cleared for privacy
        assertNull(authNotes.get(SSISessionConstants.VERIFIED_CLAIMS));
        assertNull(authNotes.get(SSISessionConstants.SSI_STATUS));
    }

    @Test
    @DisplayName("Scenario 7: DID:SOV specific notes cleared")
    void scenario_didSovNotesCleared() {
        // Setup: DID:SOV specific state
        authNotes.put(SSISessionConstants.INVI_MSG_ID, "msg-123");
        authNotes.put(SSISessionConstants.OOB_QR_SHOWN_AT, "1708400000000");
        authNotes.put(SSISessionConstants.OOB_QR_SCANNED_AT, "1708400001000");
        authNotes.put(SSISessionConstants.SOV_ACCEPT_CONN_ID, "conn-456");
        authNotes.put(SSISessionConstants.SOV_ACCEPT_LAST_AT, "1708400002000");
        authNotes.put(SSISessionConstants.SOV_ACCEPTED_CONN_ID, "conn-789");
        
        // Act: reset
        SSIStateResetService.resetTransientFlowState(mockSession);
        
        // Assert: all DID:SOV notes cleared
        assertNull(authNotes.get(SSISessionConstants.INVI_MSG_ID));
        assertNull(authNotes.get(SSISessionConstants.OOB_QR_SHOWN_AT));
        assertNull(authNotes.get(SSISessionConstants.OOB_QR_SCANNED_AT));
        assertNull(authNotes.get(SSISessionConstants.SOV_ACCEPT_CONN_ID));
        assertNull(authNotes.get(SSISessionConstants.SOV_ACCEPT_LAST_AT));
        assertNull(authNotes.get(SSISessionConstants.SOV_ACCEPTED_CONN_ID));
    }

    @Test
    @DisplayName("Scenario 8: Empty session reset succeeds")
    void scenario_emptySessionResetSucceeds() {
        // Setup: empty session
        assertTrue(authNotes.isEmpty());
        
        // Act: should not throw
        String flowId = SSIStateResetService.resetTransientFlowState(mockSession);
        
        // Assert: flow ID assigned
        assertNotNull(flowId);
        assertEquals(flowId, authNotes.get(SSISessionConstants.SSI_FLOW_ID));
    }
}

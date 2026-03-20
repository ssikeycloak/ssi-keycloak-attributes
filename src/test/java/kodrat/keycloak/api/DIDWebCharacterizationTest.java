package kodrat.keycloak.api;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;
import java.util.*;
import kodrat.keycloak.constant.SSISessionConstants;
import kodrat.keycloak.constant.SSIStatus;
import kodrat.keycloak.exception.SSIException;
import kodrat.keycloak.service.HttpClientService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.keycloak.sessions.AuthenticationSessionModel;

@DisplayName("DIDWeb Characterization Tests - Captures current behavior before refactoring")
class DIDWebCharacterizationTest {

    private DIDWeb didWeb;
    private HttpClientService httpClientService;
    private AuthenticationSessionModel session;
    private Map<String, String> authNotes;

    @BeforeEach
    void setUp() throws Exception {
        didWeb = new DIDWeb("https://agent.example.com", "test-token");
        httpClientService = mock(HttpClientService.class);
        setField(didWeb, "httpClient", httpClientService);

        session = mock(AuthenticationSessionModel.class);
        authNotes = new HashMap<>();

        when(session.getAuthNote(anyString())).thenAnswer(inv -> authNotes.get(inv.getArgument(0)));
        doAnswer(inv -> { authNotes.put(inv.getArgument(0), inv.getArgument(1)); return null; }).when(session).setAuthNote(anyString(), anyString());
        doAnswer(inv -> { authNotes.remove(inv.getArgument(0)); return null; }).when(session).removeAuthNote(anyString());
    }

    @Nested
    @DisplayName("isConnectionEstablished behavior")
    class IsConnectionEstablishedTests {
        @Test
        @DisplayName("always returns true for DIDWeb (connectionless)")
        void returnsTrue() {
            boolean result = didWeb.isConnectionEstablished(session);
            assertTrue(result, "DIDWeb should always return true for connection check (connectionless)");
        }
    }

    @Nested
    @DisplayName("hasReceivedPresentation behavior")
    class HasReceivedPresentationTests {
        @Test
        @DisplayName("returns false when stateId not in session")
        void returnsFalseWhenNoStateId() {
            boolean result = didWeb.hasReceivedPresentation(session);
            assertFalse(result);
        }

        @Test
        @DisplayName("returns true when credential subject present")
        void returnsTrueWhenCredentialSubjectPresent() throws Exception {
            authNotes.put(SSISessionConstants.SSI_STATE_ID, "state-123");
            String response = "{\"policyResults\":{\"results\":[{\"policyResults\":[{\"result\":{\"vc\":{\"credentialSubject\":{\"id\":\"did:web:user1\",\"name\":\"Alice\"}}}}]}]}}";
            when(httpClientService.get(anyString(), isNull(), eq(String.class))).thenReturn(response);

            boolean result = didWeb.hasReceivedPresentation(session);
            assertTrue(result);
        }

        @Test
        @DisplayName("returns true and sets failure reason on terminal status")
        void returnsTrueOnTerminalStatus() throws Exception {
            authNotes.put(SSISessionConstants.SSI_STATE_ID, "state-123");
            when(httpClientService.get(anyString(), isNull(), eq(String.class))).thenReturn("{\"status\":\"FAILED\"}");

            boolean result = didWeb.hasReceivedPresentation(session);
            assertTrue(result);
            assertEquals("verifier_terminal_failed", authNotes.get("ssi_failure_reason"));
        }

        @Test
        @DisplayName("clears stale state on 404")
        void clearsStaleStateOn404() throws Exception {
            authNotes.put(SSISessionConstants.SSI_STATE_ID, "stale-state");
            authNotes.put(SSISessionConstants.VERIFICATION_URL, "https://old");
            when(httpClientService.get(anyString(), isNull(), eq(String.class)))
                .thenThrow(new SSIException("HTTP error: 404"));

            boolean result = didWeb.hasReceivedPresentation(session);
            assertFalse(result);
            assertFalse(authNotes.containsKey(SSISessionConstants.SSI_STATE_ID));
            assertEquals(SSIStatus.WAITING_PROOF.getValue(), authNotes.get(SSISessionConstants.SSI_STATUS));
        }
    }

    @Nested
    @DisplayName("sendProofRequest (session-based) behavior")
    class SendProofRequestSessionTests {
        @Test
        @DisplayName("returns success when already has stateId and verificationUrl")
        void returnsSuccessWhenAlreadyInitiated() {
            authNotes.put(SSISessionConstants.SSI_STATE_ID, "existing-state");
            authNotes.put(SSISessionConstants.VERIFICATION_URL, "openid4vp://authorize");

            SSIResult result = didWeb.sendProofRequest(session);
            assertTrue(result.isDone());
        }

        @Test
        @DisplayName("regenerates when stateId exists without verificationUrl")
        void regeneratesWhenStaleState() throws Exception {
            authNotes.put(SSISessionConstants.SSI_STATE_ID, "stale-state");
            authNotes.put(SSISessionConstants.SSI_ENDPOINT, "https://agent.example.com");
            when(httpClientService.post(anyString(), any(), anyMap(), eq(String.class)))
                .thenReturn("openid4vp://authorize?request_uri=abc");

            SSIResult result = didWeb.sendProofRequest(session);
            assertTrue(result.isDone());
            verify(httpClientService).post(anyString(), any(), anyMap(), eq(String.class));
        }
    }

    @Nested
    @DisplayName("generateQRCode behavior")
    class GenerateQRCodeTests {
        @Test
        @DisplayName("generates QR code URL")
        void generatesQrCodeUrl() {
            String result = didWeb.generateQRCode("openid4vp://authorize");
            assertNotNull(result);
            assertTrue(result.startsWith("data:image/png;base64,"));
        }

        @Test
        @DisplayName("throws on null input")
        void throwsOnNull() {
            assertThrows(Exception.class, () -> didWeb.generateQRCode(null));
        }
    }

    @Nested
    @DisplayName("verifyPresentation behavior")
    class VerifyPresentationTests {
        @Test
        @DisplayName("delegates to isVerified")
        void delegatesToIsVerified() {
            boolean result = didWeb.verifyPresentation(session);
            assertFalse(result);
        }
    }

    @Nested
    @DisplayName("Auth Notes behavior")
    class AuthNotesTests {
        @Test
        @DisplayName("sets SSI_STATUS to verifying after sendProofRequest")
        void setsCorrectStatusAfterProofRequest() throws Exception {
            authNotes.put(SSISessionConstants.SSI_ENDPOINT, "https://agent.example.com");
            when(httpClientService.post(anyString(), any(), anyMap(), eq(String.class)))
                .thenReturn("openid4vp://authorize");

            didWeb.sendProofRequest(session);
            assertEquals(SSIStatus.VERIFYING.getValue(), authNotes.get(SSISessionConstants.SSI_STATUS));
        }

        @Test
        @DisplayName("sets INVITATION_URL and VERIFICATION_URL")
        void setsInvitationAndVerificationUrls() throws Exception {
            authNotes.put(SSISessionConstants.SSI_ENDPOINT, "https://agent.example.com");
            when(httpClientService.post(anyString(), any(), anyMap(), eq(String.class)))
                .thenReturn("openid4vp://authorize?test=1");

            didWeb.sendProofRequest(session);
            assertEquals("openid4vp://authorize?test=1", authNotes.get(SSISessionConstants.INVITATION_URL));
            assertEquals("openid4vp://authorize?test=1", authNotes.get(SSISessionConstants.VERIFICATION_URL));
        }
    }

    private static void setField(Object target, String fieldName, Object value) throws Exception {
        Class<?> clazz = target.getClass();
        Field field = null;
        while (clazz != null && field == null) {
            try {
                field = clazz.getDeclaredField(fieldName);
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            }
        }
        if (field == null) throw new NoSuchFieldException(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }
}

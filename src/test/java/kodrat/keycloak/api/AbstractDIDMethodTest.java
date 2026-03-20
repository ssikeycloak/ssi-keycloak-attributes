package kodrat.keycloak.api;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.*;
import kodrat.keycloak.constant.SSISessionConstants;
import kodrat.keycloak.service.HttpClientService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.keycloak.sessions.AuthenticationSessionModel;

@DisplayName("AbstractDIDMethod Tests")
class AbstractDIDMethodTest {

    private TestDIDMethod didMethod;
    private AuthenticationSessionModel session;
    private Map<String, String> authNotes;

    @BeforeEach
    void setUp() {
        didMethod = new TestDIDMethod("https://agent.example.com", "test-token");
        session = mock(AuthenticationSessionModel.class);
        authNotes = new HashMap<>();
        when(session.getAuthNote(anyString())).thenAnswer(inv -> authNotes.get(inv.getArgument(0)));
        doAnswer(inv -> { authNotes.put(inv.getArgument(0), inv.getArgument(1)); return null; }).when(session).setAuthNote(anyString(), anyString());
        doAnswer(inv -> { authNotes.remove(inv.getArgument(0)); return null; }).when(session).removeAuthNote(anyString());
    }

    @Nested
    @DisplayName("Constructor initialization")
    class ConstructorTests {
        @Test
        @DisplayName("initializes endpoint, token, and httpClient")
        void initializesFields() {
            assertNotNull(didMethod.endpoint);
            assertNotNull(didMethod.bearerToken);
            assertNotNull(didMethod.httpClient);
            assertEquals("https://agent.example.com", didMethod.endpoint);
            assertEquals("test-token", didMethod.bearerToken);
        }
    }

    @Nested
    @DisplayName("generateQRCode delegation")
    class GenerateQRCodeTests {
        @Test
        @DisplayName("delegates to QRCodeService")
        void delegatesToQRCodeService() {
            String result = didMethod.generateQRCode("openid4vp://authorize");
            assertNotNull(result);
            assertTrue(result.startsWith("data:image/png;base64,"));
        }
    }

    @Nested
    @DisplayName("isConnectionEstablished branching")
    class IsConnectionEstablishedTests {
        @Test
        @DisplayName("returns true when connection not required")
        void returnsTrueWhenNotRequired() {
            didMethod.setConnectionRequired(false);
            boolean result = didMethod.isConnectionEstablished(session);
            assertTrue(result);
        }

        @Test
        @DisplayName("delegates to checkConnectionStatus when required")
        void delegatesWhenRequired() {
            didMethod.setConnectionRequired(true);
            didMethod.setConnectionStatusResult(true);
            boolean result = didMethod.isConnectionEstablished(session);
            assertTrue(result);
            assertTrue(didMethod.wasCheckConnectionStatusCalled());
        }

        @Test
        @DisplayName("returns false when connection required but not established")
        void returnsFalseWhenRequiredButNotEstablished() {
            didMethod.setConnectionRequired(true);
            didMethod.setConnectionStatusResult(false);
            boolean result = didMethod.isConnectionEstablished(session);
            assertFalse(result);
        }
    }

    @Nested
    @DisplayName("Auth note helpers")
    class AuthNoteHelperTests {
        @Test
        @DisplayName("getAuthNote retrieves from session")
        void getAuthNoteRetrieves() {
            authNotes.put("test-key", "test-value");
            String result = didMethod.getAuthNotePublic(session, "test-key");
            assertEquals("test-value", result);
        }

        @Test
        @DisplayName("setAuthNote stores to session")
        void setAuthNoteStores() {
            didMethod.setAuthNotePublic(session, "new-key", "new-value");
            assertEquals("new-value", authNotes.get("new-key"));
        }

        @Test
        @DisplayName("removeAuthNote removes from session")
        void removeAuthNoteRemoves() {
            authNotes.put("remove-key", "value");
            didMethod.removeAuthNotePublic(session, "remove-key");
            assertFalse(authNotes.containsKey("remove-key"));
        }
    }

    @Nested
    @DisplayName("Default hook values")
    class DefaultHookValuesTests {
        @Test
        @DisplayName("isConnectionRequired defaults to false")
        void connectionRequiredDefaultsFalse() {
            assertFalse(didMethod.isConnectionRequiredPublic());
        }

        @Test
        @DisplayName("isProofRequestRequired defaults to true")
        void proofRequestRequiredDefaultsTrue() {
            assertTrue(didMethod.isProofRequestRequiredPublic());
        }
    }

    private static class TestDIDMethod extends AbstractDIDMethod {
        private boolean connectionRequired = false;
        private boolean connectionStatusResult = false;
        private boolean checkConnectionStatusCalled = false;

        TestDIDMethod(String endpoint, String bearerToken) {
            super(endpoint, bearerToken);
        }

        void setConnectionRequired(boolean required) {
            this.connectionRequired = required;
        }

        void setConnectionStatusResult(boolean result) {
            this.connectionStatusResult = result;
        }

        boolean wasCheckConnectionStatusCalled() {
            return checkConnectionStatusCalled;
        }

        @Override
        protected boolean isConnectionRequired() {
            return connectionRequired;
        }

        @Override
        protected boolean checkConnectionStatus(AuthenticationSessionModel session) {
            checkConnectionStatusCalled = true;
            return connectionStatusResult;
        }

        public boolean isConnectionRequiredPublic() {
            return isConnectionRequired();
        }

        public boolean isProofRequestRequiredPublic() {
            return isProofRequestRequired();
        }

        public String getAuthNotePublic(AuthenticationSessionModel session, String key) {
            return getAuthNote(session, key);
        }

        public void setAuthNotePublic(AuthenticationSessionModel session, String key, String value) {
            setAuthNote(session, key, value);
        }

        public void removeAuthNotePublic(AuthenticationSessionModel session, String key) {
            removeAuthNote(session, key);
        }

        @Override
        public void handleAuthentication(org.keycloak.authentication.AuthenticationFlowContext context) {
        }

        @Override
        public SSIResult sendProofRequest(AuthenticationSessionModel session) {
            return SSIResult.success();
        }

        @Override
        public boolean hasReceivedPresentation(AuthenticationSessionModel session) {
            return false;
        }

        @Override
        public boolean isVerified(AuthenticationSessionModel session) {
            return false;
        }

        @Override
        protected String createInvitationUrl(AuthenticationSessionModel session) {
            return "test-invitation-url";
        }

        @Override
        public String createInvitation(AuthenticationSessionModel session) {
            return createInvitationUrl(session);
        }

        @Override
        protected boolean checkPresentationStatus(AuthenticationSessionModel session) {
            return false;
        }

        @Override
        public boolean verifyPresentation(AuthenticationSessionModel session) {
            return false;
        }

        @Override
        protected List<Map<String, Object>> buildEvidence(AuthenticationSessionModel session) {
            return new ArrayList<>();
        }
    }
}

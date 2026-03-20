package kodrat.keycloak.api;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;
import java.util.*;
import kodrat.keycloak.constant.SSISessionConstants;
import kodrat.keycloak.constant.SSIStatus;
import kodrat.keycloak.dto.did.ConnectionsResponse;
import kodrat.keycloak.dto.did.CreateInvitationResponse;
import kodrat.keycloak.dto.did.DIDSovConnection;
import kodrat.keycloak.dto.did.DIDSovProofResponse;
import kodrat.keycloak.service.HttpClientService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.authentication.AuthenticationFlowContext;

@DisplayName("DIDSov Characterization Tests - Captures current behavior before refactoring")
class DIDSovCharacterizationTest {

    private DIDSov didSov;
    private HttpClientService httpClientService;
    private AuthenticationSessionModel session;
    private Map<String, String> authNotes;

    @BeforeEach
    void setUp() throws Exception {
        didSov = new DIDSov("https://agent.example.com", "test-token");
        httpClientService = mock(HttpClientService.class);
        setField(didSov, "httpClient", httpClientService);

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
        @DisplayName("returns true when connection already exists")
        void returnsTrueWhenConnectionExists() {
            authNotes.put(SSISessionConstants.CONNECTION_ID, "conn-123");
            UserModel user = mock(UserModel.class);
            when(session.getAuthenticatedUser()).thenReturn(user);
            when(user.getFirstAttribute("ssiConnection")).thenReturn(null);

            boolean result = didSov.isConnectionEstablished(session);
            assertTrue(result);
        }

        @Test
        @DisplayName("returns false when no msgId in session")
        void returnsFalseWhenNoMsgId() {
            UserModel user = mock(UserModel.class);
            when(session.getAuthenticatedUser()).thenReturn(user);
            when(user.getFirstAttribute("ssiConnection")).thenReturn(null);

            boolean result = didSov.isConnectionEstablished(session);
            assertFalse(result);
        }
    }

    @Nested
    @DisplayName("hasReceivedPresentation behavior")
    class HasReceivedPresentationTests {
        @Test
        @DisplayName("returns false when no presExId")
        void returnsFalseWhenNoPresExId() {
            boolean result = didSov.hasReceivedPresentation(session);
            assertFalse(result);
        }

        @Test
        @DisplayName("returns true when presentation received")
        void returnsTrueWhenPresentationReceived() throws Exception {
            authNotes.put(SSISessionConstants.PRES_EX_ID, "pres-123");

            DIDSovProofResponse response = new DIDSovProofResponse();
            response.setState("presentation-received");
            when(httpClientService.get(anyString(), isNull(), eq(DIDSovProofResponse.class)))
                .thenReturn(response);

            boolean result = didSov.hasReceivedPresentation(session);
            assertTrue(result);
        }
    }

    @Nested
    @DisplayName("sendProofRequest behavior")
    class SendProofRequestTests {
        @Test
        @DisplayName("returns notReady when no connectionId")
        void returnsNotReadyWhenNoConnectionId() {
            SSIResult result = didSov.sendProofRequest(session);
            assertFalse(result.isDone());
        }

        @Test
        @DisplayName("returns success when presExId already exists")
        void returnsSuccessWhenPresExIdExists() {
            authNotes.put(SSISessionConstants.CONNECTION_ID, "conn-123");
            authNotes.put(SSISessionConstants.PRES_EX_ID, "pres-existing");

            SSIResult result = didSov.sendProofRequest(session);
            assertTrue(result.isDone());
        }
    }

    @Nested
    @DisplayName("verifyPresentation behavior")
    class VerifyPresentationTests {
        @Test
        @DisplayName("returns false when no presExId")
        void returnsFalseWhenNoPresExId() {
            boolean result = didSov.verifyPresentation(session);
            assertFalse(result);
        }

        @Test
        @DisplayName("returns true when verified and issuer_did matches")
        void returnsTrueWhenVerified() throws Exception {
            authNotes.put(SSISessionConstants.PRES_EX_ID, "pres-123");

            DIDSovProofResponse response = buildVerifiedResponse("did:sov:issuer123:2:Schema:1.0");
            when(httpClientService.post(anyString(), eq("{}"), isNull(), eq(DIDSovProofResponse.class)))
                .thenReturn(response);

            boolean result = didSov.verifyPresentation(session);
            assertTrue(result);
        }

        @Test
        @DisplayName("returns false and sets failure reason on issuer_did mismatch")
        void returnsFalseOnIssuerMismatch() throws Exception {
            authNotes.put(SSISessionConstants.PRES_EX_ID, "pres-123");
            authNotes.put("issuer_did", "did:sov:expectedIssuer");

            DIDSovProofResponse response = buildVerifiedResponse("did:sov:wrongIssuer:2:Schema:1.0");
            when(httpClientService.post(anyString(), eq("{}"), isNull(), eq(DIDSovProofResponse.class)))
                .thenReturn(response);

            boolean result = didSov.verifyPresentation(session);
            assertFalse(result);
            assertEquals("issuer_did_mismatch", authNotes.get(SSISessionConstants.SSI_FAILURE_REASON));
        }
    }

    @Nested
    @DisplayName("generateQRCode behavior")
    class GenerateQRCodeTests {
        @Test
        @DisplayName("generates QR code URL")
        void generatesQrCodeUrl() {
            String result = didSov.generateQRCode("didcomm://invite");
            assertNotNull(result);
            assertTrue(result.startsWith("data:image/png;base64,"));
        }
    }

    @Nested
    @DisplayName("Auth Notes behavior")
    class AuthNotesTests {
        @Test
        @DisplayName("sets CONNECTION_ID and SSI_STATUS on connection")
        void setsConnectionNotes() throws Exception {
            authNotes.put(SSISessionConstants.INVI_MSG_ID, "msg-123");
            UserModel user = mock(UserModel.class);
            when(session.getAuthenticatedUser()).thenReturn(user);
            when(user.getFirstAttribute("ssiConnection")).thenReturn(null);

            ConnectionsResponse connResponse = new ConnectionsResponse();
            DIDSovConnection conn = new DIDSovConnection();
            conn.setConnectionId("conn-active");
            conn.setInvitationMsgId("msg-123");
            conn.setState("active");
            conn.setRfc23State("completed");
            connResponse.setResults(List.of(conn));
            when(httpClientService.get(anyString(), isNull(), eq(ConnectionsResponse.class)))
                .thenReturn(connResponse);

            didSov.isConnectionEstablished(session);
            assertEquals("conn-active", authNotes.get(SSISessionConstants.CONNECTION_ID));
            assertEquals(SSIStatus.CONNECTED.getValue(), authNotes.get(SSISessionConstants.SSI_STATUS));
        }

        @Test
        @DisplayName("sets PRES_EX_ID and SSI_STATUS on proof request")
        void setsProofRequestNotes() throws Exception {
            authNotes.put(SSISessionConstants.CONNECTION_ID, "conn-123");
            authNotes.put(SSISessionConstants.PROOF_REQUEST_JSON, "{\"attributes\":[\"name\"],\"schema_id\":\"test\"}");

            when(httpClientService.post(anyString(), any(), isNull(), eq(Map.class)))
                .thenReturn(Map.of("pres_ex_id", "pres-new"));

            didSov.sendProofRequest(session);
            assertEquals("pres-new", authNotes.get(SSISessionConstants.PRES_EX_ID));
            assertEquals(SSIStatus.VERIFYING.getValue(), authNotes.get(SSISessionConstants.SSI_STATUS));
        }
    }

    @Nested
    @DisplayName("Connection reuse behavior")
    class ConnectionReuseTests {
        @Test
        @DisplayName("getExistingConnectionIdByAlias returns null when no user")
        void returnsNullWhenNoUser() {
            AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
            when(context.getUser()).thenReturn(null);
            String result = DIDSov.getExistingConnectionIdByAlias(context);
            assertNull(result);
        }

        @Test
        @DisplayName("getExistingConnectionIdByAlias returns connection when exists")
        void returnsConnectionWhenExists() throws Exception {
            AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
            UserModel user = mock(UserModel.class);
            when(context.getUser()).thenReturn(user);
            when(user.getFirstAttribute("ssiConnection"))
                .thenReturn("{\"connections\":{\"ssi\":{\"connection_id\":\"existing-conn\"}}}");

            String result = DIDSov.getExistingConnectionIdByAlias(context);
            assertEquals("existing-conn", result);
        }
    }

    private DIDSovProofResponse buildVerifiedResponse(String schemaId) {
        DIDSovProofResponse response = new DIDSovProofResponse();
        response.setState("done");
        response.setVerified("true");

        DIDSovProofResponse.Identifier identifier = new DIDSovProofResponse.Identifier();
        identifier.setSchemaId(schemaId);

        DIDSovProofResponse.RequestedProof requestedProof = new DIDSovProofResponse.RequestedProof();
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
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

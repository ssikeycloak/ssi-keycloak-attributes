package kodrat.keycloak.api;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import kodrat.keycloak.constant.SSISessionConstants;
import kodrat.keycloak.constant.SSIStatus;
import kodrat.keycloak.exception.SSIException;
import kodrat.keycloak.service.HttpClientService;
import org.junit.jupiter.api.Test;
import org.keycloak.sessions.AuthenticationSessionModel;

class DIDWebTest {

    @Test
    void hasReceivedPresentation_clearsStaleState_on404() throws Exception {
        DIDWeb didWeb = new DIDWeb("https://agent.example", "token");

        HttpClientService httpClientService = mock(HttpClientService.class);
        setField(didWeb, "httpClient", httpClientService);
        when(httpClientService.get(anyString(), isNull(), eq(String.class)))
                .thenThrow(new SSIException("HTTP error: 404 - not found"));

        AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
        Map<String, String> notes = new HashMap<>();
        notes.put(SSISessionConstants.SSI_STATE_ID, "stale-state-id");
        notes.put(SSISessionConstants.VERIFICATION_URL, "https://old-verify");
        notes.put(SSISessionConstants.INVITATION_URL, "https://old-invite");
        notes.put(SSISessionConstants.QR_CODE_URL, "data:image/png;base64,abc");

        when(session.getAuthNote(anyString())).thenAnswer(inv -> notes.get(inv.getArgument(0)));
        org.mockito.Mockito.doAnswer(inv -> {
            notes.remove(inv.getArgument(0));
            return null;
        }).when(session).removeAuthNote(anyString());
        org.mockito.Mockito.doAnswer(inv -> {
            notes.put(inv.getArgument(0), inv.getArgument(1));
            return null;
        }).when(session).setAuthNote(anyString(), anyString());

        boolean hasPresentation = didWeb.hasReceivedPresentation(session);

        assertFalse(hasPresentation);
        assertFalse(notes.containsKey(SSISessionConstants.SSI_STATE_ID));
        assertFalse(notes.containsKey(SSISessionConstants.VERIFICATION_URL));
        assertFalse(notes.containsKey(SSISessionConstants.INVITATION_URL));
        assertFalse(notes.containsKey(SSISessionConstants.QR_CODE_URL));
        assertTrue(SSIStatus.WAITING_PROOF.getValue().equals(notes.get(SSISessionConstants.SSI_STATUS)));
    }

    @Test
    void hasReceivedPresentation_returnsTrue_onTerminalFailureStatus() throws Exception {
        DIDWeb didWeb = new DIDWeb("https://agent.example", "token");

        HttpClientService httpClientService = mock(HttpClientService.class);
        setField(didWeb, "httpClient", httpClientService);
        when(httpClientService.get(anyString(), isNull(), eq(String.class)))
                .thenReturn("{\"status\":\"FAILED\"}");

        AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
        Map<String, String> notes = new HashMap<>();
        notes.put(SSISessionConstants.SSI_STATE_ID, "state-1");

        when(session.getAuthNote(anyString())).thenAnswer(inv -> notes.get(inv.getArgument(0)));
        org.mockito.Mockito.doAnswer(inv -> {
            notes.put(inv.getArgument(0), inv.getArgument(1));
            return null;
        }).when(session).setAuthNote(anyString(), anyString());

        boolean hasPresentation = didWeb.hasReceivedPresentation(session);

        assertTrue(hasPresentation);
        assertTrue(notes.containsKey("ssi_failure_reason"));
    }

    @Test
    void sendProofRequest_sessionBased_regeneratesWhenStateExistsWithoutVerificationUrl() throws Exception {
        DIDWeb didWeb = new DIDWeb("https://agent.example", "token");

        HttpClientService httpClientService = mock(HttpClientService.class);
        setField(didWeb, "httpClient", httpClientService);
        when(httpClientService.post(anyString(), any(), anyMap(), eq(String.class)))
                .thenReturn("openid4vp://authorize?request_uri=abc");

        AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
        Map<String, String> notes = new HashMap<>();
        notes.put(SSISessionConstants.SSI_ENDPOINT, "https://agent.example");
        notes.put(SSISessionConstants.SSI_STATE_ID, "stale-state");
        // intentionally no VERIFICATION_URL
        notes.put("requested_credential", "{\"credential_type\":\"VerifiableDiploma\"}");

        when(session.getAuthNote(anyString())).thenAnswer(inv -> notes.get(inv.getArgument(0)));
        org.mockito.Mockito.doAnswer(inv -> {
            notes.put(inv.getArgument(0), inv.getArgument(1));
            return null;
        }).when(session).setAuthNote(anyString(), anyString());
        org.mockito.Mockito.doAnswer(inv -> {
            notes.remove(inv.getArgument(0));
            return null;
        }).when(session).removeAuthNote(anyString());

        SSIResult result = didWeb.sendProofRequest(session);

        assertTrue(result.isDone());
        assertTrue(notes.containsKey(SSISessionConstants.SSI_STATE_ID));
        assertTrue(notes.containsKey(SSISessionConstants.VERIFICATION_URL));
        verify(httpClientService).post(anyString(), any(), anyMap(), eq(String.class));
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

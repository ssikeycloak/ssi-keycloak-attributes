package kodrat.keycloak.service.flow;

import kodrat.keycloak.api.DIDMethod;
import kodrat.keycloak.api.DIDMethodFactory;
import kodrat.keycloak.constant.SSISessionConstants;
import kodrat.keycloak.service.QRCodeService;
import kodrat.keycloak.util.LogSanitizer;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import java.util.HashMap;
import java.util.Map;

/**
 * Adapter implementation for REST API flow context.
 * Wraps KeycloakSession and session IDs to provide SSIFlowContextAdapter interface.
 */
public class RestApiFlowContextAdapter implements SSIFlowContextAdapter {

    private static final Logger LOGGER = Logger.getLogger(RestApiFlowContextAdapter.class);

    private final KeycloakSession session;
    private final String sessionId;
    private final String tabId;
    private AuthenticationSessionModel authSession;
    private DIDMethod didMethod;

    public RestApiFlowContextAdapter(KeycloakSession session, String sessionId, String tabId) {
        this.session = session;
        this.sessionId = sessionId;
        this.tabId = tabId;
        this.authSession = resolveAuthSession();
    }

    private AuthenticationSessionModel resolveAuthSession() {
        try {
            RealmModel realm = session.getContext().getRealm();
            RootAuthenticationSessionModel rootSession = session.authenticationSessions()
                    .getRootAuthenticationSession(realm, sessionId);

            if (rootSession == null) {
                LOGGER.warn("[RestApiFlowContextAdapter] Root session not found: " + LogSanitizer.maskIdentifier(sessionId));
                return null;
            }

            AuthenticationSessionModel authSession = rootSession.getAuthenticationSessions().get(tabId);
            if (authSession == null) {
                LOGGER.warn("[RestApiFlowContextAdapter] Auth session not found for tab: " + LogSanitizer.maskIdentifier(tabId));
                return null;
            }

            return authSession;
        } catch (Exception e) {
            LOGGER.error("[RestApiFlowContextAdapter] Failed to resolve auth session: " + LogSanitizer.redact(e.getMessage()));
            return null;
        }
    }

    @Override
    public AuthenticationSessionModel getAuthenticationSession() {
        if (authSession == null) {
            authSession = resolveAuthSession();
        }
        return authSession;
    }

    @Override
    public String getSessionId() {
        return sessionId;
    }

    @Override
    public String getTabId() {
        return tabId;
    }

    @Override
    public String getAuthNote(String key) {
        AuthenticationSessionModel session = getAuthenticationSession();
        return session != null ? session.getAuthNote(key) : null;
    }

    @Override
    public void setAuthNote(String key, String value) {
        AuthenticationSessionModel session = getAuthenticationSession();
        if (session != null) {
            session.setAuthNote(key, value);
        } else {
            LOGGER.warn("[RestApiFlowContextAdapter] Cannot set auth note, session is null");
        }
    }

    @Override
    public void removeAuthNote(String key) {
        AuthenticationSessionModel session = getAuthenticationSession();
        if (session != null) {
            session.removeAuthNote(key);
        }
    }

    @Override
    public void setUserSessionNote(String key, String value) {
        AuthenticationSessionModel session = getAuthenticationSession();
        if (session != null) {
            session.setUserSessionNote(key, value);
        } else {
            LOGGER.warn("[RestApiFlowContextAdapter] Cannot set user session note, session is null");
        }
    }

    @Override
    public String getConfigValue(String key) {
        // For REST API, config is stored in auth notes
        return getAuthNote(key);
    }

    @Override
    public DIDMethod getDIDMethod() {
        if (didMethod == null) {
            AuthenticationSessionModel authSession = getAuthenticationSession();
            if (authSession != null) {
                didMethod = DIDMethodFactory.getMethod(authSession);
                LOGGER.debug("[RestApiFlowContextAdapter] DIDMethod resolved: " + didMethod.getClass().getSimpleName());
            } else {
                LOGGER.error("[RestApiFlowContextAdapter] Cannot resolve DIDMethod, session is null");
                throw new IllegalStateException("Authentication session not available");
            }
        }
        return didMethod;
    }

    @Override
    public String generateQRCode(String data) {
        if (data == null || data.isEmpty()) {
            return "";
        }
        return QRCodeService.generateQRCodeUrl(data);
    }

    @Override
    public Map<String, String> getConfig() {
        Map<String, String> config = new HashMap<>();
        AuthenticationSessionModel session = getAuthenticationSession();

        if (session != null) {
            // Add session-based config
            String endpoint = session.getAuthNote(SSISessionConstants.SSI_ENDPOINT);
            String token = session.getAuthNote(SSISessionConstants.SSI_BEARER_TOKEN);
            String didMethod = session.getAuthNote(SSISessionConstants.DID_METHOD);
            String schemaId = session.getAuthNote("schema_id");
            String proofRequestJson = session.getAuthNote("proof_request_json");

            if (endpoint != null) config.put("ssi_endpoint", endpoint);
            if (token != null) config.put("ssi_bearer_token", token);
            if (didMethod != null) config.put("did_method", didMethod);
            if (schemaId != null) config.put("schema_id", schemaId);
            if (proofRequestJson != null) config.put("proof_request_json", proofRequestJson);
        }

        return config;
    }

    /**
     * Returns true if the session is valid and accessible.
     */
    public boolean isSessionValid() {
        return getAuthenticationSession() != null;
    }

    @Override
    public String toString() {
        return "RestApiFlowContextAdapter{" +
                "sessionId='" + LogSanitizer.maskIdentifier(sessionId) + '\'' +
                ", tabId='" + LogSanitizer.maskIdentifier(tabId) + '\'' +
                ", valid=" + isSessionValid() +
                '}';
    }
}

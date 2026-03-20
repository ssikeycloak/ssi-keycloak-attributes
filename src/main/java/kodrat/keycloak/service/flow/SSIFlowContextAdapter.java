package kodrat.keycloak.service.flow;

import kodrat.keycloak.api.DIDMethod;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Map;

/**
 * Adapter interface for SSI flow context.
 * Abstracts the differences between authenticator context and REST session context,
 * allowing the flow orchestrator to work with both entry points uniformly.
 */
public interface SSIFlowContextAdapter {

    /**
     * Returns the authentication session.
     */
    AuthenticationSessionModel getAuthenticationSession();

    /**
     * Returns the parent session ID.
     */
    String getSessionId();

    /**
     * Returns the tab ID.
     */
    String getTabId();

    /**
     * Gets an auth note from the session.
     */
    String getAuthNote(String key);

    /**
     * Sets an auth note in the session.
     */
    void setAuthNote(String key, String value);

    /**
     * Removes an auth note from the session.
     */
    void removeAuthNote(String key);

    /**
     * Sets a user session note.
     */
    void setUserSessionNote(String key, String value);

    /**
     * Gets configuration value.
     */
    String getConfigValue(String key);

    /**
     * Returns the DID method for this context.
     */
    DIDMethod getDIDMethod();

    /**
     * Generates a QR code for the given data.
     */
    String generateQRCode(String data);

    /**
     * Returns all configuration as a map.
     */
    Map<String, String> getConfig();
}

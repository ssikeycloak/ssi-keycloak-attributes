package kodrat.keycloak.service.flow;

import kodrat.keycloak.api.DIDMethod;
import kodrat.keycloak.api.DIDMethodFactory;
import kodrat.keycloak.config.ConfigUtils;
import kodrat.keycloak.constant.SSISessionConstants;
import kodrat.keycloak.service.QRCodeService;
import kodrat.keycloak.util.LogSanitizer;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.HashMap;
import java.util.Map;

/**
 * Adapter implementation for authenticator flow context.
 * Wraps AuthenticationFlowContext to provide SSIFlowContextAdapter interface.
 */
public class AuthenticatorFlowContextAdapter implements SSIFlowContextAdapter {

    private static final Logger LOGGER = Logger.getLogger(AuthenticatorFlowContextAdapter.class);

    private final AuthenticationFlowContext context;
    private DIDMethod didMethod;

    public AuthenticatorFlowContextAdapter(AuthenticationFlowContext context) {
        this.context = context;
    }

    @Override
    public AuthenticationSessionModel getAuthenticationSession() {
        return context.getAuthenticationSession();
    }

    @Override
    public String getSessionId() {
        return context.getAuthenticationSession().getParentSession().getId();
    }

    @Override
    public String getTabId() {
        return context.getAuthenticationSession().getTabId();
    }

    @Override
    public String getAuthNote(String key) {
        return context.getAuthenticationSession().getAuthNote(key);
    }

    @Override
    public void setAuthNote(String key, String value) {
        context.getAuthenticationSession().setAuthNote(key, value);
    }

    @Override
    public void removeAuthNote(String key) {
        context.getAuthenticationSession().removeAuthNote(key);
    }

    @Override
    public void setUserSessionNote(String key, String value) {
        context.getAuthenticationSession().setUserSessionNote(key, value);
    }

    @Override
    public String getConfigValue(String key) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (config != null && config.getConfig() != null) {
            return config.getConfig().get(key);
        }
        return null;
    }

    @Override
    public DIDMethod getDIDMethod() {
        if (didMethod == null) {
            didMethod = DIDMethodFactory.getMethod(context);
            LOGGER.debug("[AuthenticatorFlowContextAdapter] DIDMethod resolved: " + didMethod.getClass().getSimpleName());
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
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        if (configModel != null && configModel.getConfig() != null) {
            config.putAll(configModel.getConfig());
        }

        // Add session-based config
        AuthenticationSessionModel session = context.getAuthenticationSession();
        String endpoint = session.getAuthNote(SSISessionConstants.SSI_ENDPOINT);
        String token = session.getAuthNote(SSISessionConstants.SSI_BEARER_TOKEN);
        String didMethod = session.getAuthNote(SSISessionConstants.DID_METHOD);

        if (endpoint != null) config.put("ssi_endpoint", endpoint);
        if (token != null) config.put("ssi_bearer_token", token);
        if (didMethod != null) config.put("did_method", didMethod);

        return config;
    }

    /**
     * Returns the underlying AuthenticationFlowContext.
     */
    public AuthenticationFlowContext getContext() {
        return context;
    }

    @Override
    public String toString() {
        return "AuthenticatorFlowContextAdapter{" +
                "sessionId='" + LogSanitizer.maskIdentifier(getSessionId()) + '\'' +
                ", tabId='" + LogSanitizer.maskIdentifier(getTabId()) + '\'' +
                '}';
    }
}

package kodrat.keycloak.api;

import jakarta.ws.rs.core.Response;
import java.util.*;
import kodrat.keycloak.config.AttributeUtil;
import kodrat.keycloak.config.ConfigUtils;
import kodrat.keycloak.constant.SSISessionConstants;
import kodrat.keycloak.constant.SSIStatus;
import kodrat.keycloak.service.EvidenceBuilder;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Template implementation for creating new DID method implementations.
 *
 * <p>This class serves as a <strong>blueprint</strong> for implementing custom DID methods
 * that integrate with the Keycloak SSI authenticator. Copy and customize this file to
 * add support for new DID methods (e.g., did:ion, did:peer, did:key).
 *
 * <h2>Creating a New DID Method</h2>
 * <p>Follow these steps to implement a new DID method:
 * <ol>
 *   <li>Copy this file and rename to your method (e.g., {@code DIDIon.java})</li>
 *   <li>Replace all occurrences of "Template" with your method name</li>
 *   <li>Implement the abstract hook methods from {@link AbstractDIDMethod}</li>
 *   <li>Override default hooks if needed (e.g., {@link #isConnectionRequired()})</li>
 *   <li>Register in {@link DIDMethodFactory#getMethodFromRaw(String, String, String)}</li>
 *   <li>Create corresponding test class</li>
 * </ol>
 *
 * <h2>Hook Methods to Implement</h2>
 * <p>The following methods <strong>must</strong> be implemented:
 * <table border="1">
 *   <caption>Required Hook Methods</caption>
 *   <tr><th>Method</th><th>Purpose</th></tr>
 *   <tr><td>{@link #createInvitationUrl(AuthenticationSessionModel)}</td><td>Generate invitation/authorization URL</td></tr>
 *   <tr><td>{@link #checkPresentationStatus(AuthenticationSessionModel)}</td><td>Check if wallet submitted presentation</td></tr>
 *   <tr><td>{@link #buildEvidence(AuthenticationSessionModel)}</td><td>Build audit evidence</td></tr>
 * </table>
 *
 * <h2>Optional Hook Methods</h2>
 * <p>The following methods have default implementations that can be overridden:
 * <table border="1">
 *   <caption>Optional Hook Methods</caption>
 *   <tr><th>Method</th><th>Default</th><th>Override When</th></tr>
 *   <tr><td>{@link #isConnectionRequired()}</td><td>false</td><td>Method requires persistent connection</td></tr>
 *   <tr><td>{@link #checkConnectionStatus(AuthenticationSessionModel)}</td><td>No-op</td><td>Need to poll connection state</td></tr>
 * </table>
 *
 * <h2>Implementation Notes</h2>
 * <ul>
 *   <li>Use {@link #getAuthNote(AuthenticationSessionModel, String)} for session reads</li>
 *   <li>Use {@link #setAuthNote(AuthenticationSessionModel, String, String)} for session writes</li>
 *   <li>Use {@link #httpClient} for HTTP calls to the SSI agent</li>
 *   <li>Log with prefix {@code [DIDYourMethod]} for easy filtering</li>
 * </ul>
 *
 * <h2>Thread Safety</h2>
 * <p>This class is <strong>not thread-safe</strong>. Each authentication flow should
 * create its own instance via {@link DIDMethodFactory}.
 *
 * @see AbstractDIDMethod
 * @see DIDMethod
 * @see DIDMethodFactory
 * @see <a href="https://www.w3.org/TR/did-core/">W3C DID Core Specification</a>
 * @since 1.0.0
 * @author Kodrat Development Team
 */
public class DIDTemplate extends AbstractDIDMethod {
    
    private static final java.util.logging.Logger LOGGER = java.util.logging.Logger.getLogger(DIDTemplate.class.getName());

    /**
     * Constructs a new DIDTemplate instance with the specified SSI agent endpoint.
     *
     * <p>Replace "Template" with your method name in the actual implementation.
     *
     * @param endpoint the base URL of the SSI agent
     * @param bearerToken the bearer token for authenticating with the SSI agent,
     *                    may be {@code null} if authentication is not required
     */
    public DIDTemplate(String endpoint, String bearerToken) {
        super(endpoint, bearerToken);
        LOGGER.info("[DIDTemplate] Initialized with endpoint: " + endpoint);
    }

    /**
     * {@inheritDoc}
     *
     * <p><strong>Template Implementation:</strong> Displays QR code and initiates
     * proof request if not already created.
     *
     * <p>Customize this method to:
     * <ul>
     *   <li>Add method-specific UI attributes</li>
     *   <li>Handle connection reuse scenarios</li>
     *   <li>Customize error handling</li>
     * </ul>
     */
    @Override
    public void handleAuthentication(AuthenticationFlowContext context) {
        LOGGER.info("[DIDTemplate] Starting SSI authentication flow");
        try {
            AuthenticationSessionModel session = context.getAuthenticationSession();
            String invitationUrl = session.getAuthNote(SSISessionConstants.INVITATION_URL);

            if (invitationUrl == null) {
                LOGGER.info("[DIDTemplate] Creating new SSI connection invitation");
                SSIResult result = sendProofRequest(session);
                if (!result.isDone()) {
                    LOGGER.warning("[DIDTemplate] Failed to initiate proof request");
                    context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, context
                            .form().setError("ssiAuthError", new Object[] { "Failed to create proof request." })
                            .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
                    return;
                }
                invitationUrl = session.getAuthNote(SSISessionConstants.INVITATION_URL);
            }

            setAuthNote(session, SSISessionConstants.SSI_ENDPOINT, this.endpoint);
            setAuthNote(session, SSISessionConstants.SSI_BEARER_TOKEN, this.bearerToken);

            String qrCodeUrl = generateQRCode(invitationUrl);
            String sessionId = session.getParentSession().getId();
            String tabId = session.getTabId();

            LOGGER.info("[DIDTemplate] Displaying QR code for session: " + sessionId);
            context.challenge(context
                    .form()
                    .setAttribute("qrCode", qrCodeUrl)
                    .setAttribute("sessionId", sessionId)
                    .setAttribute("tabId", tabId)
                    .setAttribute("requestedAttributes", ConfigUtils.getRequestedAttributes(context))
                    .setAttribute("schemaId", ConfigUtils.getSchemaId(context))
                    .setAttribute("schemaName", ConfigUtils.getSchemaName(context))
                    .setAttribute("issuerName", ConfigUtils.getIssuerName(context))
                    .setAttribute("issuerDid", ConfigUtils.getIssuerDid(context))
                    .setAttribute("uiConsentTitle", ConfigUtils.getUiConsentTitle(context))
                    .setAttribute("uiConsentDescription", ConfigUtils.getUiConsentDescription(context))
                    .setAttribute("uiRequiredDataTitle", ConfigUtils.getUiRequiredDataTitle(context))
                    .setAttribute("uiPrivacyTitle", ConfigUtils.getUiPrivacyTitle(context))
                    .setAttribute("uiPrivacyDescription", ConfigUtils.getUiPrivacyDescription(context))
                    .createForm("login-identity-consent.ftl"));
        } catch (Exception e) {
            LOGGER.severe("[DIDTemplate] Exception during authentication: " + e.getMessage());
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, context
                    .form().setError("ssiAuthError", new Object[] { e.getMessage() })
                    .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p><strong>Template Implementation:</strong> Creates invitation URL and stores
     * it in session. Override this method to implement method-specific proof request logic.
     */
    @Override
    public SSIResult sendProofRequest(AuthenticationSessionModel session) {
        LOGGER.info("[DIDTemplate] Initiating proof request");
        try {
            String invitationUrl = createInvitationUrl(session);

            if (invitationUrl == null) {
                LOGGER.severe("[DIDTemplate] Failed to generate invitation URL");
                return new SSIResult(false, null, null, null, "Failed to create invitation URL");
            }

            setAuthNote(session, SSISessionConstants.SSI_STATUS, SSIStatus.WAITING.getValue());
            setAuthNote(session, SSISessionConstants.INVITATION_URL, invitationUrl);

            Map<String, Object> extra = new HashMap<>();
            extra.put("step", "invitation-created");

            LOGGER.info("[DIDTemplate] Proof request initiated successfully");
            return new SSIResult(true, null, null, extra, "Invitation URL created");
        } catch (Exception e) {
            LOGGER.severe("[DIDTemplate] Exception during proof request: " + e.getMessage());
            return new SSIResult(false, null, null, null, "Error: " + e.getMessage());
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p><strong>Template Implementation:</strong> Delegates to {@link #checkPresentationStatus(AuthenticationSessionModel)}.
     */
    @Override
    public boolean hasReceivedPresentation(AuthenticationSessionModel session) {
        LOGGER.fine("[DIDTemplate] Checking if presentation has been received");
        return checkPresentationStatus(session);
    }

    /**
     * {@inheritDoc}
     *
     * <p><strong>Template Implementation:</strong> Checks for presence of presExId in session.
     * Override to implement actual verification status checking.
     */
    @Override
    public boolean isVerified(AuthenticationSessionModel session) {
        LOGGER.fine("[DIDTemplate] Checking verification status");
        String presExId = getAuthNote(session, SSISessionConstants.PRES_EX_ID);
        return presExId != null && !presExId.isBlank();
    }

    /**
     * {@inheritDoc}
     *
     * <p><strong>Template Implementation:</strong> Placeholder that returns false.
     * <strong>Must override</strong> with actual verification logic:
     * <ol>
     *   <li>Call SSI agent to verify the presentation</li>
     *   <li>Extract revealed attributes using {@code CredentialAttributeExtractor}</li>
     *   <li>Build evidence using {@link EvidenceBuilder}</li>
     *   <li>Save attributes to user session using {@code AttributeUtil}</li>
     * </ol>
     */
    @Override
    public boolean verifyPresentation(AuthenticationSessionModel session) {
        LOGGER.info("[DIDTemplate] Verifying presentation credentials");
        String presExId = getAuthNote(session, SSISessionConstants.PRES_EX_ID);
        if (presExId == null) {
            LOGGER.warning("[DIDTemplate] Presentation exchange ID not found in session");
            return false;
        }

        LOGGER.warning("[DIDTemplate] verifyPresentation not fully implemented - override in subclass");
        return false;
    }

    /**
     * {@inheritDoc}
     *
     * <p><strong>Template Implementation:</strong> Returns a placeholder URL.
     * <strong>Must override</strong> with actual invitation URL generation logic
     * that calls the SSI agent's API.
     *
     * @return the invitation or authorization URL for wallet connection
     */
    @Override
    protected String createInvitationUrl(AuthenticationSessionModel session) {
        LOGGER.info("[DIDTemplate] Creating invitation URL via SSI agent");
        return endpoint + "/create-verification-session";
    }

    /**
     * {@inheritDoc}
     *
     * <p><strong>Template Implementation:</strong> Checks for presExId in session.
     * <strong>Must override</strong> with actual status check logic that queries
     * the SSI agent's API.
     *
     * @return {@code true} if presentation has been received, {@code false} otherwise
     */
    @Override
    protected boolean checkPresentationStatus(AuthenticationSessionModel session) {
        LOGGER.fine("[DIDTemplate] Checking presentation status");
        String presExId = getAuthNote(session, SSISessionConstants.PRES_EX_ID);
        return presExId != null && !presExId.isBlank();
    }

    /**
     * {@inheritDoc}
     *
     * <p><strong>Template Implementation:</strong> Returns an empty list.
     * <strong>Must override</strong> with actual evidence building logic that
     * creates an audit trail from the verified credentials.
     *
     * @return a list of evidence maps for the audit trail
     */
    @Override
    protected List<Map<String, Object>> buildEvidence(AuthenticationSessionModel session) {
        return new ArrayList<>();
    }

    /**
     * Creates a new invitation/verification URL for the wallet.
     *
     * <p>This method creates a new invitation when the existing one has been
     * cleared (e.g., after a retry). It delegates to {@link #createInvitationUrl}.
     *
     * <p><strong>Template Implementation:</strong> Delegates to createInvitationUrl.
     * Subclasses should ensure createInvitationUrl properly stores state in session.
     *
     * @param session the authentication session for storing invitation state
     * @return the invitation URL, or {@code null} if creation fails
     */
    @Override
    public String createInvitation(AuthenticationSessionModel session) {
        LOGGER.info("[DIDTemplate] Creating new invitation via REST API");
        return createInvitationUrl(session);
    }
}

package kodrat.keycloak.authenticator;

import kodrat.keycloak.api.DIDMethod;
import kodrat.keycloak.api.DIDMethodFactory;
import kodrat.keycloak.api.SSIResult;
import kodrat.keycloak.config.ConfigUtils;
import kodrat.keycloak.config.AttributeUtil;
import kodrat.keycloak.constant.SSISessionConstants;
import kodrat.keycloak.constant.SSIStatus;
import kodrat.keycloak.util.LogSanitizer;
import kodrat.keycloak.util.SSIErrorPageRenderer;
import kodrat.keycloak.service.SessionLockService;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Map;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import kodrat.keycloak.service.SSIStateResetService;

/**
 * Keycloak authenticator implementation for Self-Sovereign Identity (SSI) authentication.
 *
 * <p>This authenticator integrates verifiable credential verification into the Keycloak
 * authentication flow, enabling passwordless authentication using digital wallets and
 * decentralized identifiers (DIDs).
 *
 * <h2>Authentication Flow</h2>
 * <p>The authenticator implements a 4-step verification flow:
 * <ol>
 *   <li><strong>Connection Establishment:</strong> User scans QR code to establish
 *       DIDComm connection (connection-based methods only)</li>
 *   <li><strong>Proof Request:</strong> Verifier sends credential request to wallet</li>
 *   <li><strong>Presentation Reception:</strong> Wallet submits verifiable presentation</li>
 *   <li><strong>Verification:</strong> Verifier validates presentation and extracts attributes</li>
 * </ol>
 *
 * <h2>Supported DID Methods</h2>
 * <p>The authenticator supports multiple DID methods via the factory pattern:
 * <ul>
 *   <li><strong>did:sov:</strong> Sovrin/Hyperledger Indy with DIDComm (connection-based)</li>
 *   <li><strong>did:web:</strong> OpenID4VC credential verification (connectionless)</li>
 * </ul>
 *
 * <h2>Configuration</h2>
 * <p>Configure via Keycloak Admin Console → Authentication → SSI Auth:
 * <table border="1">
 *   <caption>Configuration Parameters</caption>
 *   <tr><th>Parameter</th><th>Description</th><th>Required</th></tr>
 *   <tr><td>{@code did_method}</td><td>DID method to use ("sov" or "web")</td><td>Yes</td></tr>
 *   <tr><td>{@code ssi_endpoint}</td><td>URL of the SSI agent (ACA-Py)</td><td>Yes</td></tr>
 *   <tr><td>{@code ssi_bearer_token}</td><td>Authentication token for agent</td><td>No</td></tr>
 *   <tr><td>{@code proof_request_json}</td><td>JSON specifying requested attributes</td><td>For did:sov</td></tr>
 *   <tr><td>{@code requested_credential}</td><td>Credential requirements JSON</td><td>For did:web</td></tr>
 * </table>
 *
 * <h2>Session Locking</h2>
 * <p>The authenticator implements session locking to prevent race conditions from:
 * <ul>
 *   <li>Page refreshes during authentication</li>
 *   <li>Multiple browser tabs</li>
 *   <li>Concurrent polling requests</li>
 * </ul>
 *
 * <h2>State Management</h2>
 * <p>Authentication state is managed through auth notes:
 * <ul>
 *   <li>{@code ssi_status} - Current flow status (waiting-connection, verifying, done, etc.)</li>
 *   <li>{@code ssi_flow_id} - Unique identifier to detect duplicate flows</li>
 *   <li>{@code connection_id} - Established DIDComm connection</li>
 *   <li>{@code pres_ex_id} - Presentation exchange ID</li>
 * </ul>
 *
 * <h2>User Experience</h2>
 * <p>The authenticator provides:
 * <ul>
 *   <li>QR code display for wallet scanning</li>
 *   <li>Real-time status polling via frontend JavaScript</li>
 *   <li>Retry capability on verification failure</li>
 *   <li>Skip option for non-mandatory verification</li>
 * </ul>
 *
 * <h2>Thread Safety</h2>
 * <p>This authenticator is stateless and thread-safe. State is maintained in
 * Keycloak's authentication session, not in instance fields.
 *
 * @see DIDMethod
 * @see DIDMethodFactory
 * @see SSIStateResetService
 * @see SessionLockService
 * @since 1.0.0
 * @author Kodrat Development Team
 */
public class SSIAuth implements Authenticator {

    private static final Logger LOGGER = Logger.getLogger(SSIAuth.class.getName());

    /**
     * Entry point for the SSI authentication flow.
     *
     * <p>This method is called by Keycloak when the authentication flow reaches
     * this authenticator. It initializes the session state and delegates to the
     * appropriate DID method for QR code display.
     *
     * <p>The method performs the following:
     * <ul>
     *   <li>Checks for duplicate flow initiation (prevents refresh issues)</li>
     *   <li>Resets any transient state from previous attempts</li>
     *   <li>Creates the DID method instance via factory</li>
     *   <li>Delegates to DID method for authentication UI rendering</li>
     * </ul>
     *
     * @param context the Keycloak authentication flow context providing access to
     *                session, realm, user, and form rendering capabilities
     */
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        try {
            AuthenticationSessionModel session = context.getAuthenticationSession();

            if (session.getAuthNote(SSISessionConstants.SSI_FLOW_ID) != null) {
                LOGGER.warning("[SSIAuth] SSI flow already started for tab: " + LogSanitizer.maskIdentifier(session.getTabId()));
                SSIErrorPageRenderer.render(context,
                        "SSI verification already active",
                        "An SSI verification flow is already running for this session. You can continue login without SSI verification.");
                return;
            }

            SSIStateResetService.resetTransientFlowState(session);
            LOGGER.info("[SSIAuth] Starting SSI authentication flow");

            DIDMethod method = DIDMethodFactory.getMethod(context);
            method.handleAuthentication(context);
        } catch (Exception e) {
            LOGGER.severe("[SSIAuth] Error in authenticate(): " + e.getClass().getSimpleName() + " - " + LogSanitizer.redact(e.getMessage()));
            SSIErrorPageRenderer.render(context,
                    "SSI verification unavailable",
                    "The SSI service failed while starting verification. You can continue login without SSI verification.");
        }
    }

    /**
     * Handles form submissions and polling requests from the frontend.
     *
     * <p>This method is called when the user submits the authentication form or
     * when the frontend polls for status updates. It executes with a session lock
     * to prevent concurrent modification issues.
     *
     * <p>The method supports:
     * <ul>
     *   <li><strong>Retry:</strong> User clicked retry button, reset and restart</li>
     *   <li><strong>Skip:</strong> User chose to skip SSI verification</li>
     *   <li><strong>Polling:</strong> Progress the 4-step verification flow</li>
     * </ul>
     *
     * @param context the Keycloak authentication flow context
     */
    @Override
    public void action(AuthenticationFlowContext context) {
        AuthenticationSessionModel session = context.getAuthenticationSession();
        SessionLockService lockService = SessionLockService.getInstance();
        
        try {
            lockService.withSessionLock(session, () -> executeAction(context));
        } catch (IllegalStateException e) {
            if (e.getMessage() != null && e.getMessage().contains("Session is currently being processed")) {
                LOGGER.warning("[SSIAuth] Concurrent access detected - session already being processed");
                SSIErrorPageRenderer.render(context,
                        "SSI verification busy",
                        "The SSI verification flow is still being processed. You can continue login without SSI verification.");
            } else {
                throw e;
            }
        }
    }
    
    /**
     * Internal action execution with session lock already acquired.
     *
     * <p>Implements the 4-step SSI verification flow:
     * <ol>
     *   <li>Check if connection is established (for connection-based methods)</li>
     *   <li>Send proof request if not already sent</li>
     *   <li>Wait for presentation from wallet</li>
     *   <li>Verify presentation and extract attributes</li>
     * </ol>
     *
     * @param context the authentication flow context
     */
    private void executeAction(AuthenticationFlowContext context) {
        try {
            AuthenticationSessionModel session = context.getAuthenticationSession();

            String showSsiError = context.getHttpRequest().getDecodedFormParameters().getFirst("show_ssi_error");
            if ("true".equals(showSsiError)) {
                String errorTitle = context.getHttpRequest().getDecodedFormParameters().getFirst("ssi_error_title");
                String errorMessage = context.getHttpRequest().getDecodedFormParameters().getFirst("ssi_error_message");
                SSIErrorPageRenderer.render(context, errorTitle, errorMessage);
                return;
            }
            
            String retrySsi = context.getHttpRequest().getDecodedFormParameters().getFirst("retry_ssi");
            if ("true".equals(retrySsi)) {
                LOGGER.info("[SSIAuth] User requested SSI retry via form - resetting and restarting flow");
                SSIStateResetService.resetForRetry(session);
                
                DIDMethod method = DIDMethodFactory.getMethod(context);
                method.handleAuthentication(context);
                return;
            }
            
            String skipSsi = context.getHttpRequest().getDecodedFormParameters().getFirst("skip_ssi");
            if ("true".equals(skipSsi)) {
                LOGGER.info("[SSIAuth] User chose to skip SSI verification - continuing with empty claims");
                session.removeAuthNote(SSISessionConstants.SSI_FLOW_ID);
                session.setUserSessionNote("ssi_skipped", "true");
                session.setUserSessionNote("ssi_verified", "false");
                context.success();
                return;
            }
            
            DIDMethod method = DIDMethodFactory.getMethod(context);

            String ssiStatus = session.getAuthNote(SSISessionConstants.SSI_STATUS);
            if (ssiStatus == null) ssiStatus = "";
            LOGGER.info("[SSIAuth] Current status: " + ssiStatus);

            if (SSIStatus.DONE.getValue().equals(ssiStatus)) {
                LOGGER.info("[SSIAuth] Flow already marked done - finalizing authentication success");
                String verifiedClaims = session.getAuthNote(SSISessionConstants.VERIFIED_CLAIMS);
                if (verifiedClaims == null || verifiedClaims.isBlank()) {
                    LOGGER.warning("[SSIAuth] DONE status detected but `verified_claims` is missing. Rehydrating claims before success.");
                    boolean rehydrated = method.verifyPresentation(session);
                    if (!rehydrated) {
                        LOGGER.warning("[SSIAuth] Rehydration attempt did not restore `verified_claims`.");
                    }
                }
                session.removeAuthNote(SSISessionConstants.SSI_FLOW_ID);
                context.success();
                return;
            }

            String invitationUrl = session.getAuthNote(SSISessionConstants.INVITATION_URL);
            if (invitationUrl == null) invitationUrl = "";

            String qrCodeUrl = method.generateQRCode(invitationUrl);
            String sessionId = session.getParentSession().getId();
            String tabId = session.getTabId();
            
            LOGGER.info("[SSIAuth] Session started: " + LogSanitizer.maskIdentifier(sessionId) + ", Tab: " + LogSanitizer.maskIdentifier(tabId));

            if (SSIStatus.INVALID.getValue().equals(ssiStatus) || SSIStatus.FAILED.getValue().equals(ssiStatus)) {
                LOGGER.warning("[SSIAuth] Flow in terminal failure state: " + ssiStatus);
                session.removeAuthNote(SSISessionConstants.SSI_FLOW_ID);
                SSIErrorPageRenderer.render(context,
                        "SSI verification failed",
                        "The SSI verification ended in an error state. You can continue login without SSI verification.");
                return;
            }

            if (!method.isConnectionEstablished(session)) {
                LOGGER.info("[SSIAuth] Step 1: Waiting for SSI connection...");
                session.setAuthNote(SSISessionConstants.SSI_STATUS, SSIStatus.WAITING_CONNECTION.getValue());
                renderPage(context, qrCodeUrl, sessionId, tabId, "login-identity-consent.ftl");
                return;
            }

            boolean proofAlreadySent = SSIStatus.PROOF_REQUESTED.getValue().equals(ssiStatus)
                    || SSIStatus.WAITING_PRESENTATION.getValue().equals(ssiStatus)
                    || SSIStatus.DONE.getValue().equals(ssiStatus);

            if (!proofAlreadySent) {
                SSIResult result = method.sendProofRequest(session);
                if (!result.isDone()) {
                    LOGGER.info("[SSIAuth] Step 2: Proof request pending...");
                    session.setAuthNote(SSISessionConstants.SSI_STATUS, SSIStatus.WAITING_PROOF.getValue());
                    renderPage(context, qrCodeUrl, sessionId, tabId, "login-identity-consent.ftl");
                    return;
                }
                session.setAuthNote(SSISessionConstants.SSI_STATUS, SSIStatus.PROOF_REQUESTED.getValue());
                LOGGER.info("[SSIAuth] Step 2: Proof request sent");
            }

            if (!method.hasReceivedPresentation(session)) {
                LOGGER.info("[SSIAuth] Step 3: Waiting for credential presentation...");
                session.setAuthNote(SSISessionConstants.SSI_STATUS, SSIStatus.WAITING_PRESENTATION.getValue());
                renderPage(context, qrCodeUrl, sessionId, tabId, "login-auth-verify.ftl");
                return;
            }

            boolean verified = method.verifyPresentation(session);
            if (verified) {
                LOGGER.info("[SSIAuth] Step 4: Verification successful");
                session.setAuthNote(SSISessionConstants.SSI_STATUS, SSIStatus.DONE.getValue());

                session.removeAuthNote(SSISessionConstants.INVI_MSG_ID);
                session.removeAuthNote(SSISessionConstants.PRES_EX_ID);
                session.removeAuthNote(SSISessionConstants.SSI_FLOW_ID);

                String verifiedClaims = session.getAuthNote(SSISessionConstants.VERIFIED_CLAIMS);
                if (verifiedClaims != null && !verifiedClaims.isBlank()) {
                    String clientId = context.getAuthenticationSession().getClient() != null
                            ? context.getAuthenticationSession().getClient().getClientId()
                            : "unknown";
                    LOGGER.info("[SSIAuth] SSI claims available in session note `verified_claims` for client=" +
                            LogSanitizer.maskIdentifier(clientId) +
                            ". Ensure a User Session Note mapper is configured to include this claim in tokens.");
                }

                context.success();
            } else {
                LOGGER.warning("[SSIAuth] Step 4: Verification failed");
                SSIErrorPageRenderer.render(context,
                        "SSI verification failed",
                        "Credential verification did not succeed. You can continue login without SSI verification.");
            }

        } catch (Exception e) {
            LOGGER.severe("[SSIAuth] Exception in action(): " + e.getClass().getSimpleName() + " - " + LogSanitizer.redact(e.getMessage()));
            SSIErrorPageRenderer.render(context,
                    "SSI verification unavailable",
                    "The SSI verification flow hit an unexpected error. You can continue login without SSI verification.");
        }
    }

    /**
     * Renders the SSI authentication page with QR code and configuration attributes.
     *
     * <p>This method populates the FreeMarker template with all required attributes
     * for rendering the consent/verification page, including:
     * <ul>
     *   <li>QR code URL for wallet scanning</li>
     *   <li>Session identifiers for frontend polling</li>
     *   <li>Configuration from authenticator config</li>
     *   <li>Method and protocol display names</li>
     * </ul>
     *
     * @param context the authentication flow context
     * @param qrCode the QR code URL to display
     * @param sessionId the root session ID
     * @param tabId the tab/execution ID
     * @param ftl the FreeMarker template name to render
     */
    private void renderPage(AuthenticationFlowContext context, String qrCode, String sessionId,String tabId, String ftl) {
        java.util.List<String> attributes = ConfigUtils.getRequestedAttributes(context);
        String schemaId = ConfigUtils.getSchemaId(context);
        String schemaName = ConfigUtils.getSchemaName(context);
        String issuerName = ConfigUtils.getIssuerName(context);
        String issuerDid = ConfigUtils.getIssuerDid(context);
        String didMethod = ConfigUtils.getDIDMethod(context);
        String uiConsentTitle = ConfigUtils.getUiConsentTitle(context);
        String uiConsentDescription = ConfigUtils.getUiConsentDescription(context);
        String uiRequiredDataTitle = ConfigUtils.getUiRequiredDataTitle(context);
        String uiPrivacyTitle = ConfigUtils.getUiPrivacyTitle(context);
        String uiPrivacyDescription = ConfigUtils.getUiPrivacyDescription(context);

        String methodDisplay = "Sovrin (did:sov)";
        String protocolDisplay = "DIDComm/ACA-Py";

        if ("web".equalsIgnoreCase(didMethod)) {
            methodDisplay = "Web (did:web)";
            protocolDisplay = "OpenID4VC";
        } else if ("sov".equalsIgnoreCase(didMethod)) {
            methodDisplay = "Sovrin (did:sov)";
            protocolDisplay = "DIDComm/ACA-Py";
        }

        context.challenge(
                context.form()
                        .setAttribute("qrCode", qrCode)
                        .setAttribute("sessionId", sessionId)
                        .setAttribute("tabId", tabId)
                        .setAttribute("requestedAttributes", attributes)
                        .setAttribute("schemaId", schemaId)
                        .setAttribute("schemaName", schemaName)
                        .setAttribute("issuerName", issuerName)
                        .setAttribute("issuerDid", issuerDid)
                        .setAttribute("didMethod", didMethod)
                        .setAttribute("methodDisplay", methodDisplay)
                        .setAttribute("protocolDisplay", protocolDisplay)
                        .setAttribute("uiConsentTitle", uiConsentTitle)
                        .setAttribute("uiConsentDescription", uiConsentDescription)
                        .setAttribute("uiRequiredDataTitle", uiRequiredDataTitle)
                        .setAttribute("uiPrivacyTitle", uiPrivacyTitle)
                        .setAttribute("uiPrivacyDescription", uiPrivacyDescription)
                        .createForm(ftl)
        );
    }

    /**
     * Indicates whether this authenticator requires an existing user.
     *
     * <p>Returns {@code true} because SSI authentication verifies the user's
     * credentials (verifiable credentials) and maps them to an existing Keycloak user.
     *
     * @return always {@code true}
     */
    @Override
    public boolean requiresUser() {
        return true;
    }

    /**
     * Checks if this authenticator is configured for the given user.
     *
     * <p>Returns {@code true} for all users as SSI authentication is available
     * to any user with a digital wallet containing the required credentials.
     *
     * @param session the Keycloak session
     * @param realm the realm
     * @param user the user to check
     * @return always {@code true}
     */
    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    /**
     * Sets any required actions for the user after authentication.
     *
     * <p>Currently no required actions are set for SSI authentication.
     *
     * @param session the Keycloak session
     * @param realm the realm
     * @param user the authenticated user
     */
    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        LOGGER.info("Setting required actions for user: " + LogSanitizer.maskIdentifier(user.getUsername()));
    }

    /**
     * Closes any resources held by this authenticator.
     *
     * <p>This authenticator holds no resources, so this method is a no-op.
     */
    @Override
    public void close() {

    }
}

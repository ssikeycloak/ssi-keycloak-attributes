package kodrat.keycloak.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.logging.Logger;
import kodrat.keycloak.config.AttributeUtil;
import kodrat.keycloak.config.ConfigUtils;
import kodrat.keycloak.constant.HTTPConstants;
import kodrat.keycloak.constant.SSISessionConstants;
import kodrat.keycloak.constant.SSIStatus;
import kodrat.keycloak.dto.did.DIDWebVerificationResponse;
import kodrat.keycloak.exception.ConnectionTimeoutException;
import kodrat.keycloak.service.CredentialAttributeExtractor;
import kodrat.keycloak.service.EvidenceBuilder;
import kodrat.keycloak.service.PollingService;
import kodrat.keycloak.util.LogSanitizer;
import kodrat.keycloak.util.SSIErrorPageRenderer;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.sessions.AuthenticationSessionModel;

import static kodrat.keycloak.config.ConfigUtils.getCredentialType;

/**
 * DID method implementation for OpenID4VC-based credential verification using the
 * {@code did:web} method specification.
 *
 * <p>This implementation provides a <strong>connectionless</strong> authentication flow
 * where users scan a QR code containing an OpenID4VP authorization URL and present
 * verifiable credentials directly from their wallet without establishing a persistent
 * DIDComm connection.
 *
 * <h2>Authentication Flow</h2>
 * <p>The authentication process follows these steps:
 * <ol>
 *   <li>Create a verification session via the SSI agent's OpenID4VC endpoint</li>
 *   <li>Generate and display a QR code containing the OpenID4VP authorization URL</li>
 *   <li>Poll the SSI agent for credential presentation from the wallet</li>
 *   <li>Verify the presented credential and extract attributes</li>
 *   <li>Map extracted attributes to Keycloak user session</li>
 * </ol>
 *
 * <h2>Protocol Details</h2>
 * <p>This implementation uses:
 * <ul>
 *   <li><strong>OpenID4VP</strong> - OpenID for Verifiable Presentations</li>
 *   <li><strong>JWT-VC</strong> - JSON Web Token format for Verifiable Credentials</li>
 *   <li><strong>Direct Post</strong> - Response mode for presentation submission</li>
 * </ul>
 *
 * <h2>Configuration</h2>
 * <p>The following session notes are read by this implementation:
 * <table border="1">
 *   <caption>Session Configuration Parameters</caption>
 *   <tr><th>Parameter</th><th>Description</th></tr>
 *   <tr><td>{@code credential_type}</td><td>Credential format (e.g., "jwt_w3c_vc")</td></tr>
 *   <tr><td>{@code requested_credential}</td><td>JSON specifying credential requirements</td></tr>
 *   <tr><td>{@code authorize_base_url}</td><td>Base URL for authorization (default: openid4vp://authorize)</td></tr>
 *   <tr><td>{@code response_mode}</td><td>Presentation response mode (default: direct_post)</td></tr>
 * </table>
 *
 * <h2>Thread Safety</h2>
 * <p>This class is <strong>not thread-safe</strong>. Each authentication flow should
 * create its own instance via {@link DIDMethodFactory}. The internal {@link ObjectMapper}
 * is thread-safe and shared across instances.
 *
 * <h2>Example Usage</h2>
 * <pre>{@code
 * DIDMethod method = DIDMethodFactory.getMethod(context);
 * method.handleAuthentication(context);
 * 
 * // Later, in polling endpoint:
 * if (method.hasReceivedPresentation(session)) {
 *     boolean verified = method.verifyPresentation(session);
 * }
 * }</pre>
 *
 * @see AbstractDIDMethod
 * @see DIDMethod
 * @see DIDMethodFactory
 * @since 1.0.0
 * @author Kodrat Development Team
 */
public class DIDWeb extends AbstractDIDMethod {
    
    private static final Logger LOGGER = Logger.getLogger(DIDWeb.class.getName());
    
    private static final String FAILURE_REASON_NOTE = "ssi_failure_reason";
    
    private final ObjectMapper objectMapper;

    /**
     * Constructs a new DIDWeb instance with the specified SSI agent endpoint.
     *
     * @param endpoint the base URL of the SSI agent (e.g., "https://ssi.example.com")
     * @param bearerToken the bearer token for authenticating with the SSI agent,
     *                    may be {@code null} if authentication is not required
     * @throws NullPointerException if endpoint is null
     */
    public DIDWeb(String endpoint, String bearerToken) {
        super(endpoint, bearerToken);
        this.objectMapper = new ObjectMapper();
        LOGGER.info("[DIDWeb] Initialized with endpoint: " + endpoint);
    }

    /**
     * Handles the authentication flow UI rendering for the did:web method.
     *
     * <p>This method:
     * <ul>
     *   <li>Creates or retrieves an existing OpenID4VP verification session</li>
     *   <li>Generates a QR code URL for wallet scanning</li>
     *   <li>Renders the consent page with QR code and configuration attributes</li>
     * </ul>
     *
     * <p>If verification fails to initialize, an error page is displayed with
     * appropriate error messaging.
     *
     * @param context the Keycloak authentication flow context providing access to
     *                session, realm, and form rendering capabilities
     * @implNote This method stores sensitive data (bearer token) in session notes.
     *           Ensure proper session cleanup on authentication completion.
     */
    @Override
    public void handleAuthentication(AuthenticationFlowContext context) {
        LOGGER.info("[DIDWeb] Starting DID Web authentication flow");
        try {
            AuthenticationSessionModel session = context.getAuthenticationSession();
            String authorizeUrl = getAuthNote(session, SSISessionConstants.VERIFICATION_URL);

            if (authorizeUrl == null) {
                LOGGER.info("[DIDWeb] Creating new verification request via SSI agent");
                SSIResult result = sendProofRequest(session);
                if (!result.isDone()) {
                    LOGGER.warning("[DIDWeb] Failed to initiate proof request");
                    SSIErrorPageRenderer.render(context,
                            "SSI proof request failed",
                            "The SSI verifier could not create a wallet verification request. You can continue login without SSI verification.");
                    return;
                }
                authorizeUrl = getAuthNote(session, SSISessionConstants.VERIFICATION_URL);
            }

            String qrCodeUrl = buildLocalQrUrl(context, authorizeUrl);
            setAuthNote(session, SSISessionConstants.QR_CODE_URL, qrCodeUrl);
            setAuthNote(session, SSISessionConstants.INVITATION_URL, authorizeUrl);
            setAuthNote(session, SSISessionConstants.SSI_ENDPOINT, this.endpoint);
            setAuthNote(session, SSISessionConstants.SSI_BEARER_TOKEN, this.bearerToken);

            String sessionId = session.getParentSession().getId();
            String tabId = session.getTabId();

            LOGGER.info("[DIDWeb] Displaying QR code for session: " + LogSanitizer.maskIdentifier(sessionId));
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
                    .setAttribute("didMethod", "web")
                    .setAttribute("methodDisplay", "Web (did:web)")
                    .setAttribute("protocolDisplay", "OpenID4VC")
                    .setAttribute("uiConsentTitle", ConfigUtils.getUiConsentTitle(context))
                    .setAttribute("uiConsentDescription", ConfigUtils.getUiConsentDescription(context))
                    .setAttribute("uiRequiredDataTitle", ConfigUtils.getUiRequiredDataTitle(context))
                    .setAttribute("uiPrivacyTitle", ConfigUtils.getUiPrivacyTitle(context))
                    .setAttribute("uiPrivacyDescription", ConfigUtils.getUiPrivacyDescription(context))
                    .createForm("login-identity-consent.ftl"));
        } catch (Exception e) {
            LOGGER.severe("[DIDWeb] Exception during authentication: " + LogSanitizer.redact(e.getMessage()));
            SSIErrorPageRenderer.render(context,
                    "SSI verification unavailable",
                    "The SSI verifier failed while preparing wallet verification. You can continue login without SSI verification.");
        }
    }

    /**
     * Sends a proof request to the SSI agent to create an OpenID4VP verification session.
     *
     * <p>This method creates a new verification session if one does not already exist.
     * The session is identified by a unique state ID that is used for subsequent
     * polling operations.
     *
     * <p>If a valid state already exists with a verification URL, this method returns
     * success immediately without creating a new session. Stale states (stateId exists
     * but verification URL is missing) are automatically cleaned up.
     *
     * @param session the authentication session to store verification state
     * @return an {@link SSIResult} indicating success or failure of the operation;
     *         on success, contains the authorization URL and state ID in extra data
     * @see #hasReceivedPresentation(AuthenticationSessionModel)
     * @see SSIResult
     */
    @Override
    public SSIResult sendProofRequest(AuthenticationSessionModel session) {
        String stateId = getAuthNote(session, SSISessionConstants.SSI_STATE_ID);
        String existingVerificationUrl = getAuthNote(session, SSISessionConstants.VERIFICATION_URL);

        if (stateId != null && !stateId.isEmpty() && existingVerificationUrl != null && !existingVerificationUrl.isBlank()) {
            LOGGER.info("[DIDWeb] Proof request already initiated with state: " + LogSanitizer.maskIdentifier(stateId));
            return SSIResult.success();
        }

        if (stateId != null && !stateId.isEmpty() && (existingVerificationUrl == null || existingVerificationUrl.isBlank())) {
            LOGGER.warning("[DIDWeb] Found stale state without verification URL. Clearing and regenerating proof request.");
            removeAuthNote(session, SSISessionConstants.SSI_STATE_ID);
            stateId = null;
        }

        try {
            LOGGER.info("[DIDWeb] Initiating OpenID4VC proof request");
            String credentialType = getAuthNote(session, "credential_type");
            String requestedCredentialJson = getAuthNote(session, "requested_credential");

            String credentialName = "VerifiableDiploma";
            if (requestedCredentialJson != null && !requestedCredentialJson.isEmpty()) {
                try {
                    JsonNode configNode = objectMapper.readTree(requestedCredentialJson);
                    if (configNode.has("credential_type")) {
                        credentialName = configNode.get("credential_type").asText("VerifiableDiploma");
                    }
                } catch (Exception e) {
                    LOGGER.warning("[DIDWeb] Failed to parse requested_credential config");
                }
            }

            if (credentialType == null || credentialType.isEmpty()) {
                credentialType = "jwt_w3c_vc";
            }

            stateId = UUID.randomUUID().toString();
            Map<String, Object> payload = buildProofRequestPayload(credentialType, credentialName);

            Map<String, String> headers = new HashMap<>();
            headers.put("stateId", stateId);
            headers.put("authorizeBaseUrl", getAuthNote(session, "authorize_base_url") != null
                    ? getAuthNote(session, "authorize_base_url") : "openid4vp://authorize");
            headers.put("responseMode", getAuthNote(session, "response_mode") != null
                    ? getAuthNote(session, "response_mode") : "direct_post");
            putHeaderIfPresent(headers, "successRedirectUri", getAuthNote(session, "success_redirect_uri"));
            putHeaderIfPresent(headers, "errorRedirectUri", getAuthNote(session, "error_redirect_uri"));
            putHeaderIfPresent(headers, "statusCallbackUri", getAuthNote(session, "status_callback_uri"));
            putHeaderIfPresent(headers, "statusCallbackApiKey", getAuthNote(session, "status_callback_api_key"));

            String verifierUrl = this.endpoint + "/openid4vc/verify";
            String authorizationUrl = httpClient.post(verifierUrl, payload, headers, String.class);

            if (authorizationUrl == null || authorizationUrl.isEmpty()) {
                LOGGER.warning("[DIDWeb] No authorization_url received from verifier");
                return SSIResult.notReady("Failed to get authorization URL");
            }

            setAuthNote(session, SSISessionConstants.SSI_STATE_ID, stateId);
            setAuthNote(session, SSISessionConstants.VERIFICATION_URL, authorizationUrl);
            setAuthNote(session, SSISessionConstants.INVITATION_URL, authorizationUrl);
            setAuthNote(session, SSISessionConstants.SSI_STATUS, SSIStatus.VERIFYING.getValue());

            LOGGER.info("[DIDWeb] Authorization URL received from verifier");

            Map<String, Object> extra = new HashMap<>();
            extra.put("authorizationUrl", authorizationUrl);
            extra.put("stateId", stateId);

            return SSIResult.success(null, null, extra, "Proof request initiated");
        } catch (Exception e) {
            LOGGER.severe("[DIDWeb] Exception during proof request: " + LogSanitizer.redact(e.getMessage()));
            return SSIResult.notReady("Exception: " + e.getMessage());
        }
    }

    /**
     * Checks if the wallet has submitted a credential presentation.
     *
     * <p>This method polls the SSI agent's session endpoint to check if credential
     * data is available. It handles several edge cases:
     * <ul>
     *   <li><strong>Terminal failure states</strong> (FAILED, ERROR, REJECTED, etc.) -
     *       returns {@code true} with failure reason stored in session</li>
     *   <li><strong>404 responses</strong> - indicates stale session state that needs
     *       to be invalidated and regenerated</li>
     * </ul>
     *
     * @param session the authentication session containing the state ID
     * @return {@code true} if presentation data is available or terminal failure reached,
     *         {@code false} if still waiting or on recoverable error
     */
    @Override
    public boolean hasReceivedPresentation(AuthenticationSessionModel session) {
        String stateId = getAuthNote(session, SSISessionConstants.SSI_STATE_ID);
        if (stateId == null || stateId.isBlank()) {
            LOGGER.warning("[DIDWeb] State ID not found in session");
            return false;
        }

        try {
            String statusUrl = this.endpoint + "/openid4vc/session/" + stateId;
            String rawResponse = httpClient.get(statusUrl, null, String.class);
            JsonNode responseNode = objectMapper.readTree(rawResponse);
            DIDWebVerificationResponse response = objectMapper.treeToValue(responseNode, DIDWebVerificationResponse.class);

            boolean hasSubject = response != null && response.hasCredentialSubject();
            if (hasSubject) {
                LOGGER.info("[DIDWeb] Presentation data available from verifier session");
                return true;
            }

            String terminalStatus = extractTerminalFailureStatus(responseNode);
            if (terminalStatus != null) {
                LOGGER.warning("[DIDWeb] Verifier reached terminal status without credential subject: " + terminalStatus);
                setAuthNote(session, FAILURE_REASON_NOTE, "verifier_terminal_" + terminalStatus.toLowerCase(Locale.ROOT));
                return true;
            }

            return false;
        } catch (Exception e) {
            if (isHttp404(e)) {
                LOGGER.warning("[DIDWeb] Verifier session not found (404), invalidating stale state: " + LogSanitizer.maskIdentifier(stateId));
                invalidateStaleVerifierSession(session);
                return false;
            }
            LOGGER.warning("[DIDWeb] Exception checking presentation availability: " + LogSanitizer.redact(e.getMessage()));
            return false;
        }
    }

    /**
     * Performs credential verification using the polling mechanism.
     *
     * <p>This method polls the SSI agent with retry logic until either:
     * <ul>
     *   <li>A credential is successfully verified</li>
     *   <li>A terminal failure state is reached</li>
     *   <li>The maximum retry count is exceeded (timeout)</li>
     * </ul>
     *
     * <p>On successful verification:
     * <ul>
     *   <li>Extracts credential attributes using {@link CredentialAttributeExtractor}</li>
     *   <li>Validates configured issuer_did and subject_did constraints</li>
     *   <li>Builds audit evidence using {@link EvidenceBuilder}</li>
     *   <li>Persists attributes to the Keycloak user session</li>
     * </ul>
     *
     * @param session the authentication session containing verification state
     * @return {@code true} if verification succeeded, {@code false} otherwise
     * @see PollingService#pollWithRetry(String, java.util.function.Supplier, int, long)
     */
    @Override
    public boolean isVerified(AuthenticationSessionModel session) {
        LOGGER.info("[DIDWeb] Starting credential verification process");
        try {
            String stateId = getAuthNote(session, SSISessionConstants.SSI_STATE_ID);
            if (stateId == null || stateId.isBlank()) {
                LOGGER.warning("[DIDWeb] State ID not found in session");
                return false;
            }

            String statusUrl = this.endpoint + "/openid4vc/session/" + stateId;
            LOGGER.info("[DIDWeb] Polling verification status from agent");

            try {
                Boolean result = PollingService.pollWithRetry(
                    "DIDWebVerification",
                    () -> pollForVerification(session, statusUrl),
                    HTTPConstants.VERIFICATION_MAX_RETRIES,
                    HTTPConstants.VERIFICATION_POLLING_DELAY_MS
                );
                boolean verified = result != null && result;
                if (!verified) {
                    String reason = getAuthNote(session, FAILURE_REASON_NOTE);
                    LOGGER.warning("[DIDWeb] Verification completed with negative result - state: " +
                        LogSanitizer.maskIdentifier(stateId) + ", reason: " + (reason != null ? reason : "unknown"));
                }
                return verified;
            } catch (ConnectionTimeoutException e) {
                LOGGER.warning("[DIDWeb] Verification timeout after " +
                    (HTTPConstants.VERIFICATION_MAX_RETRIES * HTTPConstants.VERIFICATION_POLLING_DELAY_MS / 1000) + " seconds");
                return false;
            }
        } catch (Exception e) {
            LOGGER.severe("[DIDWeb] Exception during verification: " + LogSanitizer.redact(e.getMessage()));
            return false;
        }
    }

    /**
     * {@inheritDoc}
     * 
     * <p>For did:web, this delegates to {@link #isVerified(AuthenticationSessionModel)}
     * as the verification is performed via polling.
     */
    @Override
    public boolean verifyPresentation(AuthenticationSessionModel session) {
        return isVerified(session);
    }

    /**
     * {@inheritDoc}
     * 
     * <p>Creates the OpenID4VP authorization URL by initiating a proof request.
     */
    @Override
    protected String createInvitationUrl(AuthenticationSessionModel session) {
        SSIResult result = sendProofRequest(session);
        if (result.isDone()) {
            return getAuthNote(session, SSISessionConstants.VERIFICATION_URL);
        }
        return null;
    }

    /**
     * {@inheritDoc}
     * 
     * <p>Delegates to {@link #hasReceivedPresentation(AuthenticationSessionModel)}.
     */
    @Override
    protected boolean checkPresentationStatus(AuthenticationSessionModel session) {
        return hasReceivedPresentation(session);
    }

    /**
     * {@inheritDoc}
     * 
     * <p>For did:web, evidence is built during the polling phase in
     * {@link #pollForVerification(AuthenticationSessionModel, String)}.
     * 
     * @return an empty list; evidence is built during verification polling
     */
    @Override
    protected List<Map<String, Object>> buildEvidence(AuthenticationSessionModel session) {
        return new ArrayList<>();
    }

    /**
     * Polls the verification session endpoint and processes the response.
     *
     * <p>This method is called repeatedly by {@link PollingService} until
     * a definitive result (success or failure) is obtained.
     *
     * <p>Processing steps on successful poll:
     * <ol>
     *   <li>Parse the verifier session response</li>
     *   <li>Extract credential subject from the response</li>
     *   <li>Extract and validate attributes using {@link CredentialAttributeExtractor}</li>
     *   <li>Build audit evidence</li>
     *   <li>Save attributes to user session</li>
     *   <li>Cleanup temporary session notes</li>
     * </ol>
     *
     * @param session the authentication session for state storage
     * @param statusUrl the full URL to the verifier session endpoint
     * @return {@link Optional#empty()} if not ready, {@link Optional#of(Boolean.TRUE)}
     *         on success, {@link Optional#of(Boolean.FALSE)} on failure
     */
    private Optional<Boolean> pollForVerification(AuthenticationSessionModel session, String statusUrl) {
        try {
            String rawResponse = httpClient.get(statusUrl, null, String.class);
            JsonNode responseNode = objectMapper.readTree(rawResponse);
            DIDWebVerificationResponse response = objectMapper.treeToValue(responseNode, DIDWebVerificationResponse.class);

            if (response == null || !response.hasCredentialSubject()) {
                return Optional.empty();
            }

            JsonNode credentialSubject = response.getCredentialSubject().get();
            JsonNode policyResultsNode = responseNode.path("policyResults");

            Map<String, String> revealedAttrs = CredentialAttributeExtractor.extractFromDidWeb(
                session, credentialSubject, policyResultsNode,
                getAuthNote(session, "requested_credential")
            );

            if (revealedAttrs == null) {
                LOGGER.warning("[DIDWeb] Credential attribute extraction failed due to validation checks");
                if (getAuthNote(session, FAILURE_REASON_NOTE) == null) {
                    setAuthNote(session, FAILURE_REASON_NOTE, "attribute_validation_failed");
                }
                return Optional.of(false);
            }

            List<Map<String, Object>> evidenceList = EvidenceBuilder.buildFromDidWeb(policyResultsNode);
            if (evidenceList.isEmpty()) {
                evidenceList = List.of(EvidenceBuilder.buildFallbackEvidence(credentialSubject));
            }

            AttributeUtil.saveToUserSessionNote(session, revealedAttrs, evidenceList);

            removeAuthNote(session, SSISessionConstants.SSI_STATUS);
            removeAuthNote(session, SSISessionConstants.SSI_STATE_ID);
            removeAuthNote(session, SSISessionConstants.VERIFICATION_URL);
            removeAuthNote(session, SSISessionConstants.QR_CODE_URL);
            removeAuthNote(session, SSISessionConstants.INVITATION_URL);
            removeAuthNote(session, FAILURE_REASON_NOTE);

            LOGGER.info("[DIDWeb] Verification successful - " + revealedAttrs.size() + " attributes extracted and saved");
            return Optional.of(true);
        } catch (Exception e) {
            LOGGER.warning("[DIDWeb] Exception during polling: " + LogSanitizer.redact(e.getMessage()));
            return Optional.empty();
        }
    }

    /**
     * Builds a local QR code URL that proxies through the Keycloak server.
     *
     * <p>This allows the QR code image to be served from the same origin as Keycloak,
     * avoiding CORS issues and enabling the use of Keycloak's QR code generation
     * endpoint.
     *
     * @param context the authentication flow context for realm information
     * @param data the data to encode in the QR code (typically the authorization URL)
     * @return a relative URL to the Keycloak QR code endpoint, or empty string if data is null/blank
     */
    private String buildLocalQrUrl(AuthenticationFlowContext context, String data) {
        if (data == null || data.isBlank()) {
            return "";
        }
        String realmName = context.getRealm() != null ? context.getRealm().getName() : "";
        return "/realms/" + realmName + "/custom-resource/qr?data=" + URLEncoder.encode(data, StandardCharsets.UTF_8);
    }

    /**
     * Builds the JSON payload for the OpenID4VC verification request.
     *
     * <p>The payload specifies:
     * <ul>
     *   <li>Credential type and format requirements</li>
     *   <li>Verification policies (signature, expiration, not-before)</li>
     * </ul>
     *
     * @param credentialType the format type (e.g., "jwt_w3c_vc")
     * @param credentialName the credential type name (e.g., "VerifiableDiploma")
     * @return a map representing the JSON payload for the verification request
     */
    private Map<String, Object> buildProofRequestPayload(String credentialType, String credentialName) {
        Map<String, Object> payload = new HashMap<>();
        String format = "jwt_vc_json";
        Map<String, Object> credentialSpec = Map.of("type", credentialName, "format", format);
        payload.put("request_credentials", List.of(credentialSpec));
        payload.put("vc_policies", List.of("signature", "expired", "not-before"));
        return payload;
    }

    /**
     * Adds a header to the map only if the value is non-null and non-blank.
     *
     * @param headers the headers map to modify
     * @param key the header key
     * @param value the header value (only added if non-null and non-blank)
     */
    private void putHeaderIfPresent(Map<String, String> headers, String key, String value) {
        if (value != null && !value.isBlank()) {
            headers.put(key, value);
        }
    }

    /**
     * Checks if an exception indicates a 404 Not Found HTTP response.
     *
     * <p>Used to detect stale verifier sessions that have expired or been
     * cleaned up on the SSI agent side.
     *
     * @param e the exception to check
     * @return {@code true} if the exception indicates a 404 response
     */
    private boolean isHttp404(Exception e) {
        if (e == null) return false;
        return e.getMessage() != null && e.getMessage().contains("HTTP error: 404");
    }

    /**
     * Clears stale session state when the verifier returns a 404 response.
     *
     * <p>This resets the authentication state to allow a new verification session
     * to be created on the next attempt.
     *
     * @param session the authentication session to clean up
     */
    private void invalidateStaleVerifierSession(AuthenticationSessionModel session) {
        removeAuthNote(session, SSISessionConstants.SSI_STATE_ID);
        removeAuthNote(session, SSISessionConstants.VERIFICATION_URL);
        removeAuthNote(session, SSISessionConstants.INVITATION_URL);
        removeAuthNote(session, SSISessionConstants.QR_CODE_URL);
        setAuthNote(session, SSISessionConstants.SSI_STATUS, SSIStatus.WAITING_PROOF.getValue());
    }

    /**
     * Extracts terminal failure status from the verifier response.
     *
     * <p>Checks common status fields for failure indicators:
     * <ul>
     *   <li>{@code status}</li>
     *   <li>{@code state}</li>
     *   <li>{@code verificationStatus}</li>
     *   <li>{@code result}</li>
     *   <li>{@code error} object presence</li>
     * </ul>
     *
     * @param responseNode the JSON response node from the verifier
     * @return the status string if terminal failure detected, {@code null} otherwise
     */
    private String extractTerminalFailureStatus(JsonNode responseNode) {
        if (responseNode == null || responseNode.isMissingNode()) return null;
        String[] candidateFields = new String[] {"status", "state", "verificationStatus", "result"};
        for (String field : candidateFields) {
            JsonNode node = responseNode.path(field);
            if (node != null && node.isTextual()) {
                String value = node.asText();
                if (isTerminalFailureValue(value)) return value;
            }
        }
        JsonNode errorNode = responseNode.path("error");
        if (errorNode != null && !errorNode.isMissingNode() && !errorNode.isNull()) {
            return "error";
        }
        return null;
    }

    /**
     * Checks if a status value indicates a terminal failure state.
     *
     * <p>Terminal states indicate that verification cannot succeed and should
     * be reported immediately rather than continuing to poll.
     *
     * <p>Recognized terminal values (case-insensitive):
     * <ul>
     *   <li>{@code failed}</li>
     *   <li>{@code error}</li>
     *   <li>{@code rejected}</li>
     *   <li>{@code denied}</li>
     *   <li>{@code cancelled} / {@code canceled}</li>
     *   <li>{@code expired}</li>
     *   <li>{@code invalid}</li>
     * </ul>
     *
     * @param value the status value to check
     * @return {@code true} if the value indicates terminal failure
     */
    private boolean isTerminalFailureValue(String value) {
        if (value == null) return false;
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return normalized.equals("failed") || normalized.equals("error") || normalized.equals("rejected")
                || normalized.equals("denied") || normalized.equals("cancelled") || normalized.equals("canceled")
                || normalized.equals("expired") || normalized.equals("invalid");
    }

    /**
     * Creates a new OpenID4VP verification URL for the wallet.
     *
     * <p>This method initiates a new proof request to generate a verification URL.
     * Used by REST API when the existing verification URL has been cleared (e.g., after retry).
     *
     * @param session the authentication session for storing verification state
     * @return the verification URL, or {@code null} if creation fails
     */
    @Override
    public String createInvitation(AuthenticationSessionModel session) {
        String invitationUrl = createInvitationUrl(session);
        if (invitationUrl == null) {
            LOGGER.warning("[DIDWeb] Failed to create invitation/verification URL");
        } else {
            LOGGER.info("[DIDWeb] Created new verification URL via REST API");
        }
        return invitationUrl;
    }
}

package kodrat.keycloak.api;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Defines the contract for DID (Decentralized Identifier) method implementations.
 * 
 * <p>This interface provides a unified abstraction for different DID methods
 * (e.g., did:sov, did:web) to integrate with Keycloak's authentication flow.
 * All methods operate on {@link AuthenticationSessionModel} for consistent state
 * management across both authenticator and REST API contexts.
 *
 * <h2>Implementation Requirements</h2>
 * <ul>
 *   <li>All methods must be thread-safe for concurrent session access</li>
 *   <li>Implementations should handle network failures gracefully</li>
 *   <li>State must be persisted via auth notes for REST API compatibility</li>
 * </ul>
 *
 * @see AbstractDIDMethod Base class providing common functionality
 * @see DIDTemplate Template implementation for new DID methods
 * @see DIDMethodFactory Factory for creating DID method instances
 */
public interface DIDMethod {

    /**
     * Handles the authentication flow UI rendering and initializes the verification process.
     * 
     * <p>This method receives the full {@link AuthenticationFlowContext} because it needs
     * access to {@code context.challenge()} for displaying the QR code consent form.
     * Implementations should generate an invitation/verification URL and render the
     * appropriate FreeMarker template.
     *
     * @param context the authentication flow context containing session, realm, and configuration
     * @throws kodrat.keycloak.exception.SSIException if the verification process fails to initialize
     */
    void handleAuthentication(AuthenticationFlowContext context);

    /**
     * Checks whether a DID connection has been established with the wallet.
     * 
     * <p>For connectionless methods (e.g., DID Web via OpenID4VC), this method
     * should always return {@code true}. For connection-based methods (e.g., DID Sov),
     * this method should check the connection state with the SSI agent.
     *
     * @param session the authentication session containing connection state
     * @return {@code true} if connection is established or not required, {@code false} otherwise
     */
    boolean isConnectionEstablished(AuthenticationSessionModel session);

    /**
     * Sends a proof request to the connected wallet.
     * 
     * <p>This method initiates the credential verification request. For DID Sov,
     * this creates an Indy proof request. For DID Web, this creates an OpenID4VP
     * verification session. The resulting invitation URL should be stored in the
     * session for QR code generation.
     *
     * @param session the authentication session for storing proof request state
     * @return an {@link SSIResult} indicating whether the request was sent successfully
     */
    SSIResult sendProofRequest(AuthenticationSessionModel session);

    /**
     * Checks whether the wallet has submitted a credential presentation.
     * 
     * <p>This method polls the SSI agent to check if a presentation has been received.
     * It should return {@code true} once the presentation data is available for verification,
     * even if the verification itself has not yet been performed.
     *
     * @param session the authentication session containing presentation exchange state
     * @return {@code true} if presentation has been received, {@code false} otherwise
     */
    boolean hasReceivedPresentation(AuthenticationSessionModel session);

    /**
     * Verifies the submitted presentation and extracts credential attributes.
     * 
     * <p>This method performs the cryptographic verification of the presentation,
     * validates any configured constraints (e.g., issuer_did, subject_did), and
     * extracts the revealed attributes. On success, attributes should be saved to
     * the user session notes via {@link kodrat.keycloak.config.AttributeUtil}.
     *
     * @param session the authentication session containing the presentation to verify
     * @return {@code true} if verification succeeds and attributes are extracted,
     *         {@code false} if verification fails or constraints are not met
     */
    boolean verifyPresentation(AuthenticationSessionModel session);

    /**
     * Checks whether the credential has been successfully verified.
     * 
     * <p>This is a lightweight check that verifies the verification state without
     * performing the full verification process. Use this for polling scenarios.
     *
     * @param session the authentication session containing verification state
     * @return {@code true} if the credential has been verified, {@code false} otherwise
     */
    boolean isVerified(AuthenticationSessionModel session);

    /**
     * Generates a QR code data URL from an invitation or verification URL.
     * 
     * <p>The returned URL can be used directly in an HTML img tag's src attribute.
     * The QR code encodes the invitation URL that wallets scan to begin the
     * verification process.
     *
     * @param invitationUrl the invitation or verification URL to encode in the QR code
     * @return a data URL containing the base64-encoded QR code image
     * @throws kodrat.keycloak.exception.SSIException if the invitation URL is invalid
     */
    String generateQRCode(String invitationUrl);

    /**
     * Creates a new invitation/verification URL for the wallet.
     *
     * <p>This method is used by the REST API to create a new invitation when
     * the existing one has been cleared (e.g., after a retry). Implementations
     * should create the invitation via the SSI agent and store it in the session.
     *
     * @param session the authentication session for storing invitation state
     * @return the invitation URL, or {@code null} if creation fails
     */
    String createInvitation(AuthenticationSessionModel session);
}

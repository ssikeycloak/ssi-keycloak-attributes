package kodrat.keycloak.api;

import kodrat.keycloak.service.HttpClientService;
import kodrat.keycloak.service.QRCodeService;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.List;
import java.util.Map;

/**
 * Abstract base class for DID method implementations providing common infrastructure.
 * 
 * <p>This class implements the Template Method pattern, providing shared functionality
 * for HTTP communication, QR code generation, and session management while defining
 * abstract hook methods that subclasses must implement for protocol-specific logic.
 *
 * <h2>Creating a New DID Method</h2>
 * <ol>
 *   <li>Copy {@link DIDTemplate} and rename to your method (e.g., {@code DIDIon})</li>
 *   <li>Extend this class and call {@code super(endpoint, bearerToken)} in constructor</li>
 *   <li>Implement all abstract hook methods</li>
 *   <li>Override optional hooks as needed (e.g., {@link #isConnectionRequired()})</li>
 *   <li>Register in {@link DIDMethodFactory#getMethodFromRaw(String, String, String)}</li>
 * </ol>
 *
 * <h2>Hook Methods</h2>
 * <table border="1">
 *   <tr><th>Hook</th><th>Purpose</th><th>Required</th></tr>
 *   <tr><td>{@link #createInvitationUrl}</td><td>Generate invitation/verification URL</td><td>Yes</td></tr>
 *   <tr><td>{@link #checkPresentationStatus}</td><td>Poll for presentation status</td><td>Yes</td></tr>
 *   <tr><td>{@link #verifyPresentation}</td><td>Verify and extract attributes</td><td>Yes</td></tr>
 *   <tr><td>{@link #buildEvidence}</td><td>Build audit evidence</td><td>Yes</td></tr>
 *   <tr><td>{@link #isConnectionRequired}</td><td>Connection requirement flag</td><td>No (default: false)</td></tr>
 *   <tr><td>{@link #checkConnectionStatus}</td><td>Check connection state</td><td>No (default: false)</td></tr>
 * </table>
 *
 * @see DIDMethod The interface this class implements
 * @see DIDTemplate Reference implementation for new DID methods
 * @see DIDWeb OpenID4VC implementation
 * @see DIDSov DIDComm/Indy implementation
 */
public abstract class AbstractDIDMethod implements DIDMethod {

    /** The SSI agent endpoint URL. */
    protected final String endpoint;
    
    /** The bearer token for authenticating with the SSI agent. */
    protected final String bearerToken;
    
    /** HTTP client service for making requests to the SSI agent. */
    protected final HttpClientService httpClient;

    /**
     * Constructs a new DID method instance with the specified configuration.
     *
     * @param endpoint the URL of the SSI agent (e.g., "https://agent.example.com")
     * @param bearerToken the bearer token for authentication, or {@code null} if not required
     */
    protected AbstractDIDMethod(String endpoint, String bearerToken) {
        this.endpoint = endpoint;
        this.bearerToken = bearerToken;
        this.httpClient = new HttpClientService(bearerToken);
    }

    /**
     * {@inheritDoc}
     * 
     * <p>Delegates to {@link QRCodeService} for QR code generation.
     */
    @Override
    public String generateQRCode(String invitationUrl) {
        return QRCodeService.generateQRCodeUrl(invitationUrl);
    }

    /**
     * {@inheritDoc}
     * 
     * <p>Returns {@code true} immediately for connectionless methods.
     * For connection-based methods, delegates to {@link #checkConnectionStatus}.
     */
    @Override
    public boolean isConnectionEstablished(AuthenticationSessionModel session) {
        if (!isConnectionRequired()) {
            return true;
        }
        return checkConnectionStatus(session);
    }

    /**
     * Retrieves an authentication note from the session.
     *
     * @param session the authentication session
     * @param key the note key
     * @return the note value, or {@code null} if not set
     */
    protected String getAuthNote(AuthenticationSessionModel session, String key) {
        return session.getAuthNote(key);
    }

    /**
     * Stores an authentication note in the session.
     *
     * @param session the authentication session
     * @param key the note key
     * @param value the note value
     */
    protected void setAuthNote(AuthenticationSessionModel session, String key, String value) {
        session.setAuthNote(key, value);
    }

    /**
     * Removes an authentication note from the session.
     *
     * @param session the authentication session
     * @param key the note key to remove
     */
    protected void removeAuthNote(AuthenticationSessionModel session, String key) {
        session.removeAuthNote(key);
    }

    /**
     * Hook: Determines whether this DID method requires connection establishment.
     * 
     * <p>Override this method to return {@code true} for connection-based protocols
     * like DIDComm (e.g., DID Sov). Connectionless methods like DID Web should
     * return the default value of {@code false}.
     *
     * @return {@code true} if connection establishment is required, {@code false} otherwise
     */
    protected boolean isConnectionRequired() {
        return false;
    }

    /**
     * Hook: Checks the connection status with the wallet.
     * 
     * <p>This method is only called when {@link #isConnectionRequired()} returns
     * {@code true}. Implementations should query the SSI agent to determine if
     * a valid connection exists.
     *
     * @param session the authentication session containing connection state
     * @return {@code true} if connection is established, {@code false} otherwise
     */
    protected boolean checkConnectionStatus(AuthenticationSessionModel session) {
        return false;
    }

    /**
     * Hook: Determines whether a proof request is required.
     * 
     * <p>Most DID methods require sending a proof request. Override this method
     * to return {@code false} for methods that perform direct verification without
     * a separate proof request step.
     *
     * @return {@code true} if proof request is required, {@code false} otherwise
     */
    protected boolean isProofRequestRequired() {
        return true;
    }

    /**
     * Hook: Creates the invitation or verification URL for the wallet.
     * 
     * <p>This method should generate the URL that will be encoded in the QR code
     * and scanned by the wallet to begin the verification process. The URL should
     * be stored in the session using the {@code INVITATION_URL} key.
     *
     * @param session the authentication session for storing invitation state
     * @return the invitation URL, or {@code null} if creation fails
     */
    protected abstract String createInvitationUrl(AuthenticationSessionModel session);

    /**
     * Hook: Checks whether a presentation has been received from the wallet.
     * 
     * <p>This method should poll the SSI agent to check if the wallet has submitted
     * a credential presentation. It should return {@code true} once the presentation
     * data is available, regardless of whether it has been verified.
     *
     * @param session the authentication session containing presentation exchange state
     * @return {@code true} if presentation is available, {@code false} otherwise
     */
    protected abstract boolean checkPresentationStatus(AuthenticationSessionModel session);

    /**
     * Hook: Verifies the presentation and extracts credential attributes.
     * 
     * <p>This method must perform the following steps:
     * <ol>
     *   <li>Retrieve the presentation from the SSI agent</li>
     *   <li>Verify the cryptographic signature</li>
     *   <li>Validate configured constraints (issuer_did, subject_did)</li>
     *   <li>Extract revealed attributes from the credential</li>
     *   <li>Save attributes to session via {@link kodrat.keycloak.config.AttributeUtil}</li>
     * </ol>
     *
     * @param session the authentication session containing the presentation to verify
     * @return {@code true} if verification succeeds, {@code false} otherwise
     */
    @Override
    public abstract boolean verifyPresentation(AuthenticationSessionModel session);

    /**
     * Hook: Builds evidence for the audit trail.
     * 
     * <p>Evidence provides verifiable proof that the credential verification occurred.
     * The returned list should contain one or more evidence items conforming to
     * OpenID4VC evidence structure.
     *
     * @param session the authentication session containing verification data
     * @return a list of evidence items, or an empty list if evidence cannot be built
     */
    protected abstract List<Map<String, Object>> buildEvidence(AuthenticationSessionModel session);
}

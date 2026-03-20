package kodrat.keycloak.constant;

/**
 * Constants for storing SSI authentication data in Keycloak session attributes.
 *
 * <p>This class defines the key names used to store and retrieve authentication
 * state throughout the SSI verification flow. These keys are used in both
 * authentication session notes (short-lived during authentication) and user
 * session notes (persisted for the duration of the user session).
 *
 * <h2>Session Note Categories</h2>
 * <table border="1">
 *   <caption>Session Note Categories</caption>
 *   <tr><th>Category</th><th>Keys</th><th>Lifecycle</th></tr>
 *   <tr><td>Configuration</td><td>did_method, ssi_endpoint, ssi_bearer_token</td><td>Set at flow start</td></tr>
 *   <tr><td>Flow State</td><td>ssi_flow_id, ssi_status</td><td>Updated during flow</td></tr>
 *   <tr><td>Connection</td><td>connection_id, invitation_url, invi_msg_id</td><td>Connection-based methods</td></tr>
 *   <tr><td>Verification</td><td>pres_ex_id, ssi_state_id, verification_url</td><td>During verification</td></tr>
 *   <tr><td>Result</td><td>verified_claims, ssi_failure_reason</td><td>After completion</td></tr>
 * </table>
 *
 * <h2>Usage Example</h2>
 * <pre>{@code
 * // Set authentication session notes
 * session.setAuthNote(SSISessionConstants.DID_METHOD, "web");
 * session.setAuthNote(SSISessionConstants.SSI_STATUS, SSIStatus.VERIFYING.getValue());
 * 
 * // Retrieve session notes
 * String status = session.getAuthNote(SSISessionConstants.SSI_STATUS);
 * String connectionId = session.getAuthNote(SSISessionConstants.CONNECTION_ID);
 * }</pre>
 *
 * <h2>Thread Safety</h2>
 * <p>This class contains only static final constants. It is inherently thread-safe.
 *
 * @see SSIStatus
 * @see SSIReasonCode
 * @since 1.0.0
 * @author Kodrat Development Team
 */
public final class SSISessionConstants {
    
    /**
     * Private constructor to prevent instantiation.
     * This is a constants class with only static fields.
     */
    private SSISessionConstants() {
    }

    /**
     * Unique identifier for the current SSI authentication flow attempt.
     *
     * <p>Generated on each new flow or retry. Used for log correlation and
     * detecting duplicate flow invocations.
     */
    public static final String SSI_FLOW_ID = "ssi_flow_id";

    /**
     * Current status of the SSI authentication flow.
     *
     * <p>Values are from {@link SSIStatus} (e.g., "waiting-connection", "verifying", "done").
     */
    public static final String SSI_STATUS = "ssi_status";

    /**
     * Base URL of the SSI agent (e.g., ACA-Py).
     *
     * <p>Example: "https://aca-py.example.com"
     */
    public static final String SSI_ENDPOINT = "ssi_endpoint";

    /**
     * Bearer token for authenticating with the SSI agent.
     *
     * <p>May be null if the agent doesn't require authentication.
     */
    public static final String SSI_BEARER_TOKEN = "ssi_bearer_token";

    /**
     * State ID for tracking OpenID4VC verification sessions.
     *
     * <p>Used by did:web method to correlate verification requests with responses.
     */
    public static final String SSI_STATE_ID = "ssi_state_id";

    /**
     * URL for the DIDComm invitation or OpenID4VP authorization.
     *
     * <p>Encoded in QR code for wallet scanning.
     */
    public static final String INVITATION_URL = "invitation_url";

    /**
     * Epoch timestamp (milliseconds) when OOB QR code was displayed.
     *
     * <p>Used for timing metrics and debugging.
     */
    public static final String OOB_QR_SHOWN_AT = "oob_qr_shown_at";

    /**
     * Epoch timestamp (milliseconds) when wallet scan was first detected.
     *
     * <p>Set when connection request state is observed.
     */
    public static final String OOB_QR_SCANNED_AT = "oob_qr_scanned_at";

    /**
     * Connection ID currently being accepted via DIDExchange.
     *
     * <p>Used for debouncing accept-request calls.
     */
    public static final String SOV_ACCEPT_CONN_ID = "sov_accept_conn_id";

    /**
     * Epoch timestamp (milliseconds) of last DIDExchange accept attempt.
     *
     * <p>Used for debouncing to avoid duplicate accept calls.
     */
    public static final String SOV_ACCEPT_LAST_AT = "sov_accept_last_at";

    /**
     * Connection ID that has been successfully accepted.
     *
     * <p>Used to track completed DIDExchange accept operations.
     */
    public static final String SOV_ACCEPTED_CONN_ID = "sov_accepted_conn_id";

    /**
     * Relative URL for the QR code image endpoint.
     *
     * <p>Proxied through Keycloak server to avoid CORS issues.
     */
    public static final String QR_CODE_URL = "qr_code_url";

    /**
     * OpenID4VP verification URL.
     *
     * <p>Used by did:web method for credential verification.
     */
    public static final String VERIFICATION_URL = "verification_url";

    /**
     * Established DIDComm connection ID.
     *
     * <p>Used for connection-based methods (did:sov) to send proof requests.
     */
    public static final String CONNECTION_ID = "connection_id";

    /**
     * Presentation exchange ID for tracking proof requests.
     *
     * <p>Returned by ACA-Py when proof request is sent.
     */
    public static final String PRES_EX_ID = "pres_ex_id";

    /**
     * Invitation message ID for correlating connections with invitations.
     *
     * <p>Used to find connections created from a specific invitation.
     */
    public static final String INVI_MSG_ID = "invi_msg_id";

    /**
     * JSON containing verified credential claims.
     *
     * <p>Stored in OpenID4VC verified_claims format for token mappers.
     */
    public static final String VERIFIED_CLAIMS = "verified_claims";

    /**
     * Failure reason code for SSI verification diagnostics.
     *
     * <p>Set when verification fails to provide user-facing error messages.
     */
    public static final String SSI_FAILURE_REASON = "ssi_failure_reason";

    /**
     * Legacy token key for backward compatibility.
     *
     * @deprecated Use {@link #SSI_BEARER_TOKEN} instead
     */
    public static final String SSI_TOKEN = "ssi_token";

    /**
     * The DID method being used (e.g., "sov" or "web").
     */
    public static final String DID_METHOD = "did_method";

    /**
     * Raw proof request JSON from authenticator config.
     *
     * <p>Copied to session for REST API flow reuse.
     */
    public static final String PROOF_REQUEST_JSON = "proof_request_json";

    /**
     * Requested credential configuration JSON from authenticator config.
     *
     * <p>Contains credential type, schema_id, and attributes for OpenID4VC/Indy flows.
     * Copied to session for REST API flow reuse.
     */
    public static final String REQUESTED_CREDENTIAL = "requested_credential";

    /**
     * Resolvable DID for connection reuse.
     *
     * <p>Must be consistent across all invitations for the same user/realm
     * to enable ACA-Py connection reuse feature.
     */
    public static final String REUSABLE_DID = "reusable_did";
}

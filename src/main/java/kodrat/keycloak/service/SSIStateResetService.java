package kodrat.keycloak.service;

import kodrat.keycloak.constant.SSISessionConstants;
import kodrat.keycloak.util.LogSanitizer;
import kodrat.keycloak.util.SSIFlowLogger;
import org.jboss.logging.Logger;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 * Centralized service for resetting SSI authentication flow state.
 *
 * <p>This service provides a single source of truth for transient session note
 * cleanup, ensuring consistent behavior across the authenticator, REST API retry
 * endpoint, and UI components. It distinguishes between transient state (which
 * should be cleared on retry) and configuration state (which should persist).
 *
 * <h2>Transient vs Configuration State</h2>
 * <table border="1">
 *   <caption>State Categories</caption>
 *   <tr><th>Category</th><th>Examples</th><th>Cleared on Retry</th></tr>
 *   <tr><td>Transient</td><td>ssi_status, connection_id, pres_ex_id</td><td>Yes</td></tr>
 *   <tr><td>Configuration</td><td>ssi_endpoint, did_method, proof_request_json</td><td>No</td></tr>
 * </table>
 *
 * <h2>Transient Session Notes</h2>
 * <p>The following notes are cleared when resetting flow state:
 * <ul>
 *   <li>{@code ssi_status} - Current flow status</li>
 *   <li>{@code ssi_flow_id} - Flow correlation ID</li>
 *   <li>{@code invitation_url} - DIDComm invitation URL</li>
 *   <li>{@code qr_code_url} - QR code image URL</li>
 *   <li>{@code verification_url} - OpenID4VP verification URL</li>
 *   <li>{@code connection_id} - Established connection ID</li>
 *   <li>{@code pres_ex_id} - Presentation exchange ID</li>
 *   <li>{@code invi_msg_id} - Invitation message ID</li>
 *   <li>{@code ssi_state_id} - Verification state ID</li>
 *   <li>{@code oob_qr_shown_at} - QR display timestamp</li>
 *   <li>{@code oob_qr_scanned_at} - QR scan timestamp</li>
 *   <li>{@code sov_accept_*} - DIDExchange acceptance state</li>
 *   <li>{@code verified_claims} - Extracted credential claims</li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 * <pre>{@code
 * // Reset for a fresh authentication attempt
 * String newFlowId = SSIStateResetService.resetTransientFlowState(session);
 * 
 * // Reset for retry (preserves config, logs event)
 * String newFlowId = SSIStateResetService.resetForRetry(session);
 * 
 * // Get list of transient keys for validation
 * List<String> keys = SSIStateResetService.getTransientNoteKeys();
 * }</pre>
 *
 * <h2>Flow ID Generation</h2>
 * <p>Each reset generates a new UUID flow ID that can be used for log correlation
 * and debugging. The flow ID is stored in the {@code ssi_flow_id} session note.
 *
 * <h2>Thread Safety</h2>
 * <p>This class is stateless and all methods are static. It is safe to call from
 * multiple threads concurrently. Session modifications are handled by Keycloak's
 * thread-safe session management.
 *
 * @see SSIFlowLogger
 * @see SSISessionConstants
 * @since 1.0.0
 * @author Kodrat Development Team
 */
public final class SSIStateResetService {
    
    private static final Logger LOGGER = Logger.getLogger(SSIStateResetService.class);
    
    /**
     * List of transient session notes that should be cleared when resetting SSI flow.
     * These represent state that should NOT persist across retry attempts.
     */
    private static final List<String> TRANSIENT_AUTH_NOTES = Arrays.asList(
            SSISessionConstants.SSI_STATUS,
            SSISessionConstants.SSI_FLOW_ID,
            SSISessionConstants.INVITATION_URL,
            SSISessionConstants.QR_CODE_URL,
            SSISessionConstants.VERIFICATION_URL,
            SSISessionConstants.CONNECTION_ID,
            SSISessionConstants.PRES_EX_ID,
            SSISessionConstants.INVI_MSG_ID,
            SSISessionConstants.SSI_STATE_ID,
            SSISessionConstants.OOB_QR_SHOWN_AT,
            SSISessionConstants.OOB_QR_SCANNED_AT,
            SSISessionConstants.SOV_ACCEPT_CONN_ID,
            SSISessionConstants.SOV_ACCEPT_LAST_AT,
            SSISessionConstants.SOV_ACCEPTED_CONN_ID,
            SSISessionConstants.VERIFIED_CLAIMS
    );
    
    /**
     * Private constructor to prevent instantiation.
     * This is a utility class with only static methods.
     */
    private SSIStateResetService() {
    }
    
    /**
     * Resets all transient SSI flow state from the authentication session.
     *
     * <p>This method clears all transient session notes and generates a new
     * flow ID for correlation. Configuration notes (endpoint, bearer token,
     * DID method, proof request JSON) are preserved.
     *
     * <p>Call this method when:
     * <ul>
     *   <li>Starting a fresh SSI verification attempt</li>
     *   <li>Resetting after an error</li>
     *   <li>Handling a retry request</li>
     * </ul>
     *
     * @param authSession the authentication session to reset
     * @return the new flow ID assigned to this session
     */
    public static String resetTransientFlowState(AuthenticationSessionModel authSession) {
        String tabId = authSession.getTabId();
        LOGGER.info("[SSIStateResetService] Resetting transient SSI state for tab: " + LogSanitizer.maskIdentifier(tabId));
        
        int clearedCount = 0;
        for (String noteKey : TRANSIENT_AUTH_NOTES) {
            if (authSession.getAuthNote(noteKey) != null) {
                authSession.removeAuthNote(noteKey);
                clearedCount++;
            }
        }
        
        String newFlowId = UUID.randomUUID().toString();
        authSession.setAuthNote(SSISessionConstants.SSI_FLOW_ID, newFlowId);
        
        LOGGER.info("[SSIStateResetService] Cleared " + clearedCount + " transient notes, assigned new flowId: " 
                + LogSanitizer.maskIdentifier(newFlowId));
        
        return newFlowId;
    }
    
    /**
     * Resets transient state for a retry attempt.
     *
     * <p>This method is a convenience wrapper around {@link #resetTransientFlowState}
     * that also logs a retry event with the previous status for correlation.
     * Configuration notes are preserved to allow seamless retry without
     * re-fetching configuration.
     *
     * @param authSession the authentication session to reset
     * @return the new flow ID assigned to this session
     */
    public static String resetForRetry(AuthenticationSessionModel authSession) {
        String previousStatus = authSession.getAuthNote(SSISessionConstants.SSI_STATUS);
        LOGGER.info("[SSIStateResetService] Retry requested - previous status: " + previousStatus);
        
        String newFlowId = resetTransientFlowState(authSession);
        
        SSIFlowLogger.logReset(authSession, newFlowId, "api");
        
        return newFlowId;
    }
    
    /**
     * Returns the list of transient auth note keys.
     *
     * <p>Useful for testing, validation, and debugging to understand which
     * session notes are considered transient.
     *
     * @return an unmodifiable list of transient note key names
     */
    public static List<String> getTransientNoteKeys() {
        return TRANSIENT_AUTH_NOTES;
    }
}

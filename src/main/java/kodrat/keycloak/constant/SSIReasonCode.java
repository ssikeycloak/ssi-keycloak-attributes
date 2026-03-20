package kodrat.keycloak.constant;

/**
 * Reason codes for SSI authentication status responses.
 * These codes allow frontend to programmatically handle different error states.
 */
public final class SSIReasonCode {
    
    private SSIReasonCode() {
        // Utility class - prevent instantiation
    }
    
    // ==== Success states ====
    
    /** Operation completed successfully */
    public static final String SUCCESS = "success";
    
    /** Flow in progress, continue polling */
    public static final String IN_PROGRESS = "in_progress";
    
    /** Flow reset successful, ready to retry */
    public static final String RESET_OK = "reset_ok";
    
    // ==== Client error states (recoverable) ====
    
    /** Maximum polling attempts reached - user should retry */
    public static final String TIMEOUT = "timeout";
    
    /** Verification failed - credential rejected or invalid */
    public static final String INVALID = "invalid";
    
    /** Missing required parameters (sessionId, tabId) */
    public static final String MISSING_PARAMS = "missing_params";
    
    /** Session or tab not found / expired */
    public static final String SESSION_EXPIRED = "session_expired";
    
    /** Invalid tab ID for this session */
    public static final String INVALID_TAB = "invalid_tab";
    
    /** Authentication required but not provided */
    public static final String UNAUTHORIZED = "unauthorized";
    
    // ==== Server error states (may or may not be recoverable) ====
    
    /** Internal server error during SSI operation */
    public static final String INTERNAL_ERROR = "internal_error";
    
    /** Connection to SSI agent failed */
    public static final String AGENT_UNREACHABLE = "agent_unreachable";
    
    /** Proof request failed to send */
    public static final String PROOF_REQUEST_FAILED = "proof_request_failed";
    
    // ==== Utility methods ====
    
    /**
     * Checks if the reason code indicates a recoverable error (user can retry).
     * @param reasonCode The reason code to check
     * @return true if the error is recoverable via retry
     */
    public static boolean isRecoverable(String reasonCode) {
        return TIMEOUT.equals(reasonCode) 
                || INVALID.equals(reasonCode)
                || AGENT_UNREACHABLE.equals(reasonCode)
                || PROOF_REQUEST_FAILED.equals(reasonCode);
    }
    
    /**
     * Checks if the reason code indicates a terminal error (requires full restart).
     * @param reasonCode The reason code to check
     * @return true if the error requires session restart
     */
    public static boolean isTerminal(String reasonCode) {
        return SESSION_EXPIRED.equals(reasonCode)
                || INVALID_TAB.equals(reasonCode)
                || INTERNAL_ERROR.equals(reasonCode);
    }
}

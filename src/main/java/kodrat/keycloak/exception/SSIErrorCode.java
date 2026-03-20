package kodrat.keycloak.exception;

/**
 * Standardized error codes for SSI flow operations.
 * Provides machine-readable error classification for monitoring and alerting.
 */
public enum SSIErrorCode {

    // Configuration errors (1xxx)
    CONFIG_MISSING_ENDPOINT("SSI-1001", "Missing SSI endpoint configuration", ErrorCategory.CONFIGURATION),
    CONFIG_MISSING_TOKEN("SSI-1002", "Missing bearer token", ErrorCategory.CONFIGURATION),
    CONFIG_INVALID_JSON("SSI-1003", "Invalid JSON in configuration", ErrorCategory.CONFIGURATION),
    CONFIG_MISSING_SCHEMA("SSI-1004", "Missing schema ID or attributes", ErrorCategory.CONFIGURATION),

    // Connection errors (2xxx)
    CONNECTION_TIMEOUT("SSI-2001", "Connection to SSI agent timed out", ErrorCategory.NETWORK),
    CONNECTION_REFUSED("SSI-2002", "Connection refused by SSI agent", ErrorCategory.NETWORK),
    CONNECTION_DNS_FAILED("SSI-2003", "DNS resolution failed", ErrorCategory.NETWORK),
    CONNECTION_SSL_ERROR("SSI-2004", "SSL/TLS handshake failed", ErrorCategory.NETWORK),
    CONNECTION_UNKNOWN_HOST("SSI-2005", "Unknown host", ErrorCategory.NETWORK),

    // Flow errors (3xxx)
    FLOW_INVALID_STATE("SSI-3001", "Invalid flow state transition", ErrorCategory.BUSINESS_LOGIC),
    FLOW_SESSION_EXPIRED("SSI-3002", "Authentication session expired", ErrorCategory.BUSINESS_LOGIC),
    FLOW_DUPLICATE("SSI-3003", "Duplicate flow initiation detected", ErrorCategory.BUSINESS_LOGIC),
    FLOW_NOT_INITIALIZED("SSI-3004", "Flow not properly initialized", ErrorCategory.BUSINESS_LOGIC),

    // DIDComm errors (4xxx)
    // Note: Some DIDComm errors are retryable (transient), some are not (permanent)
    DIDCOMM_INVITATION_FAILED("SSI-4001", "Failed to create connection invitation", ErrorCategory.DID_COMMUNICATION, true),
    DIDCOMM_CONNECTION_FAILED("SSI-4002", "Failed to establish connection", ErrorCategory.DID_COMMUNICATION, true),
    DIDCOMM_PROOF_REQUEST_FAILED("SSI-4003", "Failed to send proof request", ErrorCategory.DID_COMMUNICATION, true),
    DIDCOMM_PRESENTATION_TIMEOUT("SSI-4004", "Presentation not received within timeout", ErrorCategory.DID_COMMUNICATION, true),
    DIDCOMM_VERIFICATION_FAILED("SSI-4005", "Presentation verification failed", ErrorCategory.DID_COMMUNICATION, false),
    DIDCOMM_INVALID_RESPONSE("SSI-4006", "Invalid response from agent", ErrorCategory.DID_COMMUNICATION, true),

    // Authentication errors (5xxx)
    AUTH_UNAUTHORIZED("SSI-5001", "Unauthorized access", ErrorCategory.AUTHENTICATION),
    AUTH_TOKEN_EXPIRED("SSI-5002", "Bearer token expired", ErrorCategory.AUTHENTICATION),
    AUTH_INVALID_CREDENTIALS("SSI-5003", "Invalid credentials presented", ErrorCategory.AUTHENTICATION),

    // Internal errors (9xxx)
    INTERNAL_SERIALIZATION("SSI-9001", "Failed to serialize/deserialize data", ErrorCategory.INTERNAL),
    INTERNAL_UNEXPECTED("SSI-9999", "Unexpected internal error", ErrorCategory.INTERNAL);

    private final String code;
    private final String message;
    private final ErrorCategory category;
    private final Boolean retryable;

    SSIErrorCode(String code, String message, ErrorCategory category) {
        this(code, message, category, null);
    }

    SSIErrorCode(String code, String message, ErrorCategory category, Boolean retryable) {
        this.code = code;
        this.message = message;
        this.category = category;
        this.retryable = retryable;
    }

    public String getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }

    public ErrorCategory getCategory() {
        return category;
    }

    /**
     * Checks if this error is retryable.
     * If specific retryable flag is set, use that; otherwise fall back to category default.
     */
    public boolean isRetryable() {
        if (retryable != null) {
            return retryable;
        }
        return category.isRetryable();
    }

    /**
     * Error categories for grouping and handling strategies.
     */
    public enum ErrorCategory {
        CONFIGURATION(false),
        NETWORK(true),
        BUSINESS_LOGIC(false),
        DID_COMMUNICATION(true),
        AUTHENTICATION(false),
        INTERNAL(false);

        private final boolean retryable;

        ErrorCategory(boolean retryable) {
            this.retryable = retryable;
        }

        public boolean isRetryable() {
            return retryable;
        }
    }
}

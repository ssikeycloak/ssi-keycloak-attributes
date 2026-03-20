package kodrat.keycloak.exception;

import kodrat.keycloak.util.LogSanitizer;

import java.util.HashMap;
import java.util.Map;

/**
 * Typed exception for SSI flow operations.
 * Provides structured error information with error codes, context, and retry guidance.
 */
public class SSIFlowException extends Exception {

    private final SSIErrorCode errorCode;
    private final String contextId;
    private final Map<String, Object> contextData;
    private final long timestamp;

    /**
     * Creates a new SSI flow exception.
     *
     * @param errorCode   the standardized error code
     * @param message     detailed error message
     * @param contextId   identifier for context (session ID, connection ID, etc.)
     * @param cause       the underlying cause
     */
    public SSIFlowException(SSIErrorCode errorCode, String message, String contextId, Throwable cause) {
        super(buildMessage(errorCode, message, contextId), cause);
        this.errorCode = errorCode;
        this.contextId = contextId;
        this.contextData = new HashMap<>();
        this.timestamp = System.currentTimeMillis();
    }

    /**
     * Creates a new SSI flow exception without cause.
     */
    public SSIFlowException(SSIErrorCode errorCode, String message, String contextId) {
        this(errorCode, message, contextId, null);
    }

    /**
     * Creates a new SSI flow exception with simple message.
     */
    public SSIFlowException(SSIErrorCode errorCode, String message) {
        this(errorCode, message, null, null);
    }

    /**
     * Factory method for configuration errors.
     */
    public static SSIFlowException configurationError(String configKey, String details) {
        SSIErrorCode code = SSIErrorCode.CONFIG_INVALID_JSON;
        if (configKey != null) {
            if (configKey.contains("endpoint")) {
                code = SSIErrorCode.CONFIG_MISSING_ENDPOINT;
            } else if (configKey.contains("token")) {
                code = SSIErrorCode.CONFIG_MISSING_TOKEN;
            } else if (configKey.contains("schema")) {
                code = SSIErrorCode.CONFIG_MISSING_SCHEMA;
            }
        }
        return new SSIFlowException(code, "Configuration error for '" + configKey + "': " + details, configKey);
    }

    /**
     * Factory method for connection errors.
     */
    public static SSIFlowException connectionError(Throwable cause, String endpoint) {
        SSIErrorCode code = SSIErrorCode.CONNECTION_REFUSED;
        String maskedEndpoint = endpoint != null ? LogSanitizer.maskInvitationUrl(endpoint) : "unknown";

        if (cause instanceof java.net.ConnectException) {
            code = SSIErrorCode.CONNECTION_REFUSED;
        } else if (cause instanceof java.net.http.HttpTimeoutException) {
            code = SSIErrorCode.CONNECTION_TIMEOUT;
        } else if (cause instanceof java.net.UnknownHostException) {
            code = SSIErrorCode.CONNECTION_DNS_FAILED;
        } else if (cause instanceof javax.net.ssl.SSLException) {
            code = SSIErrorCode.CONNECTION_SSL_ERROR;
        } else if (cause instanceof java.net.UnknownHostException) {
            code = SSIErrorCode.CONNECTION_UNKNOWN_HOST;
        }

        return new SSIFlowException(code, "Connection failed to " + maskedEndpoint, maskedEndpoint, cause);
    }

    /**
     * Factory method for flow errors.
     */
    public static SSIFlowException flowError(String currentState, String attemptedTransition) {
        return new SSIFlowException(
                SSIErrorCode.FLOW_INVALID_STATE,
                "Invalid state transition from '" + currentState + "' to '" + attemptedTransition + "'",
                currentState
        );
    }

    /**
     * Factory method for DIDComm errors.
     */
    public static SSIFlowException didCommError(String operation, String details, Throwable cause) {
        SSIErrorCode code = SSIErrorCode.DIDCOMM_INVALID_RESPONSE;

        if (operation != null) {
            switch (operation.toLowerCase()) {
                case "invitation":
                    code = SSIErrorCode.DIDCOMM_INVITATION_FAILED;
                    break;
                case "connection":
                    code = SSIErrorCode.DIDCOMM_CONNECTION_FAILED;
                    break;
                case "proof":
                    code = SSIErrorCode.DIDCOMM_PROOF_REQUEST_FAILED;
                    break;
                case "presentation":
                    code = SSIErrorCode.DIDCOMM_PRESENTATION_TIMEOUT;
                    break;
                case "verification":
                    code = SSIErrorCode.DIDCOMM_VERIFICATION_FAILED;
                    break;
            }
        }

        return new SSIFlowException(code, "DIDComm operation '" + operation + "' failed: " + details, operation, cause);
    }

    private static String buildMessage(SSIErrorCode errorCode, String message, String contextId) {
        StringBuilder sb = new StringBuilder();
        sb.append("[").append(errorCode.getCode()).append("] ");
        sb.append(errorCode.getMessage());
        if (message != null && !message.isEmpty()) {
            sb.append(" - ").append(LogSanitizer.redact(message));
        }
        if (contextId != null && !contextId.isEmpty()) {
            sb.append(" (context: ").append(LogSanitizer.maskIdentifier(contextId)).append(")");
        }
        return sb.toString();
    }

    public SSIErrorCode getErrorCode() {
        return errorCode;
    }

    public String getCode() {
        return errorCode.getCode();
    }

    public String getContextId() {
        return contextId;
    }

    public Map<String, Object> getContextData() {
        return Map.copyOf(contextData);
    }

    public SSIFlowException withContextData(String key, Object value) {
        if (value instanceof String) {
            this.contextData.put(key, LogSanitizer.redact((String) value));
        } else {
            this.contextData.put(key, value);
        }
        return this;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public boolean isRetryable() {
        return errorCode.isRetryable();
    }

    public SSIErrorCode.ErrorCategory getCategory() {
        return errorCode.getCategory();
    }

    /**
     * Converts to a Map for JSON serialization.
     */
    public Map<String, Object> toMap() {
        Map<String, Object> map = new HashMap<>();
        map.put("code", errorCode.getCode());
        map.put("message", getMessage());
        map.put("category", errorCode.getCategory().name());
        map.put("retryable", isRetryable());
        if (contextId != null) {
            map.put("contextId", LogSanitizer.maskIdentifier(contextId));
        }
        if (!contextData.isEmpty()) {
            map.put("context", contextData);
        }
        return map;
    }

    @Override
    public String toString() {
        return "SSIFlowException{" +
                "code='" + errorCode.getCode() + '\'' +
                ", message='" + getMessage() + '\'' +
                ", category=" + errorCode.getCategory() +
                ", retryable=" + isRetryable() +
                ", contextId='" + contextId + '\'' +
                '}';
    }
}

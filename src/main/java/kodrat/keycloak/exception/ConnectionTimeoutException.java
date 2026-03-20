package kodrat.keycloak.exception;

/**
 * Exception thrown when an SSI connection operation times out.
 * Use this when polling for connection establishment or verification
 * exceeds the maximum retry attempts.
 */
public class ConnectionTimeoutException extends SSIException {

    /**
     * Constructs a ConnectionTimeoutException with the specified message.
     *
     * @param message The detail message explaining the timeout error
     */
    public ConnectionTimeoutException(String message) {
        super(message);
    }

    /**
     * Constructs a ConnectionTimeoutException with the specified message and cause.
     *
     * @param message The detail message explaining the timeout error
     * @param cause The underlying cause of the timeout
     */
    public ConnectionTimeoutException(String message, Throwable cause) {
        super(message, cause);
    }
}

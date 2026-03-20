package kodrat.keycloak.exception;

/**
 * Exception thrown when SSI verification fails.
 * Use this when credential or presentation verification does not succeed,
 * such as invalid signatures, expired credentials, or failed policy checks.
 */
public class VerificationFailedException extends SSIException {

    /**
     * Constructs a VerificationFailedException with the specified message.
     *
     * @param message The detail message explaining the verification failure
     */
    public VerificationFailedException(String message) {
        super(message);
    }

    /**
     * Constructs a VerificationFailedException with the specified message and cause.
     *
     * @param message The detail message explaining the verification failure
     * @param cause The underlying cause of the verification failure
     */
    public VerificationFailedException(String message, Throwable cause) {
        super(message, cause);
    }
}

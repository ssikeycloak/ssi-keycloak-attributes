package kodrat.keycloak.exception;

/**
 * Base exception for all SSI (Self-Sovereign Identity) related errors.
 *
 * <p>This is the primary exception class for SSI authentication failures,
 * HTTP communication errors, and other SSI-specific error conditions.
 * It extends {@link RuntimeException} to allow unchecked throwing.
 *
 * <h2>Common Usage Scenarios</h2>
 * <ul>
 *   <li>HTTP request failures (connection refused, timeout, HTTP errors)</li>
 *   <li>JSON serialization/deserialization errors</li>
 *   <li>Verification failures</li>
 *   <li>Configuration errors</li>
 * </ul>
 *
 * <h2>Usage Example</h2>
 * <pre>{@code
 * // Throw with message only
 * throw new SSIException("Connection refused: SSI agent not running");
 *
 * // Throw with message and cause
 * try {
 *     httpClient.send(request);
 * } catch (IOException e) {
 *     throw new SSIException("Failed to communicate with SSI agent", e);
 * }
 * }</pre>
 *
 * <h2>Subclasses</h2>
 * <p>For more specific error types, see:
 * <ul>
 *   <li>{@link ConnectionTimeoutException} - Polling timeout errors</li>
 *   <li>{@link VerificationFailedException} - Credential verification failures</li>
 * </ul>
 *
 * @see ConnectionTimeoutException
 * @see VerificationFailedException
 * @since 1.0.0
 * @author Kodrat Development Team
 */
public class SSIException extends RuntimeException {

    /**
     * Constructs a new SSIException with the specified detail message.
     *
     * @param message the detail message explaining the error; should be
     *                descriptive enough for debugging but avoid including
     *                sensitive data (tokens, credentials)
     */
    public SSIException(String message) {
        super(message);
    }

    /**
     * Constructs a new SSIException with the specified detail message and cause.
     *
     * @param message the detail message explaining the error
     * @param cause the underlying cause of this exception; may be {@code null}
     *              if the cause is unknown or nonexistent
     */
    public SSIException(String message, Throwable cause) {
        super(message, cause);
    }
}

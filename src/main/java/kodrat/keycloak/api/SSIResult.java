package kodrat.keycloak.api;

import java.util.HashMap;
import java.util.Map;

/**
 * Encapsulates the result of a DID method operation, primarily from
 * {@link DIDMethod#sendProofRequest(org.keycloak.sessions.AuthenticationSessionModel)}.
 *
 * <p>This class provides a standardized way to communicate operation outcomes between
 * DID method implementations and the authentication flow orchestrator. It supports
 * both simple success/failure scenarios and complex results with additional metadata.
 *
 * <h2>Result States</h2>
 * <p>An SSIResult can represent several states:
 * <ul>
 *   <li><strong>Ready (done=true):</strong> Operation completed successfully, ready
 *       for the next step (e.g., verification)</li>
 *   <li><strong>Not Ready (done=false):</strong> Operation pending or failed, not
 *       ready to proceed. Check the message for details.</li>
 * </ul>
 *
 * <h2>Result Fields</h2>
 * <table border="1">
 *   <caption>Result Field Descriptions</caption>
 *   <tr><th>Field</th><th>Type</th><th>Description</th></tr>
 *   <tr><td>{@code done}</td><td>boolean</td><td>Whether the operation completed successfully</td></tr>
 *   <tr><td>{@code presExId}</td><td>String</td><td>Presentation exchange ID (ACA-Py specific)</td></tr>
 *   <tr><td>{@code connectionId}</td><td>String</td><td>Connection ID (ACA-Py specific)</td></tr>
 *   <tr><td>{@code extra}</td><td>Map</td><td>Additional metadata (extensible)</td></tr>
 *   <tr><td>{@code message}</td><td>String</td><td>Human-readable status or error message</td></tr>
 * </table>
 *
 * <h2>Usage Examples</h2>
 *
 * <h3>Creating Results</h3>
 * <pre>{@code
 * // Simple success
 * SSIResult success = SSIResult.success();
 *
 * // Success with IDs (for connection-based methods)
 * SSIResult withIds = SSIResult.success("pres-ex-123", "conn-456");
 *
 * // Success with extra metadata
 * SSIResult withExtra = SSIResult.success(null, null,
 *     Map.of("authorizationUrl", "openid4vp://..."), "Proof request initiated");
 *
 * // Not ready (e.g., connection pending)
 * SSIResult pending = SSIResult.notReady("Connection not yet established");
 * }</pre>
 *
 * <h3>Consuming Results</h3>
 * <pre>{@code
 * SSIResult result = didMethod.sendProofRequest(session);
 * if (result.isDone()) {
 *     // Proceed to verification
 *     String presExId = result.getPresExId();
 *     Map<String, Object> metadata = result.getExtra();
 * } else {
 *     // Handle pending state
 *     String reason = result.getMessage();
 *     logger.warning("Proof request not ready: " + reason);
 * }
 * }</pre>
 *
 * <h3>Builder Pattern</h3>
 * <pre>{@code
 * SSIResult result = SSIResult.success()
 *     .withExtra("step", "proof-requested")
 *     .withExtra("timestamp", System.currentTimeMillis());
 * }</pre>
 *
 * <h2>Thread Safety</h2>
 * <p>This class is <strong>not thread-safe</strong>. The {@link #withExtra(String, Object)}
 * method modifies the internal extra map. For concurrent access, create separate
 * instances or use defensive copying.
 *
 * <h2>Implementation Notes</h2>
 * <p>The {@code presExId} and {@code connectionId} fields are specific to ACA-Py
 * (Aries Cloud Agent Python) implementations. Other DID methods may leave these
 * as {@code null} and use the {@code extra} map for method-specific identifiers.
 *
 * @see DIDMethod#sendProofRequest(org.keycloak.sessions.AuthenticationSessionModel)
 * @see AbstractDIDMethod
 * @since 1.0.0
 * @author Kodrat Development Team
 */
public class SSIResult {

    /**
     * Indicates whether the operation completed successfully and the flow can proceed.
     *
     * <p>When {@code true}, the authentication flow can proceed to the next step
     * (typically credential verification). When {@code false}, the operation is
     * either still in progress or has failed; check {@link #getMessage()} for details.
     */
    private final boolean done;

    /**
     * The presentation exchange ID returned by ACA-Py.
     *
     * <p>This identifier is used to track the proof presentation lifecycle in
     * connection-based methods like did:sov. May be {@code null} for connectionless
     * methods like did:web.
     */
    private final String presExId;

    /**
     * The connection ID for the established DIDComm connection.
     *
     * <p>This identifier represents the connection between the verifier (Keycloak)
     * and the prover (wallet). Used primarily in connection-based methods like did:sov.
     */
    private final String connectionId;

    /**
     * Additional metadata returned by the operation.
     *
     * <p>This extensible map allows DID method implementations to return
     * method-specific data such as authorization URLs, state IDs, or timestamps.
     */
    private final Map<String, Object> extra;

    /**
     * Human-readable message describing the result.
     *
     * <p>For successful operations, this may be a simple "OK". For failures or
     * pending states, this contains a descriptive reason.
     */
    private final String message;

    /**
     * Constructs a new SSIResult with all fields.
     *
     * <p>This constructor is typically not called directly. Use factory methods
     * like {@link #success()} or {@link #notReady(String)} instead.
     *
     * @param done whether the operation completed successfully
     * @param presExId the presentation exchange ID, may be {@code null}
     * @param connectionId the connection ID, may be {@code null}
     * @param extra additional metadata, may be {@code null} (converted to empty map)
     * @param message human-readable status message, may be {@code null}
     */
    public SSIResult(boolean done, String presExId, String connectionId, Map<String, Object> extra, String message) {
        this.done = done;
        this.presExId = presExId;
        this.connectionId = connectionId;
        this.extra = extra != null ? extra : new HashMap<>();
        this.message = message;
    }

    /**
     * Creates a result indicating the operation is not ready to proceed.
     *
     * <p>Use this factory method when:
     * <ul>
     *   <li>A connection has not yet been established</li>
     *   <li>A proof request failed to send</li>
     *   <li>An error occurred during the operation</li>
     * </ul>
     *
     * @param message the reason why the operation is not ready; if null or blank,
     *                defaults to "Not ready"
     * @return an SSIResult with {@code done=false} and the specified message
     */
    public static SSIResult notReady(String message) {
        String resolvedMessage = (message == null || message.isBlank()) ? "Not ready" : message;
        return new SSIResult(false, null, null, null, resolvedMessage);
    }

    /**
     * Creates a simple success result with no identifiers.
     *
     * <p>Use this factory method for connectionless methods (like did:web) that
     * don't require presentation exchange or connection IDs.
     *
     * @return an SSIResult with {@code done=true} and message "OK"
     */
    public static SSIResult success() {
        return new SSIResult(true, null, null, null, "OK");
    }

    /**
     * Creates a success result with presentation and connection identifiers.
     *
     * <p>Use this factory method for connection-based methods (like did:sov) that
     * track presentations via exchange IDs.
     *
     * @param presExId the presentation exchange ID from ACA-Py, may be {@code null}
     * @param connectionId the connection ID from ACA-Py, may be {@code null}
     * @return an SSIResult with {@code done=true} and the specified identifiers
     */
    public static SSIResult success(String presExId, String connectionId) {
        return new SSIResult(true, presExId, connectionId, null, "OK");
    }

    /**
     * Creates a success result with all available data.
     *
     * <p>Use this factory method when you need to include additional metadata
     * along with the success status.
     *
     * @param presExId the presentation exchange ID, may be {@code null}
     * @param connectionId the connection ID, may be {@code null}
     * @param extra additional metadata to include in the result
     * @param message a custom success message
     * @return an SSIResult with {@code done=true} and all specified data
     */
    public static SSIResult success(String presExId, String connectionId, Map<String, Object> extra, String message) {
        return new SSIResult(true, presExId, connectionId, extra, message);
    }

    /**
     * Adds an additional metadata entry to this result.
     *
     * <p>This method follows a builder pattern, allowing chaining:
     * <pre>{@code
     * SSIResult result = SSIResult.success()
     *     .withExtra("step", "proof-requested")
     *     .withExtra("timestamp", Instant.now());
     * }</pre>
     *
     * <p><strong>Note:</strong> This method modifies the internal extra map in place.
     * The returned reference is {@code this} for chaining convenience.
     *
     * @param key the metadata key
     * @param value the metadata value
     * @return this SSIResult instance for method chaining
     */
    public SSIResult withExtra(String key, Object value) {
        this.extra.put(key, value);
        return this;
    }

    /**
     * Returns whether the operation completed successfully.
     *
     * @return {@code true} if ready to proceed, {@code false} otherwise
     */
    public boolean isDone() {
        return done;
    }

    /**
     * Returns the presentation exchange ID.
     *
     * @return the presentation exchange ID, or {@code null} if not applicable
     */
    public String getPresExId() {
        return presExId;
    }

    /**
     * Returns the connection ID.
     *
     * @return the connection ID, or {@code null} if not applicable
     */
    public String getConnectionId() {
        return connectionId;
    }

    /**
     * Returns the additional metadata map.
     *
     * <p>The returned map is mutable and can be modified directly or via
     * {@link #withExtra(String, Object)}.
     *
     * @return the extra metadata map, never {@code null}
     */
    public Map<String, Object> getExtra() {
        return extra;
    }

    /**
     * Returns the human-readable status message.
     *
     * @return the message, may be {@code null}
     */
    public String getMessage() {
        return message;
    }

    /**
     * Returns a string representation of this result for debugging.
     *
     * @return a string containing all field values
     */
    @Override
    public String toString() {
        return "SSIResult{" +
                "done=" + done +
                ", presExId='" + presExId + '\'' +
                ", connectionId='" + connectionId + '\'' +
                ", extra=" + extra +
                ", message='" + message + '\'' +
                '}';
    }
}

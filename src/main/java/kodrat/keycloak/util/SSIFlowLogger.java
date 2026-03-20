package kodrat.keycloak.util;

import org.jboss.logging.Logger;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Utility for consistent, correlated logging across SSI authentication flows.
 *
 * <p>This class provides structured logging with correlation IDs (session ID, tab ID)
 * for end-to-end traceability of SSI authentication flows. All log messages follow
 * a consistent format that can be parsed by log aggregation systems.
 *
 * <h2>Log Format</h2>
 * <p>All log messages follow this format:
 * <pre>
 * [SSI-FLOW] event={event} session={sessionId} tab={tabId} ts={timestamp} msg="{message}" {context}
 * </pre>
 *
 * <h2>Event Types</h2>
 * <table border="1">
 *   <caption>Available Event Types</caption>
 *   <tr><th>Event</th><th>Log Level</th><th>Description</th></tr>
 *   <tr><td>{@code start}</td><td>INFO</td><td>Flow started</td></tr>
 *   <tr><td>{@code wait}</td><td>INFO</td><td>Waiting for connection/presentation</td></tr>
 *   <tr><td>{@code connect}</td><td>INFO</td><td>Connection established</td></tr>
 *   <tr><td>{@code proof-request}</td><td>INFO</td><td>Proof request sent</td></tr>
 *   <tr><td>{@code verify}</td><td>INFO</td><td>Verification completed</td></tr>
 *   <tr><td>{@code retry}</td><td>INFO</td><td>User requested retry</td></tr>
 *   <tr><td>{@code reset}</td><td>INFO</td><td>Flow state reset</td></tr>
 *   <tr><td>{@code success}</td><td>INFO</td><td>Authentication succeeded</td></tr>
 *   <tr><td>{@code failure}</td><td>WARN</td><td>Authentication failed</td></tr>
 *   <tr><td>{@code timeout}</td><td>WARN</td><td>Polling timeout</td></tr>
 *   <tr><td>{@code terminal}</td><td>WARN</td><td>Non-recoverable error</td></tr>
 * </table>
 *
 * <h2>Usage Example</h2>
 * <pre>{@code
 * // Log flow start
 * SSIFlowLogger.logStart(session, "web");
 * 
 * // Log connection with context
 * SSIFlowLogger.logConnect(session, connectionId);
 * 
 * // Log verification result
 * SSIFlowLogger.logVerify(session, true, 5);
 * 
 * // Log custom event with context
 * Map<String, Object> context = new HashMap<>();
 * context.put("reason", "invalid_credential");
 * SSIFlowLogger.logEvent(session, SSIFlowLogger.EVENT_FAILURE, "Verification failed", context);
 * }</pre>
 *
 * <h2>Log Level Policy</h2>
 * <ul>
 *   <li>INFO: Normal flow events (start, wait, connect, verify, success, retry, reset)</li>
 *   <li>WARN: Failure events (failure, timeout, terminal)</li>
 * </ul>
 *
 * <h2>Thread Safety</h2>
 * <p>This class is stateless and all methods are static. It is safe to call from
 * multiple threads concurrently.
 *
 * @see LogSanitizer
 * @see SSIStateResetService
 * @since 1.0.0
 * @author Kodrat Development Team
 */
public final class SSIFlowLogger {
    
    private static final Logger LOGGER = Logger.getLogger(SSIFlowLogger.class);
    
    /** Event type for flow start. */
    public static final String EVENT_START = "start";
    
    /** Event type for waiting state. */
    public static final String EVENT_WAIT = "wait";
    
    /** Event type for connection established. */
    public static final String EVENT_CONNECT = "connect";
    
    /** Event type for proof request sent. */
    public static final String EVENT_PROOF_REQUEST = "proof-request";
    
    /** Event type for verification completed. */
    public static final String EVENT_VERIFY = "verify";
    
    /** Event type for retry requested. */
    public static final String EVENT_RETRY = "retry";
    
    /** Event type for flow reset. */
    public static final String EVENT_RESET = "reset";
    
    /** Event type for successful completion. */
    public static final String EVENT_SUCCESS = "success";
    
    /** Event type for failure. */
    public static final String EVENT_FAILURE = "failure";
    
    /** Event type for timeout. */
    public static final String EVENT_TIMEOUT = "timeout";
    
    /** Event type for terminal (non-recoverable) error. */
    public static final String EVENT_TERMINAL = "terminal";
    
    /**
     * Private constructor to prevent instantiation.
     * This is a utility class with only static methods.
     */
    private SSIFlowLogger() {
    }
    
    /**
     * Logs a flow event with correlation IDs from the authentication session.
     *
     * @param session the authentication session for correlation IDs
     * @param event the event type (use the EVENT_* constants)
     * @param message a human-readable message describing the event
     */
    public static void logEvent(AuthenticationSessionModel session, String event, String message) {
        logEvent(session, event, message, null);
    }
    
    /**
     * Logs a flow event with correlation IDs and additional context.
     *
     * <p>The context map is converted to key=value pairs in the log message.
     * Values are redacted using {@link LogSanitizer#redact(String)}.
     *
     * @param session the authentication session for correlation IDs
     * @param event the event type (use the EVENT_* constants)
     * @param message a human-readable message describing the event
     * @param context additional context key-value pairs; may be {@code null}
     */
    public static void logEvent(AuthenticationSessionModel session, String event, String message, Map<String, Object> context) {
        String sessionId = session.getParentSession() != null 
                ? LogSanitizer.maskIdentifier(session.getParentSession().getId()) 
                : "unknown";
        String tabId = LogSanitizer.maskIdentifier(session.getTabId());
        
        StringBuilder logBuilder = new StringBuilder();
        logBuilder.append("[SSI-FLOW] ")
                .append("event=").append(event)
                .append(" session=").append(sessionId)
                .append(" tab=").append(tabId)
                .append(" ts=").append(Instant.now().toString())
                .append(" msg=\"").append(message).append("\"");
        
        if (context != null && !context.isEmpty()) {
            for (Map.Entry<String, Object> entry : context.entrySet()) {
                String key = entry.getKey();
                Object value = entry.getValue();
                String safeValue = value != null ? LogSanitizer.redact(String.valueOf(value)) : "null";
                logBuilder.append(" ").append(key).append("=").append(safeValue);
            }
        }
        
        if (EVENT_FAILURE.equals(event) || EVENT_TIMEOUT.equals(event) || EVENT_TERMINAL.equals(event)) {
            LOGGER.warn(logBuilder.toString());
        } else if (EVENT_RETRY.equals(event) || EVENT_RESET.equals(event)) {
            LOGGER.info(logBuilder.toString());
        } else {
            LOGGER.info(logBuilder.toString());
        }
    }
    
    /**
     * Logs a flow start event.
     *
     * @param session the authentication session
     * @param didMethod the DID method being used (e.g., "web", "sov")
     */
    public static void logStart(AuthenticationSessionModel session, String didMethod) {
        Map<String, Object> context = new HashMap<>();
        context.put("didMethod", didMethod);
        logEvent(session, EVENT_START, "SSI authentication flow started", context);
    }
    
    /**
     * Logs a connection waiting event.
     *
     * @param session the authentication session
     * @param waitReason the reason for waiting (e.g., "connection", "presentation")
     */
    public static void logWait(AuthenticationSessionModel session, String waitReason) {
        Map<String, Object> context = new HashMap<>();
        context.put("reason", waitReason);
        logEvent(session, EVENT_WAIT, "Waiting for " + waitReason, context);
    }
    
    /**
     * Logs a connection established event.
     *
     * @param session the authentication session
     * @param connectionId the connection ID (will be masked in logs)
     */
    public static void logConnect(AuthenticationSessionModel session, String connectionId) {
        Map<String, Object> context = new HashMap<>();
        context.put("connectionId", LogSanitizer.maskIdentifier(connectionId));
        logEvent(session, EVENT_CONNECT, "Connection established", context);
    }
    
    /**
     * Logs a proof request sent event.
     *
     * @param session the authentication session
     * @param presExId the presentation exchange ID (will be masked in logs)
     */
    public static void logProofRequest(AuthenticationSessionModel session, String presExId) {
        Map<String, Object> context = new HashMap<>();
        context.put("presExId", LogSanitizer.maskIdentifier(presExId));
        logEvent(session, EVENT_PROOF_REQUEST, "Proof request sent", context);
    }
    
    /**
     * Logs a verification event with result.
     *
     * @param session the authentication session
     * @param success whether verification succeeded
     * @param claimsCount the number of claims extracted
     */
    public static void logVerify(AuthenticationSessionModel session, boolean success, int claimsCount) {
        Map<String, Object> context = new HashMap<>();
        context.put("success", success);
        context.put("claimsCount", claimsCount);
        logEvent(session, EVENT_VERIFY, "Presentation verification " + (success ? "succeeded" : "failed"), context);
    }
    
    /**
     * Logs a retry request event.
     *
     * @param session the authentication session
     * @param previousStatus the status before retry was requested
     */
    public static void logRetry(AuthenticationSessionModel session, String previousStatus) {
        Map<String, Object> context = new HashMap<>();
        context.put("previousStatus", previousStatus);
        logEvent(session, EVENT_RETRY, "Retry requested by user", context);
    }
    
    /**
     * Logs a flow reset event.
     *
     * @param session the authentication session
     * @param newFlowId the new flow ID assigned (will be masked in logs)
     * @param source the source of the reset (e.g., "api", "form")
     */
    public static void logReset(AuthenticationSessionModel session, String newFlowId, String source) {
        Map<String, Object> context = new HashMap<>();
        context.put("newFlowId", LogSanitizer.maskIdentifier(newFlowId));
        context.put("source", source);
        logEvent(session, EVENT_RESET, "Flow state reset", context);
    }
    
    /**
     * Logs a successful completion event.
     *
     * @param session the authentication session
     * @param claimsCount the number of claims extracted
     */
    public static void logSuccess(AuthenticationSessionModel session, int claimsCount) {
        Map<String, Object> context = new HashMap<>();
        context.put("claimsCount", claimsCount);
        logEvent(session, EVENT_SUCCESS, "SSI authentication completed successfully", context);
    }
    
    /**
     * Logs a failure event.
     *
     * @param session the authentication session
     * @param reason the reason for failure
     * @param errorCode the error code (from {@link kodrat.keycloak.constant.SSIReasonCode})
     */
    public static void logFailure(AuthenticationSessionModel session, String reason, String errorCode) {
        Map<String, Object> context = new HashMap<>();
        context.put("reason", reason);
        context.put("errorCode", errorCode);
        logEvent(session, EVENT_FAILURE, "SSI authentication failed: " + reason, context);
    }
    
    /**
     * Logs a timeout event.
     *
     * @param session the authentication session
     * @param attempts the number of polling attempts made
     */
    public static void logTimeout(AuthenticationSessionModel session, int attempts) {
        Map<String, Object> context = new HashMap<>();
        context.put("attempts", attempts);
        logEvent(session, EVENT_TIMEOUT, "Polling timeout reached", context);
    }
    
    /**
     * Logs a terminal (non-recoverable) error event.
     *
     * @param session the authentication session
     * @param reason the reason for the terminal error
     */
    public static void logTerminal(AuthenticationSessionModel session, String reason) {
        Map<String, Object> context = new HashMap<>();
        context.put("reason", reason);
        logEvent(session, EVENT_TERMINAL, "Terminal error: " + reason, context);
    }
}

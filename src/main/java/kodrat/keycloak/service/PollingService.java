package kodrat.keycloak.service;

import kodrat.keycloak.constant.HTTPConstants;
import kodrat.keycloak.exception.ConnectionTimeoutException;

import java.util.Optional;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;
import java.util.logging.Logger;

/**
 * Service for polling operations with retry logic and configurable delays.
 *
 * <p>This service provides utility methods for polling asynchronous operations
 * until they complete or a timeout is reached. It supports both result-returning
 * operations (via {@link Optional}) and boolean conditions.
 *
 * <h2>Polling Strategies</h2>
 * <table border="1">
 *   <caption>Available Polling Methods</caption>
 *   <tr><th>Method</th><th>Return Type</th><th>Use Case</th></tr>
 *   <tr><td>{@link #pollWithRetry(String, Supplier)}</td><td>T</td><td>Poll until result available</td></tr>
 *   <tr><td>{@link #pollUntil(String, BooleanSupplier)}</td><td>boolean</td><td>Poll until condition true</td></tr>
 * </table>
 *
 * <h2>Default Settings</h2>
 * <p>Default retry settings from {@link HTTPConstants}:
 * <ul>
 *   <li>Max attempts: 30</li>
 *   <li>Delay between attempts: 1000ms</li>
 *   <li>Total timeout: ~30 seconds</li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 * <pre>{@code
 * // Poll for result
 * Boolean result = PollingService.pollWithRetry(
 *     "Verification",
 *     () -> {
 *         if (isVerified(session)) return Optional.of(true);
 *         if (hasFailed(session)) return Optional.of(false);
 *         return Optional.empty();
 *     }
 * );
 *
 * // Poll until condition
 * boolean connected = PollingService.pollUntil(
 *     "Connection",
 *     () -> method.isConnectionEstablished(session)
 * );
 *
 * // Custom retry settings
 * String result = PollingService.pollWithRetry(
 *     "Custom",
 *     operation,
 *     10,    // max attempts
 *     500    // delay ms
 * );
 * }</pre>
 *
 * <h2>Error Handling</h2>
 * <ul>
 *   <li>Exceptions during polling are logged but don't stop retries</li>
 *   <li>Thread interruption is handled gracefully</li>
 *   <li>Timeout throws {@link ConnectionTimeoutException}</li>
 * </ul>
 *
 * <h2>Thread Safety</h2>
 * <p>This class is stateless and all methods are static. It is safe to call from
 * multiple threads concurrently.
 *
 * @see ConnectionTimeoutException
 * @see HTTPConstants
 * @since 1.0.0
 * @author Kodrat Development Team
 */
public class PollingService {
    
    private static final Logger LOGGER = Logger.getLogger(PollingService.class.getName());

    /**
     * Private constructor to prevent instantiation.
     * This is a utility class with only static methods.
     */
    private PollingService() {
    }

    /**
     * Polls an operation until it returns a result or max attempts are reached.
     *
     * <p>This method repeatedly calls the operation supplier until it returns
     * a non-empty Optional or the maximum number of attempts is exhausted.
     * Exceptions during individual attempts are logged but don't stop polling.
     *
     * @param <T> the type of result to return
     * @param operationName a descriptive name for logging purposes
     * @param operation the operation to poll; should return {@link Optional#empty()}
     *                  if not ready, or {@link Optional#of(Object)} with the result
     * @param maxAttempts the maximum number of polling attempts
     * @param delayMs the delay in milliseconds between attempts
     * @return the result when the operation succeeds
     * @throws ConnectionTimeoutException if max attempts are exceeded without a result
     * @throws ConnectionTimeoutException if the polling thread is interrupted
     */
    public static <T> T pollWithRetry(
            String operationName,
            Supplier<Optional<T>> operation,
            int maxAttempts,
            int delayMs) throws ConnectionTimeoutException {
        
        LOGGER.info("[" + operationName + "] Starting polling with max " + maxAttempts + 
                " attempts, " + delayMs + "ms delay");
        
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            LOGGER.info("[" + operationName + "] Attempt " + attempt + "/" + maxAttempts);
            
            try {
                Optional<T> result = operation.get();
                
                if (result.isPresent()) {
                    LOGGER.info("[" + operationName + "] Operation completed successfully on attempt " + attempt);
                    return result.get();
                }
                
                LOGGER.fine("[" + operationName + "] Result not ready yet, will retry");
                
            } catch (Exception e) {
                LOGGER.warning("[" + operationName + "] Exception during attempt " + attempt + ": " + e.getMessage());
            }
            
            if (attempt < maxAttempts) {
                try {
                    Thread.sleep(delayMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new ConnectionTimeoutException(
                            "[" + operationName + "] Polling interrupted during attempt " + attempt, e);
                }
            }
        }
        
        String message = "[" + operationName + "] Operation timed out after " + maxAttempts + 
                " attempts (" + (maxAttempts * delayMs / 1000) + " seconds)";
        LOGGER.warning(message);
        throw new ConnectionTimeoutException(message);
    }

    /**
     * Polls an operation until it returns a result using default retry settings.
     *
     * <p>Uses default settings from {@link HTTPConstants#MAX_RETRIES} and
     * {@link HTTPConstants#POLLING_DELAY_MS}.
     *
     * @param <T> the type of result to return
     * @param operationName a descriptive name for logging purposes
     * @param operation the operation to poll
     * @return the result when the operation succeeds
     * @throws ConnectionTimeoutException if max attempts are exceeded without a result
     */
    public static <T> T pollWithRetry(
            String operationName,
            Supplier<Optional<T>> operation) throws ConnectionTimeoutException {
        return pollWithRetry(operationName, operation, HTTPConstants.MAX_RETRIES, HTTPConstants.POLLING_DELAY_MS);
    }

    /**
     * Polls until a condition becomes true or max attempts are reached.
     *
     * <p>This method repeatedly checks the condition until it returns {@code true}
     * or the maximum number of attempts is exhausted. Unlike {@link #pollWithRetry},
     * this method returns {@code false} on timeout rather than throwing an exception.
     *
     * @param operationName a descriptive name for logging purposes
     * @param condition the boolean condition to check
     * @param maxAttempts the maximum number of polling attempts
     * @param delayMs the delay in milliseconds between attempts
     * @return {@code true} if the condition becomes true, {@code false} if max
     *         attempts exceeded or polling is interrupted
     */
    public static boolean pollUntil(
            String operationName,
            BooleanSupplier condition,
            int maxAttempts,
            int delayMs) {
        
        LOGGER.info("[" + operationName + "] Starting condition polling with max " + maxAttempts + 
                " attempts, " + delayMs + "ms delay");
        
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            LOGGER.info("[" + operationName + "] Checking condition, attempt " + attempt + "/" + maxAttempts);
            
            try {
                if (condition.getAsBoolean()) {
                    LOGGER.info("[" + operationName + "] Condition met on attempt " + attempt);
                    return true;
                }
                
                LOGGER.fine("[" + operationName + "] Condition not met, will retry");
                
            } catch (Exception e) {
                LOGGER.warning("[" + operationName + "] Exception during condition check (attempt " + 
                        attempt + "): " + e.getMessage());
            }
            
            if (attempt < maxAttempts) {
                try {
                    Thread.sleep(delayMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    LOGGER.warning("[" + operationName + "] Polling interrupted during attempt " + attempt);
                    return false;
                }
            }
        }
        
        LOGGER.warning("[" + operationName + "] Condition not met after " + maxAttempts + 
                " attempts (" + (maxAttempts * delayMs / 1000) + " seconds)");
        return false;
    }

    /**
     * Polls until a condition becomes true using default retry settings.
     *
     * <p>Uses default settings from {@link HTTPConstants#MAX_RETRIES} and
     * {@link HTTPConstants#POLLING_DELAY_MS}.
     *
     * @param operationName a descriptive name for logging purposes
     * @param condition the boolean condition to check
     * @return {@code true} if the condition becomes true, {@code false} otherwise
     */
    public static boolean pollUntil(
            String operationName,
            BooleanSupplier condition) {
        return pollUntil(operationName, condition, HTTPConstants.MAX_RETRIES, HTTPConstants.POLLING_DELAY_MS);
    }
}

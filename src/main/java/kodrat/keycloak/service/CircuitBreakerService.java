package kodrat.keycloak.service;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;
import io.github.resilience4j.retry.RetryRegistry;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

/**
 * Singleton service for managing circuit breakers and retry policies for SSI agent communication.
 *
 * <p>This service provides resilience patterns to protect the SSI authenticator from
 * cascading failures when the SSI agent (e.g., ACA-Py) becomes unavailable or
 * experiences high latency. It implements the Circuit Breaker pattern to fail fast
 * during outages and the Retry pattern to handle transient failures.
 *
 * <h2>Circuit Breaker Configuration</h2>
 * <table border="1">
 *   <caption>Circuit Breaker Settings</caption>
 *   <tr><th>Setting</th><th>Value</th><th>Description</th></tr>
 *   <tr><td>Failure Rate Threshold</td><td>50%</td><td>Opens when 50% of calls fail</td></tr>
 *   <tr><td>Wait Duration (Open)</td><td>30s</td><td>Time before attempting recovery</td></tr>
 *   <tr><td>Sliding Window Size</td><td>10 calls</td><td>Number of calls for rate calculation</td></tr>
 *   <tr><td>Minimum Calls</td><td>5</td><td>Minimum calls before rate calculation</td></tr>
 *   <tr><td>Slow Call Threshold</td><td>30s</td><td>Calls slower than this are "slow"</td></tr>
 *   <tr><td>Slow Call Rate Threshold</td><td>80%</td><td>Opens when 80% of calls are slow</td></tr>
 *   <tr><td>Half-Open Permitted Calls</td><td>3</td><td>Calls allowed in half-open state</td></tr>
 * </table>
 *
 * <h2>Retry Configuration</h2>
 * <table border="1">
 *   <caption>Retry Settings</caption>
 *   <tr><th>Setting</th><th>Value</th><th>Description</th></tr>
 *   <tr><td>Max Attempts</td><td>3</td><td>Total attempts including initial</td></tr>
 *   <tr><td>Wait Duration</td><td>500ms</td><td>Delay between retry attempts</td></tr>
 * </table>
 *
 * <h2>Retryable Conditions</h2>
 * <p>Retries are attempted for the following error conditions:
 * <ul>
 *   <li>Connection refused (agent not running)</li>
 *   <li>Timeout (agent not responding)</li>
 *   <li>HTTP 502 Bad Gateway</li>
 *   <li>HTTP 503 Service Unavailable</li>
 *   <li>HTTP 429 Too Many Requests</li>
 * </ul>
 *
 * <h2>Circuit Breaker States</h2>
 * <ul>
 *   <li><strong>CLOSED:</strong> Normal operation - all requests pass through</li>
 *   <li><strong>OPEN:</strong> Failing fast - all requests are rejected immediately</li>
 *   <li><strong>HALF_OPEN:</strong> Testing recovery - limited requests allowed through</li>
 * </ul>
 *
 * <h2>Usage Example</h2>
 * <pre>{@code
 * CircuitBreakerService service = CircuitBreakerService.getInstance();
 * 
 * // Get circuit breaker for an endpoint
 * CircuitBreaker cb = service.getCircuitBreaker("ssi-http-client");
 * 
 * // Check state
 * if (cb.getState() == CircuitBreaker.State.OPEN) {
 *     // SSI agent is unavailable
 * }
 * 
 * // Get retry policy
 * Retry retry = service.getRetry("ssi-http-client");
 * 
 * // Check health status
 * String health = service.getHealthStatus();
 * }</pre>
 *
 * <h2>Thread Safety</h2>
 * <p>This class is thread-safe. The singleton instance can be safely accessed from
 * multiple threads. Internal state uses concurrent collections and atomic variables.
 *
 * @see HttpClientService
 * @since 1.0.0
 * @author Kodrat Development Team
 */
public final class CircuitBreakerService {
    
    private static final Logger LOGGER = Logger.getLogger(CircuitBreakerService.class.getName());
    
    private static final CircuitBreakerService INSTANCE = new CircuitBreakerService();
    
    private final CircuitBreakerRegistry circuitBreakerRegistry;
    private final RetryRegistry retryRegistry;
    private final ConcurrentHashMap<String, AtomicLong> failureCounters = new ConcurrentHashMap<>();
    
    /**
     * Private constructor for singleton pattern.
     * Initializes circuit breaker and retry registries with default configuration.
     */
    private CircuitBreakerService() {
        CircuitBreakerConfig circuitBreakerConfig = CircuitBreakerConfig.custom()
            .failureRateThreshold(50)
            .waitDurationInOpenState(Duration.ofSeconds(30))
            .permittedNumberOfCallsInHalfOpenState(3)
            .slidingWindowSize(10)
            .slidingWindowType(CircuitBreakerConfig.SlidingWindowType.COUNT_BASED)
            .minimumNumberOfCalls(5)
            .slowCallDurationThreshold(Duration.ofSeconds(30))
            .slowCallRateThreshold(80)
            .build();
        
        this.circuitBreakerRegistry = CircuitBreakerRegistry.of(circuitBreakerConfig);
        
        RetryConfig retryConfig = RetryConfig.custom()
            .maxAttempts(3)
            .waitDuration(Duration.ofMillis(500))
            .retryOnException(e -> isRetryable(e))
            .build();
        
        this.retryRegistry = RetryRegistry.of(retryConfig);
        
        LOGGER.info("[CircuitBreakerService] Initialized with failureRateThreshold=50%, waitDuration=30s, slidingWindow=10");
    }
    
    /**
     * Returns the singleton instance of the circuit breaker service.
     *
     * @return the singleton CircuitBreakerService instance
     */
    public static CircuitBreakerService getInstance() {
        return INSTANCE;
    }
    
    /**
     * Gets or creates a circuit breaker with the specified name.
     *
     * <p>Circuit breakers are shared across all HTTP calls using the same name,
     * providing coordinated failure protection. Event listeners are registered
     * for state transitions, errors, and successes.
     *
     * @param name the unique name for the circuit breaker (e.g., "ssi-http-client")
     * @return the CircuitBreaker instance for the given name
     */
    public CircuitBreaker getCircuitBreaker(String name) {
        CircuitBreaker circuitBreaker = circuitBreakerRegistry.circuitBreaker(name);
        
        circuitBreaker.getEventPublisher()
            .onStateTransition(event -> {
                LOGGER.warning("[CircuitBreaker:" + name + "] State transition: " + 
                    event.getStateTransition().getFromState() + " -> " + 
                    event.getStateTransition().getToState());
            })
            .onError(event -> {
                LOGGER.warning("[CircuitBreaker:" + name + "] Call failed: " + 
                    event.getThrowable().getMessage());
                incrementFailureCounter(name);
            })
            .onSuccess(event -> {
                LOGGER.fine("[CircuitBreaker:" + name + "] Call succeeded in " + 
                    event.getElapsedDuration().toMillis() + "ms");
            });
        
        return circuitBreaker;
    }
    
    /**
     * Gets or creates a retry policy with the specified name.
     *
     * <p>Retry policies are configured to attempt up to 3 retries with 500ms
     * delay for transient errors. Event listeners are registered for retry
     * attempts and exhaustion.
     *
     * @param name the unique name for the retry policy (e.g., "ssi-http-client")
     * @return the Retry instance for the given name
     */
    public Retry getRetry(String name) {
        Retry retry = retryRegistry.retry(name);
        
        retry.getEventPublisher()
            .onRetry(event -> {
                LOGGER.info("[Retry:" + name + "] Attempt " + event.getNumberOfRetryAttempts() + 
                    " after " + event.getWaitInterval().toMillis() + "ms");
            })
            .onError(event -> {
                LOGGER.warning("[Retry:" + name + "] All retry attempts exhausted");
            });
        
        return retry;
    }
    
    /**
     * Returns the current state of the named circuit breaker.
     *
     * @param name the circuit breaker name
     * @return the current state (CLOSED, OPEN, or HALF_OPEN)
     */
    public CircuitBreaker.State getState(String name) {
        CircuitBreaker circuitBreaker = circuitBreakerRegistry.circuitBreaker(name);
        return circuitBreaker.getState();
    }
    
    /**
     * Returns the total failure count for the named circuit breaker.
     *
     * <p>This is a cumulative count of all failures since the last reset.
     *
     * @param name the circuit breaker name
     * @return the total number of failures
     */
    public long getFailureCount(String name) {
        AtomicLong counter = failureCounters.get(name);
        return counter != null ? counter.get() : 0;
    }
    
    /**
     * Resets the circuit breaker metrics and failure counters.
     *
     * <p>This method should be called after resolving connectivity issues
     * to clear the failure history.
     *
     * @param name the circuit breaker name to reset
     */
    public void resetMetrics(String name) {
        failureCounters.remove(name);
        CircuitBreaker circuitBreaker = circuitBreakerRegistry.circuitBreaker(name);
        circuitBreaker.reset();
        LOGGER.info("[CircuitBreaker:" + name + "] Metrics reset");
    }
    
    /**
     * Increments the failure counter for the named circuit breaker.
     *
     * @param name the circuit breaker name
     */
    private void incrementFailureCounter(String name) {
        failureCounters.computeIfAbsent(name, k -> new AtomicLong(0)).incrementAndGet();
    }
    
    /**
     * Determines if an exception should trigger a retry attempt.
     *
     * <p>Retries are attempted for transient failures that may resolve:
     * <ul>
     *   <li>Connection refused (agent not running)</li>
     *   <li>Timeout (agent not responding)</li>
     *   <li>HTTP 502 Bad Gateway</li>
     *   <li>HTTP 503 Service Unavailable</li>
     *   <li>HTTP 429 Too Many Requests</li>
     * </ul>
     *
     * @param e the exception to evaluate
     * @return {@code true} if the exception is retryable
     */
    private boolean isRetryable(Throwable e) {
        String message = e.getMessage();
        if (message == null) {
            return false;
        }
        
        return message.contains("Connection refused") ||
               message.contains("Timeout") ||
               message.contains("503") ||
               message.contains("502") ||
                message.contains("429");
    }
    
    /**
     * Returns a JSON-formatted health status of all circuit breakers.
     *
     * <p>The status includes:
     * <ul>
     *   <li>Current state</li>
     *   <li>Failure rate</li>
     *   <li>Slow call rate</li>
     *   <li>Number of buffered calls</li>
     *   <li>Number of failed calls</li>
     * </ul>
     *
     * @return JSON string with health status of all circuit breakers
     */
    public String getHealthStatus() {
        StringBuilder status = new StringBuilder();
        status.append("{");
        status.append("\"circuitBreakers\":{");
        
        boolean first = true;
        for (String name : circuitBreakerRegistry.getAllCircuitBreakers().stream()
                .map(CircuitBreaker::getName).toList()) {
            if (!first) status.append(",");
            first = false;
            
            CircuitBreaker cb = circuitBreakerRegistry.circuitBreaker(name);
            CircuitBreaker.Metrics metrics = cb.getMetrics();
            
            status.append("\"").append(name).append("\":{");
            status.append("\"state\":\"").append(cb.getState()).append("\",");
            status.append("\"failureRate\":").append(metrics.getFailureRate()).append(",");
            status.append("\"slowCallRate\":").append(metrics.getSlowCallRate()).append(",");
            status.append("\"numberOfBufferedCalls\":").append(metrics.getNumberOfBufferedCalls()).append(",");
            status.append("\"numberOfFailedCalls\":").append(metrics.getNumberOfFailedCalls());
            status.append("}");
        }
        
        status.append("}}");
        return status.toString();
    }
}

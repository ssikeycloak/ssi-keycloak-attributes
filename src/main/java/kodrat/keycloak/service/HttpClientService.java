package kodrat.keycloak.service;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.retry.Retry;
import io.vavr.control.Try;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.function.Supplier;
import java.util.logging.Logger;
import kodrat.keycloak.constant.HTTPConstants;
import kodrat.keycloak.exception.SSIException;
import kodrat.keycloak.util.LogSanitizer;

/**
 * HTTP client service for communicating with SSI agents (e.g., ACA-Py).
 *
 * <p>This service provides a robust HTTP client with built-in resilience patterns
 * including circuit breaker protection and automatic retries for transient failures.
 * It handles JSON serialization/deserialization and provides detailed logging for
 * debugging and monitoring.
 *
 * <h2>Features</h2>
 * <ul>
 *   <li><strong>Circuit Breaker:</strong> Protects against cascading failures when
 *       the SSI agent is unavailable</li>
 *   <li><strong>Automatic Retries:</strong> Retries failed requests with exponential
 *       backoff for transient errors</li>
 *   <li><strong>Bearer Token Auth:</strong> Optional authentication for protected endpoints</li>
 *   <li><strong>JSON Handling:</strong> Automatic serialization/deserialization of
 *       request/response bodies</li>
 *   <li><strong>Detailed Logging:</strong> Request/response logging with sensitive
 *       data redaction</li>
 * </ul>
 *
 * <h2>Circuit Breaker States</h2>
 * <p>The circuit breaker operates in three states:
 * <ul>
 *   <li><strong>CLOSED:</strong> Normal operation, requests pass through</li>
 *   <li><strong>OPEN:</strong> Failing fast, requests are rejected immediately</li>
 *   <li><strong>HALF_OPEN:</strong> Testing if service has recovered</li>
 * </ul>
 *
 * <h2>Usage Example</h2>
 * <pre>{@code
 * // Create client with authentication
 * HttpClientService client = new HttpClientService("my-bearer-token");
 *
 * // GET request
 * MyResponse response = client.get(
 *     "https://ssi-agent.example.com/api/endpoint",
 *     null,  // no additional headers
 *     MyResponse.class
 * );
 *
 * // POST request
 * MyResponse response = client.post(
 *     "https://ssi-agent.example.com/api/endpoint",
 *     Map.of("key", "value"),  // request body
 *     Map.of("X-Custom-Header", "value"),  // additional headers
 *     MyResponse.class
 * );
 *
 * // Check circuit breaker state
 * if (client.getCircuitBreakerState() == CircuitBreaker.State.OPEN) {
 *     // Service is unavailable
 * }
 * }</pre>
 *
 * <h2>Configuration</h2>
 * <p>Circuit breaker and retry behavior is configured via {@link CircuitBreakerService}.
 * Default settings:
 * <ul>
 *   <li>Connection timeout: 30 seconds</li>
 *   <li>Request timeout: 60 seconds</li>
 *   <li>Failure rate threshold: 50%</li>
 *   <li>Slow call duration threshold: 10 seconds</li>
 * </ul>
 *
 * <h2>Error Handling</h2>
 * <p>All HTTP errors are wrapped in {@link SSIException} with descriptive messages:
 * <ul>
 *   <li>Connection refused - Agent not running</li>
 *   <li>Timeout - Agent not responding</li>
 *   <li>Unknown host - DNS resolution failed</li>
 *   <li>SSL error - Certificate or TLS issues</li>
 *   <li>HTTP error - Non-2xx response from agent</li>
 * </ul>
 *
 * <h2>Thread Safety</h2>
 * <p>This class is <strong>thread-safe</strong>. The underlying {@link HttpClient}
 * and {@link ObjectMapper} are thread-safe, and the circuit breaker is designed
 * for concurrent access.
 *
 * @see CircuitBreakerService
 * @see SSIException
 * @see LogSanitizer
 * @since 1.0.0
 * @author Kodrat Development Team
 */
public class HttpClientService {
    
    private static final Logger LOGGER = Logger.getLogger(HttpClientService.class.getName());
    
    private static final String CIRCUIT_BREAKER_NAME = "ssi-http-client";
    
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final String bearerToken;
    private final CircuitBreaker circuitBreaker;
    private final Retry retry;

    /**
     * Constructs an HttpClientService without authentication.
     *
     * <p>Use this constructor for public endpoints that don't require authentication.
     */
    public HttpClientService() {
        this(null);
    }

    /**
     * Constructs an HttpClientService with bearer token authentication.
     *
     * <p>The bearer token will be included in the Authorization header for all
     * requests made through this client instance.
     *
     * @param bearerToken the bearer token for authentication; may be {@code null}
     *                    or blank for public endpoints
     */
    public HttpClientService(String bearerToken) {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30))
                .build();
        this.objectMapper = new ObjectMapper();
        this.objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        this.bearerToken = bearerToken;
        
        CircuitBreakerService cbService = CircuitBreakerService.getInstance();
        this.circuitBreaker = cbService.getCircuitBreaker(CIRCUIT_BREAKER_NAME);
        this.retry = cbService.getRetry(CIRCUIT_BREAKER_NAME);
        
        LOGGER.info("[HttpClientService] Initialized with connectTimeout=30s, bearerToken=" + 
            LogSanitizer.redactToken(bearerToken) + ", circuitBreaker=" + circuitBreaker.getState());
    }

    /**
     * Sends a POST request to the specified URL with JSON body.
     *
     * <p>This method:
     * <ol>
     *   <li>Serializes the body object to JSON</li>
     *   <li>Applies circuit breaker and retry decorators</li>
     *   <li>Executes the HTTP POST request</li>
     *   <li>Deserializes the response to the specified type</li>
     * </ol>
     *
     * <p>The request includes:
     * <ul>
     *   <li>Content-Type: application/json</li>
     *   <li>Authorization: Bearer {token} (if configured)</li>
     *   <li>Any additional headers provided</li>
     * </ul>
     *
     * @param <T> the type of response to return
     * @param url the target URL (must be a valid HTTP/HTTPS URL)
     * @param body the request body object (will be serialized to JSON)
     * @param headers additional headers to include; may be {@code null}
     * @param responseType the class type to deserialize the response to;
     *                     use {@code String.class} for raw response
     * @return the deserialized response object
     * @throws SSIException if the HTTP request fails, times out, or returns
     *                      an error status code
     * @throws SSIException if the circuit breaker is open (service unavailable)
     */
    public <T> T post(String url, Object body, Map<String, String> headers, Class<T> responseType) {
        String jsonBody;
        try {
            jsonBody = objectMapper.writeValueAsString(body);
            LOGGER.info("[POST] URL: " + url);
            LOGGER.info("[POST] Body: " + LogSanitizer.redact(jsonBody));
        } catch (Exception e) {
            LOGGER.severe("[POST] Failed to serialize body: " + e.getMessage());
            throw new SSIException("Failed to serialize request body", e);
        }

        Supplier<T> requestSupplier = () -> executePost(url, jsonBody, headers, responseType);
        
        Supplier<T> decoratedSupplier = Retry.decorateSupplier(retry, 
            CircuitBreaker.decorateSupplier(circuitBreaker, requestSupplier));

        try {
            return Try.ofSupplier(decoratedSupplier)
                .recover(CallNotPermittedException.class, e -> {
                    LOGGER.severe("[POST] Circuit breaker OPEN - rejecting request to " + url);
                    throw new SSIException("Circuit breaker open - SSI endpoint unavailable", e);
                })
                .recover(SSIException.class, e -> {
                    throw e;
                })
                .recover(Exception.class, e -> {
                    LOGGER.severe("[POST] All retry attempts failed for " + url);
                    throw new SSIException("Request failed after retries: " + e.getMessage(), e);
                })
                .get();
        } catch (SSIException e) {
            throw e;
        } catch (Exception e) {
            throw new SSIException("Failed to execute POST request to " + url, e);
        }
    }
    
    /**
     * Executes the actual HTTP POST request without resilience decorators.
     *
     * @param url the target URL
     * @param jsonBody the JSON body to send
     * @param headers additional headers
     * @param responseType the response type
     * @return the deserialized response
     */
    private <T> T executePost(String url, String jsonBody, Map<String, String> headers, Class<T> responseType) {
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header(HTTPConstants.CONTENT_TYPE_HEADER, HTTPConstants.CONTENT_TYPE_JSON)
                    .timeout(Duration.ofSeconds(60))
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody));

            if (bearerToken != null && !bearerToken.isBlank()) {
                builder.header(HTTPConstants.AUTHORIZATION_HEADER, HTTPConstants.AUTHORIZATION_BEARER + bearerToken);
                LOGGER.info("[POST] Authorization header set (token=" + LogSanitizer.redactToken(bearerToken) + ")");
            } else {
                LOGGER.info("[POST] No bearer token configured (public endpoint mode)");
            }

            if (headers != null) {
                headers.forEach(builder::header);
            }

            HttpRequest request = builder.build();
            LOGGER.info("[POST] Sending request...");
            long startTime = System.currentTimeMillis();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            long elapsed = System.currentTimeMillis() - startTime;

            LOGGER.info("[POST] Response status: " + response.statusCode() + " (took " + elapsed + "ms)");
            LOGGER.fine("[POST] Response body: " + LogSanitizer.redact(response.body()));

            if (response.statusCode() != HTTPConstants.HTTP_OK && response.statusCode() != HTTPConstants.HTTP_CREATED) {
                LOGGER.severe("[POST] HTTP error " + response.statusCode() + " - Response: " + LogSanitizer.redact(response.body()));
                throw new SSIException("HTTP error: " + response.statusCode() + " - " + LogSanitizer.redact(response.body()));
            }

            if (responseType == String.class) {
                return responseType.cast(response.body().trim());
            }

            return objectMapper.readValue(response.body(), responseType);
        } catch (SSIException e) {
            throw e;
        } catch (java.net.ConnectException e) {
            LOGGER.severe("[POST] Connection refused to " + url + " - " + e.getMessage());
            throw new SSIException("Connection refused: " + url + " - Check if Aries agent is running", e);
        } catch (java.net.http.HttpTimeoutException e) {
            LOGGER.severe("[POST] Timeout connecting to " + url + " after 60s");
            throw new SSIException("Timeout: " + url + " - Aries agent not responding", e);
        } catch (java.net.UnknownHostException e) {
            LOGGER.severe("[POST] Unknown host: " + url + " - DNS resolution failed");
            throw new SSIException("Unknown host: " + url + " - DNS resolution failed", e);
        } catch (javax.net.ssl.SSLException e) {
            LOGGER.severe("[POST] SSL error connecting to " + url + " - " + e.getMessage());
            throw new SSIException("SSL error: " + url + " - " + e.getMessage(), e);
        } catch (Exception e) {
            LOGGER.severe("[POST] Failed request to " + url + " - " + e.getClass().getSimpleName() + ": " + e.getMessage());
            throw new SSIException("Failed to execute POST request to " + url, e);
        }
    }

    /**
     * Sends a GET request to the specified URL.
     *
     * <p>This method:
     * <ol>
     *   <li>Applies circuit breaker and retry decorators</li>
     *   <li>Executes the HTTP GET request</li>
     *   <li>Deserializes the response to the specified type</li>
     * </ol>
     *
     * <p>The request includes:
     * <ul>
     *   <li>Authorization: Bearer {token} (if configured)</li>
     *   <li>Any additional headers provided</li>
     * </ul>
     *
     * @param <T> the type of response to return
     * @param url the target URL (must be a valid HTTP/HTTPS URL)
     * @param headers additional headers to include; may be {@code null}
     * @param responseType the class type to deserialize the response to;
     *                     use {@code String.class} for raw response
     * @return the deserialized response object
     * @throws SSIException if the HTTP request fails, times out, or returns
     *                      an error status code
     * @throws SSIException if the circuit breaker is open (service unavailable)
     */
    public <T> T get(String url, Map<String, String> headers, Class<T> responseType) {
        Supplier<T> requestSupplier = () -> executeGet(url, headers, responseType);
        
        Supplier<T> decoratedSupplier = Retry.decorateSupplier(retry, 
            CircuitBreaker.decorateSupplier(circuitBreaker, requestSupplier));

        try {
            return Try.ofSupplier(decoratedSupplier)
                .recover(CallNotPermittedException.class, e -> {
                    LOGGER.severe("[GET] Circuit breaker OPEN - rejecting request to " + url);
                    throw new SSIException("Circuit breaker open - SSI endpoint unavailable", e);
                })
                .recover(SSIException.class, e -> {
                    throw e;
                })
                .recover(Exception.class, e -> {
                    LOGGER.severe("[GET] All retry attempts failed for " + url);
                    throw new SSIException("Request failed after retries: " + e.getMessage(), e);
                })
                .get();
        } catch (SSIException e) {
            throw e;
        } catch (Exception e) {
            throw new SSIException("Failed to execute GET request to " + url, e);
        }
    }
    
    /**
     * Executes the actual HTTP GET request without resilience decorators.
     *
     * @param url the target URL
     * @param headers additional headers
     * @param responseType the response type
     * @return the deserialized response
     */
    private <T> T executeGet(String url, Map<String, String> headers, Class<T> responseType) {
        try {
            LOGGER.info("[GET] URL: " + url);

            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(60))
                    .GET();

            if (bearerToken != null && !bearerToken.isBlank()) {
                builder.header(HTTPConstants.AUTHORIZATION_HEADER, HTTPConstants.AUTHORIZATION_BEARER + bearerToken);
                LOGGER.info("[GET] Authorization header set (token=" + LogSanitizer.redactToken(bearerToken) + ")");
            } else {
                LOGGER.info("[GET] No bearer token configured (public endpoint mode)");
            }

            if (headers != null) {
                headers.forEach(builder::header);
            }

            HttpRequest request = builder.build();
            LOGGER.info("[GET] Sending request...");
            long startTime = System.currentTimeMillis();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            long elapsed = System.currentTimeMillis() - startTime;

            LOGGER.info("[GET] Response status: " + response.statusCode() + " (took " + elapsed + "ms)");
            LOGGER.fine("[GET] Response body: " + LogSanitizer.redact(response.body()));

            if (response.statusCode() != HTTPConstants.HTTP_OK) {
                LOGGER.severe("[GET] HTTP error " + response.statusCode() + " - Response: " + LogSanitizer.redact(response.body()));
                throw new SSIException("HTTP error: " + response.statusCode() + " - " + LogSanitizer.redact(response.body()));
            }

            if (responseType == String.class) {
                return responseType.cast(response.body().trim());
            }

            return objectMapper.readValue(response.body(), responseType);
        } catch (SSIException e) {
            throw e;
        } catch (java.net.ConnectException e) {
            LOGGER.severe("[GET] Connection refused to " + url + " - " + e.getMessage());
            throw new SSIException("Connection refused: " + url + " - Check if Aries agent is running", e);
        } catch (java.net.http.HttpTimeoutException e) {
            LOGGER.severe("[GET] Timeout connecting to " + url + " after 60s");
            throw new SSIException("Timeout: " + url + " - Aries agent not responding", e);
        } catch (java.net.UnknownHostException e) {
            LOGGER.severe("[GET] Unknown host: " + url + " - DNS resolution failed");
            throw new SSIException("Unknown host: " + url + " - DNS resolution failed", e);
        } catch (javax.net.ssl.SSLException e) {
            LOGGER.severe("[GET] SSL error connecting to " + url + " - " + e.getMessage());
            throw new SSIException("SSL error: " + url + " - " + e.getMessage(), e);
        } catch (Exception e) {
            LOGGER.severe("[GET] Failed request to " + url + " - " + e.getClass().getSimpleName() + ": " + e.getMessage());
            throw new SSIException("Failed to execute GET request to " + url, e);
        }
    }
    
    /**
     * Returns the current state of the circuit breaker.
     *
     * @return the circuit breaker state (CLOSED, OPEN, or HALF_OPEN)
     */
    public CircuitBreaker.State getCircuitBreakerState() {
        return circuitBreaker.getState();
    }
    
    /**
     * Returns a formatted string with circuit breaker metrics.
     *
     * <p>Metrics include:
     * <ul>
     *   <li>Current state</li>
     *   <li>Failure rate percentage</li>
     *   <li>Slow call rate percentage</li>
     *   <li>Number of buffered calls</li>
     *   <li>Number of failed calls</li>
     * </ul>
     *
     * @return formatted metrics string
     */
    public String getCircuitBreakerMetrics() {
        CircuitBreaker.Metrics metrics = circuitBreaker.getMetrics();
        return String.format(
            "{state=%s, failureRate=%.2f, slowCallRate=%.2f, bufferedCalls=%d, failedCalls=%d}",
            circuitBreaker.getState(),
            metrics.getFailureRate(),
            metrics.getSlowCallRate(),
            metrics.getNumberOfBufferedCalls(),
            metrics.getNumberOfFailedCalls()
        );
    }
}

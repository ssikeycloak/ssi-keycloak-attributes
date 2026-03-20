package kodrat.keycloak.constant;

/**
 * Constants for HTTP communication and polling operations.
 * Includes headers, status codes, and retry configuration.
 */
public final class HTTPConstants {
    /**
     * Prevents instantiation of this utility class.
     */
    private HTTPConstants() {
    }

    public static final String CONTENT_TYPE_JSON = "application/json";
    /**
     * Bearer token prefix for authorization header.
     */
    public static final String AUTHORIZATION_BEARER = "Bearer ";

    /**
     * HTTP header name for authorization.
     */
    public static final String AUTHORIZATION_HEADER = "Authorization";

    /**
     * HTTP header name for content type.
     */
    public static final String CONTENT_TYPE_HEADER = "Content-Type";

    /**
     * HTTP status code for successful requests.
     */
    public static final int HTTP_OK = 200;

    /**
     * HTTP status code for created resources.
     */
    public static final int HTTP_CREATED = 201;

    /**
     * HTTP status code for bad requests.
     */
    public static final int HTTP_BAD_REQUEST = 400;

    /**
     * HTTP status code for unauthorized access.
     */
    public static final int HTTP_UNAUTHORIZED = 401;

    /**
     * HTTP status code for forbidden access.
     */
    public static final int HTTP_FORBIDDEN = 403;

    /**
     * HTTP status code for resource not found.
     */
    public static final int HTTP_NOT_FOUND = 404;

    /**
     * HTTP status code for internal server errors.
     */
    public static final int HTTP_INTERNAL_ERROR = 500;

    /**
     * HTTP status code for service unavailable.
     */
    public static final int HTTP_SERVICE_UNAVAILABLE = 503;

    /**
     * Maximum number of retry attempts for general operations.
     */
    public static final int MAX_RETRIES = 5;

    /**
     * Delay between polling attempts in milliseconds.
     */
    public static final int POLLING_DELAY_MS = 3000;

    /**
     * Maximum number of retry attempts for connection establishment.
     */
    public static final int CONNECTION_MAX_RETRIES = 5;

    /**
     * Delay between connection polling attempts in milliseconds.
     */
    public static final int CONNECTION_POLLING_DELAY_MS = 5000;

    /**
     * Maximum number of retry attempts for verification operations.
     */
    public static final int VERIFICATION_MAX_RETRIES = 40;

    /**
     * Delay between verification polling attempts in milliseconds.
     */
    public static final int VERIFICATION_POLLING_DELAY_MS = 3000;
}

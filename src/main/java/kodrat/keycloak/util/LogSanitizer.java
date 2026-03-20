package kodrat.keycloak.util;

import java.util.regex.Pattern;

/**
 * Utility class for sanitizing sensitive data before logging.
 *
 * <p>This class provides methods to prevent exposure of sensitive information
 * such as authentication tokens, credentials, PII, and session identifiers
 * in application logs. It supports multiple redaction strategies depending
 * on the sensitivity level of the data.
 *
 * <h2>Redaction Strategies</h2>
 * <table border="1">
 *   <caption>Available Redaction Methods</caption>
 *   <tr><th>Method</th><th>Use Case</th><th>Output Example</th></tr>
 *   <tr><td>{@link #redactToken(String)}</td><td>Bearer tokens, API keys</td><td>{@code ***abcd}</td></tr>
 *   <tr><td>{@link #redact(String)}</td><td>Highly sensitive data</td><td>{@code [REDACTED]}</td></tr>
 *   <tr><td>{@link #maskIdentifier(String)}</td><td>Session/connection IDs</td><td>{@code abcd...wxyz}</td></tr>
 *   <tr><td>{@link #maskInvitationUrl(String)}</td><td>Invitation URLs</td><td>{@code https://host/[REDACTED]}</td></tr>
 *   <tr><td>{@link #sanitizeJson(String)}</td><td>JSON with sensitive fields</td><td>Field values redacted</td></tr>
 *   <tr><td>{@link #sanitize(String)}</td><td>General log messages</td><td>Patterns redacted</td></tr>
 * </table>
 *
 * <h2>Sensitive Data Patterns</h2>
 * <p>The following patterns are automatically detected and redacted:
 * <ul>
 *   <li>Bearer tokens in Authorization headers</li>
 *   <li>API keys in JSON (api_key, apiKey)</li>
 *   <li>Passwords in JSON</li>
 *   <li>Authorization headers</li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 * <pre>{@code
 * // Token redaction (shows last 4 chars for debugging)
 * String safe = LogSanitizer.redactToken("eyJhbGciOiJSUzI1NiIs...");
 * // Result: "***I1Ni"
 *
 * // Complete redaction for highly sensitive data
 * String safe = LogSanitizer.redact(userPassword);
 * // Result: "[REDACTED]"
 *
 * // Session ID masking (shows prefix and suffix)
 * String safe = LogSanitizer.maskIdentifier("abc123def456ghi789");
 * // Result: "abc1...i789"
 *
 * // URL masking (shows protocol and domain only)
 * String safe = LogSanitizer.maskInvitationUrl("https://ssi.example.com/invite?c=xyz");
 * // Result: "https://ssi.example.com/[REDACTED]"
 *
 * // Sanitize full log message
 * String safe = LogSanitizer.sanitize("Authorization: Bearer eyJhbGciOiJS...");
 * // Result: "Authorization: Bearer [REDACTED]"
 * }</pre>
 *
 * <h2>Thread Safety</h2>
 * <p>This class is stateless and all methods are static. It is safe to call from
 * multiple threads concurrently.
 *
 * @since 1.0.0
 * @author Kodrat Development Team
 */
public final class LogSanitizer {

    private static final int MAX_VISIBLE_LENGTH = 4;
    private static final String REDACTED = "[REDACTED]";
    private static final String TOKEN_MASK = "***";

    private static final Pattern BEARER_TOKEN_PATTERN = Pattern.compile(
            "(Bearer\\s+)[a-zA-Z0-9._-]+", Pattern.CASE_INSENSITIVE);
    private static final Pattern API_KEY_PATTERN = Pattern.compile(
            "(\"api[_-]?key\"\\s*:\\s*\")([^\"]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
            "(\"password\"\\s*:\\s*\")([^\"]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern AUTHORIZATION_HEADER_PATTERN = Pattern.compile(
            "(Authorization:\\s*Bearer\\s+)[a-zA-Z0-9._-]+", Pattern.CASE_INSENSITIVE);

    /**
     * Private constructor to prevent instantiation.
     * This is a utility class with only static methods.
     *
     * @throws AssertionError always, as this constructor should never be called
     */
    private LogSanitizer() {
        throw new AssertionError("Utility class cannot be instantiated");
    }

    /**
     * Redacts a bearer token, showing only the last 4 characters for debugging.
     *
     * <p>Use this method for tokens where partial visibility helps with
     * debugging and correlation without exposing the full secret.
     *
     * @param token the token to redact
     * @return redacted token representation:
     *         <ul>
     *           <li>{@code [EMPTY]} if null or empty</li>
     *           <li>{@code ***} if 4 characters or less</li>
     *           <li>{@code ***abcd} showing last 4 chars otherwise</li>
     *         </ul>
     */
    public static String redactToken(String token) {
        if (token == null || token.isEmpty()) {
            return "[EMPTY]";
        }
        if (token.length() <= MAX_VISIBLE_LENGTH) {
            return TOKEN_MASK;
        }
        return TOKEN_MASK + token.substring(token.length() - MAX_VISIBLE_LENGTH);
    }

    /**
     * Completely redacts sensitive content.
     *
     * <p>Use this method for highly sensitive data where no visibility is acceptable,
     * such as passwords or decrypted PII.
     *
     * @param content the content to redact
     * @return {@code [REDACTED]} for non-empty content, {@code [EMPTY]} for null/empty
     */
    public static String redact(String content) {
        if (content == null || content.isEmpty()) {
            return "[EMPTY]";
        }
        return REDACTED;
    }

    /**
     * Redacts sensitive fields from a JSON-like string.
     *
     * <p>Replaces values for known sensitive keys with [REDACTED]:
     * <ul>
     *   <li>{@code api_key} / {@code apiKey}</li>
     *   <li>{@code password}</li>
     *   <li>Bearer tokens in values</li>
     * </ul>
     *
     * <p>The JSON structure and non-sensitive values are preserved.
     *
     * @param json the JSON string to sanitize
     * @return sanitized JSON string with sensitive values redacted;
     *         {@code [EMPTY]} if input is null/empty
     */
    public static String sanitizeJson(String json) {
        if (json == null || json.isEmpty()) {
            return "[EMPTY]";
        }

        String sanitized = json;
        sanitized = BEARER_TOKEN_PATTERN.matcher(sanitized).replaceAll("$1[REDACTED]");
        sanitized = API_KEY_PATTERN.matcher(sanitized).replaceAll("$1[REDACTED]\"");
        sanitized = PASSWORD_PATTERN.matcher(sanitized).replaceAll("$1[REDACTED]\"");

        return sanitized;
    }

    /**
     * Sanitizes HTTP headers by redacting sensitive values.
     *
     * <p>The following headers are redacted:
     * <ul>
     *   <li>Authorization (shows last 4 chars of token)</li>
     *   <li>X-API-Key (shows last 4 chars)</li>
     *   <li>Cookie (shows last 4 chars)</li>
     * </ul>
     *
     * @param headerName the header name (case-insensitive)
     * @param headerValue the header value to sanitize
     * @return sanitized header value; original value if header is not sensitive
     */
    public static String sanitizeHeader(String headerName, String headerValue) {
        if (headerValue == null) {
            return null;
        }

        String lowerName = headerName.toLowerCase();
        if (lowerName.contains("authorization") ||
            lowerName.contains("x-api-key") ||
            lowerName.contains("cookie")) {
            return redactToken(headerValue);
        }

        return headerValue;
    }

    /**
     * Masks an invitation URL, showing only the protocol and domain.
     *
     * <p>Use this method for DIDComm invitation URLs where the domain is
     * useful for debugging but the full URL contains sensitive tokens.
     *
     * @param url the invitation URL to mask
     * @return masked URL in format {@code protocol://host/[REDACTED]};
     *         {@code [EMPTY]} if null/empty; {@code [INVALID_URL]} if malformed
     */
    public static String maskInvitationUrl(String url) {
        if (url == null || url.isEmpty()) {
            return "[EMPTY]";
        }

        try {
            java.net.URI uri = java.net.URI.create(url);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            if (scheme == null || host == null) {
                return "[INVALID_URL]";
            }
            return scheme + "://" + host + "/[REDACTED]";
        } catch (Exception e) {
            return "[INVALID_URL]";
        }
    }

    /**
     * Creates a safe representation of session/connection identifiers for logging.
     *
     * <p>Shows a prefix and suffix (4 characters each) for correlation purposes
     * while hiding the full identifier. Useful for session IDs, connection IDs,
     * and other opaque identifiers.
     *
     * @param id the identifier to mask
     * @return masked identifier:
     *         <ul>
     *           <li>{@code [EMPTY]} if null or empty</li>
     *           <li>{@code ***} if 8 characters or less</li>
     *           <li>{@code abcd...wxyz} showing first and last 4 chars otherwise</li>
     *         </ul>
     */
    public static String maskIdentifier(String id) {
        if (id == null || id.isEmpty()) {
            return "[EMPTY]";
        }
        if (id.length() <= 8) {
            return TOKEN_MASK;
        }
        return id.substring(0, 4) + "..." + id.substring(id.length() - 4);
    }

    /**
     * Sanitizes a full log message by applying all redaction patterns.
     *
     * <p>Applies the following transformations:
     * <ul>
     *   <li>Redacts Bearer tokens in Authorization headers</li>
     *   <li>Redacts standalone Bearer tokens</li>
     * </ul>
     *
     * <p>Use this method when logging arbitrary messages that may contain
     * sensitive patterns.
     *
     * @param message the message to sanitize
     * @return sanitized message with sensitive patterns redacted;
     *         {@code [NULL]} if input is null
     */
    public static String sanitize(String message) {
        if (message == null) {
            return "[NULL]";
        }

        String sanitized = message;
        sanitized = AUTHORIZATION_HEADER_PATTERN.matcher(sanitized)
                .replaceAll("$1[REDACTED]");
        sanitized = BEARER_TOKEN_PATTERN.matcher(sanitized)
                .replaceAll("$1[REDACTED]");

        return sanitized;
    }
}

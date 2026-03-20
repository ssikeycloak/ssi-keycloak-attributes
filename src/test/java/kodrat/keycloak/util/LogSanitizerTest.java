package kodrat.keycloak.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for LogSanitizer utility.
 */
class LogSanitizerTest {

    @Test
    void redactToken_withNull_returnsEmptyMarker() {
        assertEquals("[EMPTY]", LogSanitizer.redactToken(null));
    }

    @Test
    void redactToken_withEmptyString_returnsEmptyMarker() {
        assertEquals("[EMPTY]", LogSanitizer.redactToken(""));
    }

    @Test
    void redactToken_withShortToken_returnsMaskOnly() {
        assertEquals("***", LogSanitizer.redactToken("abc"));
    }

    @Test
    void redactToken_withLongToken_returnsMaskedWithSuffix() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        String result = LogSanitizer.redactToken(token);
        assertTrue(result.startsWith("***"));
        assertTrue(result.endsWith("CJ9"));
        assertNotEquals(token, result);
    }

    @Test
    void redact_withNull_returnsEmptyMarker() {
        assertEquals("[EMPTY]", LogSanitizer.redact(null));
    }

    @Test
    void redact_withContent_returnsRedactedMarker() {
        assertEquals("[REDACTED]", LogSanitizer.redact("sensitive data"));
    }

    @Test
    void sanitizeJson_withBearerToken_redactsToken() {
        String json = "{\"Authorization\": \"Bearer abc123xyz789\"}";
        String result = LogSanitizer.sanitizeJson(json);
        assertTrue(result.contains("[REDACTED]"));
        assertFalse(result.contains("abc123xyz789"));
    }

    @Test
    void sanitizeJson_withApiKey_redactsKey() {
        String json = "{\"api_key\": \"secret123\"}";
        String result = LogSanitizer.sanitizeJson(json);
        assertTrue(result.contains("[REDACTED]"));
        assertFalse(result.contains("secret123"));
    }

    @Test
    void sanitizeJson_withPassword_redactsPassword() {
        String json = "{\"password\": \"mypassword123\"}";
        String result = LogSanitizer.sanitizeJson(json);
        assertTrue(result.contains("[REDACTED]"));
        assertFalse(result.contains("mypassword123"));
    }

    @Test
    void sanitizeHeader_withAuthorizationHeader_redactsValue() {
        String result = LogSanitizer.sanitizeHeader("Authorization", "Bearer secret123");
        assertTrue(result.startsWith("***"));
        assertFalse(result.contains("secret123"));
    }

    @Test
    void sanitizeHeader_withNormalHeader_returnsAsIs() {
        String result = LogSanitizer.sanitizeHeader("Content-Type", "application/json");
        assertEquals("application/json", result);
    }

    @Test
    void maskInvitationUrl_withValidUrl_masksPath() {
        String url = "https://agent.example.com/invitation?c_i=eyJAdHlwZSI6...";
        String result = LogSanitizer.maskInvitationUrl(url);
        assertEquals("https://agent.example.com/[REDACTED]", result);
    }

    @Test
    void maskInvitationUrl_withInvalidUrl_returnsInvalidMarker() {
        String result = LogSanitizer.maskInvitationUrl("not-a-valid-url");
        assertEquals("[INVALID_URL]", result);
    }

    @Test
    void maskIdentifier_withLongId_showsPrefixAndSuffix() {
        String id = "12345678-1234-1234-1234-123456789abc";
        String result = LogSanitizer.maskIdentifier(id);
        assertEquals("1234...9abc", result);
    }

    @Test
    void maskIdentifier_withShortId_returnsMask() {
        String result = LogSanitizer.maskIdentifier("abc123");
        assertEquals("***", result);
    }

    @Test
    void sanitize_withBearerInMessage_redactsToken() {
        String message = "Request failed with token: Bearer secretToken123";
        String result = LogSanitizer.sanitize(message);
        assertTrue(result.contains("[REDACTED]"));
        assertFalse(result.contains("secretToken123"));
    }
}

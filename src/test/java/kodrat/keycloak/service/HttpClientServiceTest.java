package kodrat.keycloak.service;

import kodrat.keycloak.constant.HTTPConstants;
import kodrat.keycloak.constant.SSIStatus;
import kodrat.keycloak.exception.ConnectionTimeoutException;
import kodrat.keycloak.exception.SSIException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link HttpClientService}.
 * Tests URL handling, parameter construction, and error scenarios.
 */
public class HttpClientServiceTest {

    @Test
    public void testConstructor_WithBearerToken() {
        HttpClientService service = new HttpClientService("test-token");

        assertNotNull(service);
    }

    @Test
    public void testConstructor_WithoutBearerToken() {
        HttpClientService service = new HttpClientService();

        assertNotNull(service);
    }

    @Test
    public void testPostRequest_SerializationFailure() {
        HttpClientService service = new HttpClientService();

        String testUrl = "https://example.com/path?param=value";

        Exception exception = assertThrows(SSIException.class, () -> {
            service.post(testUrl, new Object(), null, String.class);
        });

        assertTrue(exception.getMessage().contains("Failed to serialize request body"));
    }
}

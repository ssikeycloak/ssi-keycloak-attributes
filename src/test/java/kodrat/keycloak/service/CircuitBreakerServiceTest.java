package kodrat.keycloak.service;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class CircuitBreakerServiceTest {

    @Test
    void testGetInstance_ReturnsSingleton() {
        CircuitBreakerService instance1 = CircuitBreakerService.getInstance();
        CircuitBreakerService instance2 = CircuitBreakerService.getInstance();
        assertSame(instance1, instance2);
    }

    @Test
    void testGetCircuitBreaker_ReturnsValidCircuitBreaker() {
        CircuitBreakerService service = CircuitBreakerService.getInstance();
        io.github.resilience4j.circuitbreaker.CircuitBreaker cb = service.getCircuitBreaker("test");
        assertNotNull(cb);
        assertEquals(io.github.resilience4j.circuitbreaker.CircuitBreaker.State.CLOSED, cb.getState());
    }

    @Test
    void testGetRetry_ReturnsValidRetry() {
        CircuitBreakerService service = CircuitBreakerService.getInstance();
        io.github.resilience4j.retry.Retry retry = service.getRetry("test");
        assertNotNull(retry);
    }

    @Test
    void testGetState_ReturnsCorrectState() {
        CircuitBreakerService service = CircuitBreakerService.getInstance();
        io.github.resilience4j.circuitbreaker.CircuitBreaker.State state = service.getState("test");
        assertEquals(io.github.resilience4j.circuitbreaker.CircuitBreaker.State.CLOSED, state);
    }

    @Test
    void testGetFailureCount_InitiallyZero() {
        CircuitBreakerService service = CircuitBreakerService.getInstance();
        long count = service.getFailureCount("test");
        assertEquals(0, count);
    }

    @Test
    void testResetMetrics_ResetsCounters() {
        CircuitBreakerService service = CircuitBreakerService.getInstance();
        service.resetMetrics("test");
        long count = service.getFailureCount("test");
        assertEquals(0, count);
    }

    @Test
    void testGetHealthStatus_ReturnsValidJson() {
        CircuitBreakerService service = CircuitBreakerService.getInstance();
        String health = service.getHealthStatus();
        assertNotNull(health);
        assertTrue(health.contains("circuitBreakers"));
    }
}

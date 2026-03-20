package kodrat.keycloak.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SessionLockServiceTest {

    @Mock
    private AuthenticationSessionModel session;

    @Mock
    private RootAuthenticationSessionModel parentSession;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(session.getParentSession()).thenReturn(parentSession);
        when(parentSession.getId()).thenReturn("parent-session-123");
        when(session.getTabId()).thenReturn("tab-456");
    }

    @Test
    void testGetInstance_ReturnsSingleton() {
        SessionLockService instance1 = SessionLockService.getInstance();
        SessionLockService instance2 = SessionLockService.getInstance();
        assertSame(instance1, instance2);
    }

    @Test
    void testWithSessionLock_ExecutesAction() {
        SessionLockService service = SessionLockService.getInstance();
        String result = service.withSessionLock(session, () -> "success");
        assertEquals("success", result);
    }

    @Test
    void testWithSessionLock_WithRunnable() {
        SessionLockService service = SessionLockService.getInstance();
        boolean[] executed = {false};
        service.withSessionLock(session, () -> executed[0] = true);
        assertTrue(executed[0]);
    }

    @Test
    void testIsSessionLocked_ReturnsFalseWhenNotLocked() {
        SessionLockService service = SessionLockService.getInstance();
        boolean locked = service.isSessionLocked(session);
        assertFalse(locked);
    }

    @Test
    void testGetActiveLockCount_InitiallyZero() {
        SessionLockService service = SessionLockService.getInstance();
        int count = service.getActiveLockCount();
        assertEquals(0, count);
    }
}

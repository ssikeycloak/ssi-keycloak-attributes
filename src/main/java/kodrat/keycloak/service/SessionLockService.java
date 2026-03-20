package kodrat.keycloak.service;

import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;
import java.util.logging.Logger;

public final class SessionLockService {
    private static final Logger LOGGER = Logger.getLogger(SessionLockService.class.getName());
    
    private static final SessionLockService INSTANCE = new SessionLockService();
    
    private final ConcurrentHashMap<String, ReentrantLock> sessionLocks = new ConcurrentHashMap<>();
    private static final long LOCK_TIMEOUT_MS = 5000;
    
    private SessionLockService() {
        LOGGER.info("[SessionLockService] Initialized");
    }
    
    public static SessionLockService getInstance() {
        return INSTANCE;
    }
    
    public <T> T withSessionLock(AuthenticationSessionModel session, Supplier<T> action) {
        String sessionId = getSessionKey(session);
        ReentrantLock lock = sessionLocks.computeIfAbsent(sessionId, k -> new ReentrantLock());
        
        boolean acquired = false;
        try {
            acquired = lock.tryLock();
            if (!acquired) {
                LOGGER.warning("[SessionLockService] Session " + sessionId + " is locked, waiting...");
                acquired = lock.tryLock(LOCK_TIMEOUT_MS, TimeUnit.MILLISECONDS);
            }
            
            if (!acquired) {
                LOGGER.severe("[SessionLockService] Failed to acquire lock for session " + sessionId + " after " + LOCK_TIMEOUT_MS + "ms");
                throw new IllegalStateException("Session is currently being processed by another request");
            }
            
            LOGGER.fine("[SessionLockService] Lock acquired for session " + sessionId);
            return action.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Lock acquisition interrupted", e);
        } finally {
            if (acquired) {
                lock.unlock();
                LOGGER.fine("[SessionLockService] Lock released for session " + sessionId);
            }
            cleanupLock(sessionId);
        }
    }
    
    public void withSessionLock(AuthenticationSessionModel session, Runnable action) {
        withSessionLock(session, () -> {
            action.run();
            return null;
        });
    }
    
    public boolean isSessionLocked(AuthenticationSessionModel session) {
        String sessionId = getSessionKey(session);
        ReentrantLock lock = sessionLocks.get(sessionId);
        return lock != null && lock.isLocked();
    }
    
    public int getActiveLockCount() {
        return (int) sessionLocks.values().stream().filter(ReentrantLock::isLocked).count();
    }
    
    public void forceUnlock(AuthenticationSessionModel session) {
        String sessionId = getSessionKey(session);
        ReentrantLock lock = sessionLocks.get(sessionId);
        if (lock != null && lock.isHeldByCurrentThread()) {
            lock.unlock();
            LOGGER.warning("[SessionLockService] Force unlocked session " + sessionId);
        }
    }
    
    private String getSessionKey(AuthenticationSessionModel session) {
        String parentId = session.getParentSession() != null ? session.getParentSession().getId() : "unknown";
        String tabId = session.getTabId() != null ? session.getTabId() : "unknown";
        return parentId + ":" + tabId;
    }
    
    private void cleanupLock(String sessionId) {
        ReentrantLock lock = sessionLocks.get(sessionId);
        if (lock != null && !lock.isLocked() && lock.getQueueLength() == 0) {
            sessionLocks.remove(sessionId);
        }
    }
}

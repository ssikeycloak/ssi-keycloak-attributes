package kodrat.keycloak.service;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

public final class ThreadPoolService {
    private static final Logger LOGGER = Logger.getLogger(ThreadPoolService.class.getName());
    
    private static final ThreadPoolService INSTANCE = new ThreadPoolService();
    
    private final ExecutorService httpExecutor;
    private final ScheduledExecutorService scheduledExecutor;
    private final AtomicInteger httpTaskCount = new AtomicInteger(0);
    private final AtomicInteger scheduledTaskCount = new AtomicInteger(0);
    
    private static final int CORE_POOL_SIZE = Runtime.getRuntime().availableProcessors();
    private static final int MAX_POOL_SIZE = CORE_POOL_SIZE * 2;
    private static final int QUEUE_CAPACITY = 100;
    private static final long KEEP_ALIVE_SECONDS = 60;
    
    private ThreadPoolService() {
        this.httpExecutor = new ThreadPoolExecutor(
            CORE_POOL_SIZE,
            MAX_POOL_SIZE,
            KEEP_ALIVE_SECONDS,
            TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(QUEUE_CAPACITY),
            new SsiThreadFactory("ssi-http"),
            new ThreadPoolExecutor.CallerRunsPolicy()
        );
        
        this.scheduledExecutor = new ScheduledThreadPoolExecutor(
            2,
            new SsiThreadFactory("ssi-scheduled"),
            new ThreadPoolExecutor.CallerRunsPolicy()
        );
        
        LOGGER.info("[ThreadPoolService] Initialized with corePoolSize=" + CORE_POOL_SIZE + 
            ", maxPoolSize=" + MAX_POOL_SIZE + ", queueCapacity=" + QUEUE_CAPACITY);
    }
    
    public static ThreadPoolService getInstance() {
        return INSTANCE;
    }
    
    public ExecutorService getHttpExecutor() {
        return httpExecutor;
    }
    
    public ScheduledExecutorService getScheduledExecutor() {
        return scheduledExecutor;
    }
    
    public <T> CompletableFuture<T> submitHttpTask(Callable<T> task) {
        httpTaskCount.incrementAndGet();
        return CompletableFuture.supplyAsync(() -> {
            try {
                return task.call();
            } catch (Exception e) {
                throw new CompletionException(e);
            } finally {
                httpTaskCount.decrementAndGet();
            }
        }, httpExecutor);
    }
    
    public CompletableFuture<Void> submitHttpTask(Runnable task) {
        httpTaskCount.incrementAndGet();
        return CompletableFuture.runAsync(() -> {
            try {
                task.run();
            } finally {
                httpTaskCount.decrementAndGet();
            }
        }, httpExecutor);
    }
    
    public ScheduledFuture<?> scheduleAtFixedRate(Runnable command, long initialDelay, long period, TimeUnit unit) {
        scheduledTaskCount.incrementAndGet();
        return scheduledExecutor.scheduleAtFixedRate(() -> {
            try {
                command.run();
            } finally {
                scheduledTaskCount.decrementAndGet();
            }
        }, initialDelay, period, unit);
    }
    
    public ScheduledFuture<?> schedule(Runnable command, long delay, TimeUnit unit) {
        return scheduledExecutor.schedule(command, delay, unit);
    }
    
    public ThreadPoolMetrics getMetrics() {
        if (httpExecutor instanceof ThreadPoolExecutor tpe) {
            return new ThreadPoolMetrics(
                tpe.getActiveCount(),
                tpe.getPoolSize(),
                tpe.getCorePoolSize(),
                tpe.getMaximumPoolSize(),
                tpe.getQueue().size(),
                tpe.getCompletedTaskCount(),
                httpTaskCount.get()
            );
        }
        return new ThreadPoolMetrics(0, 0, 0, 0, 0, 0, 0);
    }
    
    public boolean isHealthy() {
        if (httpExecutor instanceof ThreadPoolExecutor tpe) {
            int activeThreads = tpe.getActiveCount();
            int maxThreads = tpe.getMaximumPoolSize();
            double utilization = (double) activeThreads / maxThreads;
            
            return utilization < 0.9 && !httpExecutor.isShutdown() && !httpExecutor.isTerminated();
        }
        return false;
    }
    
    public void shutdown() {
        LOGGER.info("[ThreadPoolService] Shutting down thread pools...");
        httpExecutor.shutdown();
        scheduledExecutor.shutdown();
        
        try {
            if (!httpExecutor.awaitTermination(30, TimeUnit.SECONDS)) {
                httpExecutor.shutdownNow();
            }
            if (!scheduledExecutor.awaitTermination(30, TimeUnit.SECONDS)) {
                scheduledExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            httpExecutor.shutdownNow();
            scheduledExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        LOGGER.info("[ThreadPoolService] Thread pools shut down");
    }
    
    public static class ThreadPoolMetrics {
        private final int activeThreads;
        private final int currentPoolSize;
        private final int corePoolSize;
        private final int maxPoolSize;
        private final int queuedTasks;
        private final long completedTasks;
        private final int pendingTasks;
        
        public ThreadPoolMetrics(int activeThreads, int currentPoolSize, int corePoolSize, 
                                 int maxPoolSize, int queuedTasks, long completedTasks, int pendingTasks) {
            this.activeThreads = activeThreads;
            this.currentPoolSize = currentPoolSize;
            this.corePoolSize = corePoolSize;
            this.maxPoolSize = maxPoolSize;
            this.queuedTasks = queuedTasks;
            this.completedTasks = completedTasks;
            this.pendingTasks = pendingTasks;
        }
        
        public int getActiveThreads() { return activeThreads; }
        public int getCurrentPoolSize() { return currentPoolSize; }
        public int getCorePoolSize() { return corePoolSize; }
        public int getMaxPoolSize() { return maxPoolSize; }
        public int getQueuedTasks() { return queuedTasks; }
        public long getCompletedTasks() { return completedTasks; }
        public int getPendingTasks() { return pendingTasks; }
        
        public double getUtilization() {
            return maxPoolSize > 0 ? (double) activeThreads / maxPoolSize : 0;
        }
        
        @Override
        public String toString() {
            return String.format(
                "ThreadPoolMetrics{active=%d, poolSize=%d, core=%d, max=%d, queued=%d, completed=%d, pending=%d, utilization=%.2f%%}",
                activeThreads, currentPoolSize, corePoolSize, maxPoolSize, queuedTasks, completedTasks, pendingTasks, getUtilization() * 100
            );
        }
    }
    
    private static class SsiThreadFactory implements ThreadFactory {
        private final AtomicInteger threadNumber = new AtomicInteger(1);
        private final String namePrefix;
        
        SsiThreadFactory(String namePrefix) {
            this.namePrefix = "ssi-" + namePrefix + "-";
        }
        
        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(r, namePrefix + threadNumber.getAndIncrement());
            t.setDaemon(true);
            t.setPriority(Thread.NORM_PRIORITY);
            return t;
        }
    }
}

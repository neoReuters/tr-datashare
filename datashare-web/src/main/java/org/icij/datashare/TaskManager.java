package org.icij.datashare;

import com.google.inject.Inject;
import org.icij.datashare.monitoring.Monitorable;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.*;

import static java.lang.Integer.valueOf;
import static java.util.concurrent.Executors.newFixedThreadPool;
import static java.util.stream.Collectors.toList;

public class TaskManager {
    private Logger logger = LoggerFactory.getLogger(getClass());
    private final ExecutorService executor;
    private final ConcurrentMap<String, MonitorableFutureTask> tasks = new ConcurrentHashMap<>();

    @Inject
    public TaskManager(final PropertiesProvider provider) {
        Optional<String> parallelism = provider.get("parallelism");
        executor = parallelism.map(s -> newFixedThreadPool(valueOf(s))).
                   orElseGet( () -> newFixedThreadPool(Runtime.getRuntime().availableProcessors()));
    }

    public MonitorableFutureTask<Void> startTask(final Runnable task) {
        MonitorableFutureTask<Void> futureTask = new MonitorableFutureTask<>(task, null);
        executor.submit(futureTask);
        tasks.put(futureTask.toString(), futureTask);
        return futureTask;
    }

    public MonitorableFutureTask<Void> startTask(final Runnable task, final Runnable callback) {
        MonitorableFutureTask<Void> futureTask = new MonitorableFutureTask<Void>(task, null) {
            @Override protected void done() {
                callback.run();
            }
        };
        executor.submit(futureTask);
        tasks.put(futureTask.toString(), futureTask);
        return futureTask;
    }
    public <V> MonitorableFutureTask<V> startTask(final Callable<V> task, final Runnable callback) {
        MonitorableFutureTask<V> futureTask = new MonitorableFutureTask<V>(task) {
            @Override protected void done() {
                callback.run();
            }
        };
        executor.submit(futureTask);
        tasks.put(futureTask.toString(), futureTask);
        return futureTask;
    }

    public <V> MonitorableFutureTask<V> startTask(final Callable<V> task) {
        MonitorableFutureTask<V> futureTask = new MonitorableFutureTask<>(task);
        executor.submit(futureTask);
        tasks.put(futureTask.toString(), futureTask);
        return futureTask;
    }

    public MonitorableFutureTask getTask(final String taskName) {
        return tasks.get(taskName);
    }

    public List<Runnable> shutdownNow() {
        return executor.shutdownNow();
    }

    public void shutdownAndAwaitTermination(int timeout, TimeUnit timeUnit) throws InterruptedException {
        executor.shutdown();
        executor.awaitTermination(timeout, timeUnit);
    }

    public Collection<MonitorableFutureTask> getTasks() {
        return tasks.values();
    }

    List<MonitorableFutureTask> waitTasksToBeDone(int timeout, TimeUnit timeUnit) {
        return getTasks().stream().map(monitorableFutureTask -> {
            try {
                monitorableFutureTask.get(timeout, timeUnit);
            } catch (InterruptedException|ExecutionException|TimeoutException e) {
                logger.error("task interrupted while running", e);
            }
            return monitorableFutureTask;
        }).collect(toList());
    }

    List<MonitorableFutureTask> cleanDoneTasks() {
        return getTasks().stream().filter(FutureTask::isDone).map(t -> tasks.remove(t.toString())).collect(toList());
    }

    static class MonitorableFutureTask<V> extends FutureTask<V> implements Monitorable {
        private final Monitorable monitorable;
        MonitorableFutureTask(@NotNull Callable<V> callable) {
            super(callable);
            monitorable = getMonitorable(callable);
        }

        MonitorableFutureTask(@NotNull Runnable runnable, V result) {
            super(runnable, result);
            monitorable = getMonitorable(runnable);
        }

        private Monitorable getMonitorable(@NotNull Object runnableOrCallable) {
            if (runnableOrCallable instanceof Monitorable) {
                return (Monitorable) runnableOrCallable;
            }
            return () -> -2;
        }

        @Override
        public double getProgressRate() {
            return monitorable.getProgressRate();
        }
    }
}

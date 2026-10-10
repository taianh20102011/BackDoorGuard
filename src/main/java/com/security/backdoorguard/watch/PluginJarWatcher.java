package com.security.backdoorguard.watch;

import com.security.backdoorguard.BackdoorGuardPlugin;
import com.security.backdoorguard.logging.SecurityLogger;
import com.security.backdoorguard.scanner.JarScanner;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;

/** Recursive WatchService monitor. JARs are scanned after a debounce/stability window. */
public final class PluginJarWatcher implements AutoCloseable {
    private final BackdoorGuardPlugin plugin;
    private final JarScanner scanner;
    private final SecurityLogger logger;
    private final Path root;
    private final AtomicBoolean running = new AtomicBoolean();
    private final AtomicBoolean limitsWarned = new AtomicBoolean();
    private static final int MAX_WATCHED_DIRECTORIES = 4096;
    private static final int MAX_PENDING_SCANS = 1024;
    private final Map<WatchKey, Path> watchKeys = new ConcurrentHashMap<>();
    private final Map<Path, ScheduledFuture<?>> pending = new ConcurrentHashMap<>();
    private final ScheduledExecutorService debounce = Executors.newSingleThreadScheduledExecutor(r -> daemon(r, "BackdoorGuard-File-Debounce"));
    private volatile WatchService watchService;
    private volatile Thread watchThread;

    public PluginJarWatcher(BackdoorGuardPlugin plugin, JarScanner scanner, SecurityLogger logger) {
        this.plugin = plugin; this.scanner = scanner; this.logger = logger;
        this.root = plugin.getDataFolder().toPath().getParent().toAbsolutePath().normalize();
    }

    public synchronized void start() {
        if (!plugin.getConfig().getBoolean("jar-scanner.enabled", true) || !plugin.getConfig().getBoolean("jar-scanner.watch-enabled", true) || !running.compareAndSet(false, true)) return;
        try {
            Files.createDirectories(root);
            watchService = FileSystems.getDefault().newWatchService();
            try (Stream<Path> paths = Files.walk(root)) {
                paths.filter(path -> !Files.isSymbolicLink(path) && Files.isDirectory(path))
                        .forEach(this::registerQuietly);
            }
            watchThread = daemon(this::watchLoop, "BackdoorGuard-Plugin-Watcher");
            watchThread.start();
            logger.info(plugin.getMessages().get("watch.file-watcher-started", "path", root));
        } catch (IOException e) {
            running.set(false);
            logger.warning(plugin.getMessages().get("watch.file-watcher-failed", "error", safe(e)));
            closeService();
        }
    }

    public boolean isRunning() { return running.get(); }

    private void registerQuietly(Path dir) {
        if (!running.get() || watchService == null || Files.isSymbolicLink(dir)) return;
        if (watchKeys.size() >= MAX_WATCHED_DIRECTORIES) {
            if (limitsWarned.compareAndSet(false, true)) logger.warning("Plugin file watcher reached its directory limit; some subdirectories will not be monitored.");
            return;
        }
        try {
            if (!dir.toRealPath().startsWith(root.toRealPath())) return;
            WatchKey key = dir.register(watchService, StandardWatchEventKinds.ENTRY_CREATE,
                    StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_DELETE);
            watchKeys.put(key, dir);
        } catch (IOException | RuntimeException e) {
            logger.warning(plugin.getMessages().get("watch.directory-register-failed", "path", dir.getFileName(), "error", safe(e)));
        }
    }

    private void watchLoop() {
        while (running.get()) {
            WatchKey key;
            try { key = watchService.poll(1, TimeUnit.SECONDS); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
            catch (RuntimeException e) { if (running.get()) logger.warning("File watcher failed: " + safe(e)); break; }
            if (key == null) continue;
            Path dir = watchKeys.get(key);
            if (dir == null) { key.reset(); continue; }
            for (WatchEvent<?> event : key.pollEvents()) {
                if (event.kind() == StandardWatchEventKinds.OVERFLOW) continue;
                Object context = event.context();
                if (!(context instanceof Path relative)) continue;
                Path changed = dir.resolve(relative).toAbsolutePath().normalize();
                if (!changed.startsWith(root)) continue;
                if (event.kind() == StandardWatchEventKinds.ENTRY_CREATE && !Files.isSymbolicLink(changed) && Files.isDirectory(changed)) {
                    try (Stream<Path> paths = Files.walk(changed)) {
                        paths.filter(path -> !Files.isSymbolicLink(path) && Files.isDirectory(path))
                                .forEach(this::registerQuietly);
                    } catch (IOException e) { logger.warning("Could not register new plugin directory: " + safe(e)); }
                }
                String file = changed.getFileName() == null ? "" : changed.getFileName().toString().toLowerCase(java.util.Locale.ROOT);
                if (!file.endsWith(".jar")) continue;
                if (event.kind() == StandardWatchEventKinds.ENTRY_DELETE) {
                    cancelPending(changed);
                    logger.alert(plugin.getMessages().get("watch.jar-removed-title"),
                            plugin.getMessages().get("watch.jar-removed-detail", "file", changed.getFileName()));
                } else {
                    queueScan(changed, event.kind().name().toLowerCase(java.util.Locale.ROOT));
                }
            }
            if (!key.reset()) watchKeys.remove(key);
        }
    }

    private void queueScan(Path path, String reason) {
        if (pending.size() >= MAX_PENDING_SCANS && !pending.containsKey(path)) {
            if (limitsWarned.compareAndSet(false, true)) logger.warning("Plugin file watcher reached its pending-scan limit; additional file events are being throttled.");
            return;
        }
        try {
            ScheduledFuture<?> newFuture = debounce.schedule(() -> {
                pending.remove(path);
                if (!running.get() || !Files.isRegularFile(path) || Files.isSymbolicLink(path)) return;
                try {
                    long sizeBefore = Files.size(path);
                    long modifiedBefore = Files.getLastModifiedTime(path).toMillis();
                    Thread.sleep(350L);
                    long sizeAfter = Files.size(path);
                    long modifiedAfter = Files.getLastModifiedTime(path).toMillis();
                    if (sizeBefore != sizeAfter || modifiedBefore != modifiedAfter) {
                        // Upload/copy is still active; wait for the next quiet window.
                        queueScan(path, reason);
                        return;
                    }
                    scanner.scanFileAsync(path, reason);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                } catch (IOException ex) {
                    logger.warning(plugin.getMessages().get("watch.file-stability-check-failed",
                            "file", path.getFileName(), "error", safe(ex)));
                }
            }, Math.max(250, plugin.getConfig().getLong("jar-scanner.watch-debounce-ms", 1500)), TimeUnit.MILLISECONDS);
            ScheduledFuture<?> previous = pending.put(path, newFuture);
            if (previous != null) previous.cancel(false);
        } catch (java.util.concurrent.RejectedExecutionException ignored) {
            // The watcher is closing/reloading; no new work should be submitted.
        }
    }

    private void cancelPending(Path path) {
        ScheduledFuture<?> future = pending.remove(path);
        if (future != null) future.cancel(false);
    }

    @Override public synchronized void close() {
        running.set(false);
        for (ScheduledFuture<?> future : pending.values()) future.cancel(false);
        pending.clear();
        debounce.shutdownNow();
        closeService();
        Thread t = watchThread; if (t != null) t.interrupt();
        watchKeys.clear();
    }

    private void closeService() {
        WatchService service = watchService; watchService = null;
        if (service != null) try { service.close(); } catch (IOException ignored) { }
    }

    private static Thread daemon(Runnable r, String name) { Thread t = new Thread(r, name); t.setDaemon(true); return t; }
    private static String safe(Throwable e) { return e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage(); }
}

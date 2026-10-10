package com.security.backdoorguard.watch;

import com.security.backdoorguard.BackdoorGuardPlugin;
import com.security.backdoorguard.logging.SecurityLogger;
import org.bukkit.command.CommandExecutor;
import org.bukkit.event.HandlerList;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;

/** Detects deregistration/hijack of our protections and changes to the on-disk plugin JAR. */
public final class SelfIntegrityTask implements Runnable {
    private final BackdoorGuardPlugin plugin;
    private final SecurityLogger logger;
    private final CommandExecutor expectedExecutor;
    private final String commandName;
    private final Runnable reregisterListeners;
    private final Path sourceJar;
    private final CompletableFuture<String> baselineHash;
    private final AtomicBoolean hashCheckInFlight = new AtomicBoolean();
    private final AtomicBoolean sourceChangeReported = new AtomicBoolean();

    public SelfIntegrityTask(BackdoorGuardPlugin plugin, SecurityLogger logger, String commandName,
                             CommandExecutor expectedExecutor, Runnable reregisterListeners) {
        this.plugin = plugin;
        this.logger = logger;
        this.commandName = commandName;
        this.expectedExecutor = expectedExecutor;
        this.reregisterListeners = reregisterListeners;
        this.sourceJar = resolveSourceJar();
        this.baselineHash = CompletableFuture.supplyAsync(this::hashSource);
    }

    @Override public void run() {
        int listenerCount = HandlerList.getRegisteredListeners(plugin).size();
        int expectedCount = 1 + (plugin.getConfig().getBoolean("chat-trigger.enabled", true) ? 1 : 0);
        if (listenerCount < expectedCount) {
            String detail = plugin.getMessages().get("watch.self-listeners-detail", "expected", expectedCount, "actual", listenerCount);
            plugin.getLogger().severe(detail);
            HandlerList.unregisterAll(plugin);
            reregisterListeners.run();
            logger.alert(plugin.getMessages().get("watch.self-listeners"), detail);
        }
        var command = plugin.getServer().getPluginCommand(commandName);
        if (command != null && command.getExecutor() != expectedExecutor) {
            logger.alert(plugin.getMessages().get("watch.self-command-hijack"),
                    plugin.getMessages().get("watch.self-command-detail", "command", commandName));
        }
        checkSourceJarAsync();
    }

    private void checkSourceJarAsync() {
        if (sourceJar == null || !baselineHash.isDone() || !hashCheckInFlight.compareAndSet(false, true)) return;
        CompletableFuture.supplyAsync(this::hashSource).whenComplete((current, failure) -> {
            try {
                if (failure != null || current == null || current.isBlank()) return;
                String baseline = baselineHash.getNow("");
                if (!baseline.isBlank() && !baseline.equals(current) && sourceChangeReported.compareAndSet(false, true)) {
                    Path filename = sourceJar.getFileName();
                    logger.alert(plugin.getMessages().get("watch.source-integrity-change"),
                            plugin.getMessages().get("watch.source-integrity-detail", "file", filename == null ? "BackdoorGuard JAR" : filename.toString()));
                }
            } finally { hashCheckInFlight.set(false); }
        });
    }

    private Path resolveSourceJar() {
        try {
            if (plugin.getClass().getProtectionDomain() == null || plugin.getClass().getProtectionDomain().getCodeSource() == null) return null;
            URI uri = plugin.getClass().getProtectionDomain().getCodeSource().getLocation().toURI();
            Path path = Path.of(uri).toAbsolutePath().normalize();
            return Files.isRegularFile(path) ? path : null;
        } catch (Exception ignored) { return null; }
    }

    private String hashSource() {
        if (sourceJar == null || !Files.isRegularFile(sourceJar)) return "";
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (var in = Files.newInputStream(sourceJar)) {
                byte[] buffer = new byte[8192]; int read;
                while ((read = in.read(buffer)) != -1) digest.update(buffer, 0, read);
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (Exception ignored) { return ""; }
    }
}

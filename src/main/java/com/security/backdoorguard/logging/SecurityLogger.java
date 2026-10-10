package com.security.backdoorguard.logging;

import com.security.backdoorguard.i18n.LanguageManager;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import com.security.backdoorguard.BackdoorGuardPlugin;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/** Append-only security logs plus console, staff notification, and optional Discord delivery. */
public class SecurityLogger {
    private static final DateTimeFormatter FILE_DATE = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    private static final DateTimeFormatter LOG_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final BackdoorGuardPlugin plugin;
    private final Path logDir;
    private volatile boolean fileLoggingEnabled;
    private volatile boolean broadcastToAdmins;
    private volatile DiscordWebhook webhook;

    public SecurityLogger(BackdoorGuardPlugin plugin, boolean broadcastToAdmins, DiscordWebhook webhook) {
        this.plugin = plugin;
        this.logDir = plugin.getDataFolder().toPath().resolve("logs");
        this.fileLoggingEnabled = plugin.getConfig().getBoolean("logging.enabled", true);
        this.broadcastToAdmins = broadcastToAdmins;
        this.webhook = webhook;
        try {
            Files.createDirectories(logDir);
        } catch (IOException e) {
            plugin.getLogger().severe(plugin.getMessages().get("logger.create-dir-failed", "error", e.getMessage()));
        }
    }

    public void configure(boolean fileLoggingEnabled, boolean broadcastToAdmins, DiscordWebhook webhook) {
        this.fileLoggingEnabled = fileLoggingEnabled;
        this.broadcastToAdmins = broadcastToAdmins;
        this.webhook = webhook;
    }

    public void alert(String category, String detail) {
        String timestamp = LocalDateTime.now().format(LOG_TIME);
        String line = String.format("[%s] [%s] %s", timestamp, category, detail);
        writeToFile(line);
        plugin.getLogger().warning(line);

        if (broadcastToAdmins) {
            Runnable notify = () -> {
                for (Player player : Bukkit.getOnlinePlayers()) {
                    if (player.hasPermission("backdoorguard.notify")) {
                        player.sendMessage(plugin.getMessages().getForPlayer(player, "logger.broadcast",
                                "category", category, "detail", detail));
                    }
                }
            };
            if (Bukkit.isPrimaryThread()) notify.run();
            else {
                try { Bukkit.getScheduler().runTask(plugin, notify); }
                catch (IllegalStateException ignored) { }
            }
        }
        DiscordWebhook currentWebhook = webhook;
        if (currentWebhook != null) currentWebhook.sendAsync(category, detail, timestamp);
    }

    public void info(String message) {
        plugin.getLogger().info(message);
    }

    public void warning(String message) {
        plugin.getLogger().warning(message);
    }

    private synchronized void writeToFile(String line) {
        if (!fileLoggingEnabled) return;
        Path file = logDir.resolve("security-" + LocalDateTime.now().format(FILE_DATE) + ".log");
        try {
            Files.writeString(file, line + System.lineSeparator(), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            plugin.getLogger().severe(plugin.getMessages().get("logger.write-failed", "error", e.getMessage()));
        }
    }
}

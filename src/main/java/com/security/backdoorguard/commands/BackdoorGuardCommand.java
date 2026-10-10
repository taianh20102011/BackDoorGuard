package com.security.backdoorguard.commands;

import com.security.backdoorguard.BackdoorGuardPlugin;
import com.security.backdoorguard.scanner.JarScanner;
import org.bukkit.Bukkit;
import org.bukkit.OfflinePlayer;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.stream.Collectors;

public final class BackdoorGuardCommand implements CommandExecutor, TabCompleter {
    private final BackdoorGuardPlugin plugin;

    public BackdoorGuardCommand(BackdoorGuardPlugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public boolean onCommand(@NotNull CommandSender sender, @NotNull Command command,
                             @NotNull String label, String[] args) {
        if (!sender.hasPermission("backdoorguard.admin")) {
            sender.sendMessage(message(sender, "commands.no-permission"));
            return true;
        }
        if (args.length == 0) {
            sender.sendMessage(message(sender, "commands.usage"));
            return true;
        }

        switch (args[0].toLowerCase(Locale.ROOT)) {
            case "reload" -> {
                plugin.reloadPluginConfig();
                sender.sendMessage(message(sender, "commands.reload"));
            }
            case "status" -> handleStatus(sender);
            case "scan" -> handleScan(sender);
            case "trust" -> handleTrust(sender, args);
            case "vl" -> handleViolation(sender, args);
            case "cache" -> handleCache(sender, args);
            case "audit" -> handleAudit(sender);
            default -> sender.sendMessage(message(sender, "commands.usage"));
        }
        return true;
    }

    private void handleScan(CommandSender sender) {
        JarScanner scanner = plugin.getJarScanner();
        if (scanner.isScanning()) {
            sender.sendMessage(message(sender, "commands.scan-busy"));
            return;
        }
        sender.sendMessage(message(sender, "commands.scan-start"));
        scanner.scanAllAsync(summary -> sender.sendMessage(message(sender, "commands.scan-finish",
                "scanned", summary.scanned(), "alerts", summary.alerts(), "trusted", summary.trustedSkipped(),
                "cached", summary.cacheSkipped(), "errors", summary.errors())));
    }

    private void handleStatus(CommandSender sender) {
        sender.sendMessage(message(sender, "commands.status-title"));
        sender.sendMessage(message(sender, "commands.status-ops", "count", plugin.getWhitelistedOps().size()));
        sender.sendMessage(message(sender, "commands.status-keywords", "count", plugin.getSuspiciousKeywords().size()));
        sender.sendMessage(message(sender, "commands.status-webhook", "state",
                plugin.getWebhook().isEnabled() ? "ON" : "OFF"));
        sender.sendMessage(message(sender, "commands.status-command-map", "state",
                plugin.getCommandMapWatcher().isAvailable() ? "ON" : "OFF"));
        sender.sendMessage(message(sender, "commands.status-trusted", "count",
                plugin.getConfig().getStringList("trusted-jar-hashes").size()));
        sender.sendMessage(message(sender, "plugin.language", "language", plugin.getMessages().getLanguage()));
        sender.sendMessage(message(sender, "commands.status-scanner", "state",
                plugin.getJarScanner().isScanning() ? "SCANNING" : "IDLE"));
        sender.sendMessage(message(sender, "commands.status-file-watcher", "state",
                plugin.getPluginJarWatcher() != null && plugin.getPluginJarWatcher().isRunning() ? "ON" : "OFF"));
    }

    private void handleTrust(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(message(sender, "commands.trust-usage"));
            return;
        }
        String supplied = args[1];
        if (supplied.contains("/") || supplied.contains("\\") || supplied.contains(":")
                || supplied.equals(".") || supplied.equals("..") || supplied.contains("..")) {
            sender.sendMessage(message(sender, "commands.trust-invalid-name"));
            return;
        }
        String jarName = supplied.toLowerCase(Locale.ROOT).endsWith(".jar") ? supplied : supplied + ".jar";
        if (!jarName.matches("(?i)[A-Za-z0-9 _().-]+\\.jar")) {
            sender.sendMessage(message(sender, "commands.trust-invalid-name"));
            return;
        }

        final File jarFile;
        final long originalSize;
        final long originalModified;
        try {
            File pluginsDir = plugin.getDataFolder().getParentFile().getCanonicalFile();
            File candidate = new File(pluginsDir, jarName).getCanonicalFile();
            if (!candidate.getParentFile().equals(pluginsDir) || !candidate.isFile()
                    || !Files.isRegularFile(candidate.toPath()) || Files.isSymbolicLink(candidate.toPath())) {
                sender.sendMessage(message(sender, "commands.trust-not-found", "file", jarName));
                return;
            }
            jarFile = candidate;
            originalSize = Files.size(jarFile.toPath());
            originalModified = Files.getLastModifiedTime(jarFile.toPath()).toMillis();
        } catch (Exception e) {
            sender.sendMessage(message(sender, "commands.trust-error", "error",
                    e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            return;
        }

        sender.sendMessage(message(sender, "commands.trust-hashing", "file", jarName));
        java.util.concurrent.CompletableFuture.supplyAsync(() -> {
            try {
                String hash = plugin.getJarScanner().computeHash(jarFile).toLowerCase(Locale.ROOT);
                if (Files.size(jarFile.toPath()) != originalSize
                        || Files.getLastModifiedTime(jarFile.toPath()).toMillis() != originalModified) {
                    throw new IOException("JAR changed while hashing; retry after the upload/copy has finished.");
                }
                return hash;
            } catch (Exception e) {
                throw new java.util.concurrent.CompletionException(e);
            }
        }).whenComplete((hash, failure) -> {
            Runnable complete = () -> {
                if (!plugin.isEnabled()) return;
                if (failure != null || hash == null) {
                    Throwable cause = failure;
                    while (cause != null && cause.getCause() != null) cause = cause.getCause();
                    sender.sendMessage(message(sender, "commands.trust-error", "error",
                            cause == null || cause.getMessage() == null ? "Hashing failed" : cause.getMessage()));
                    return;
                }
                List<String> trusted = new ArrayList<>(plugin.getConfig().getStringList("trusted-jar-hashes"));
                if (trusted.stream().anyMatch(existing -> existing.equalsIgnoreCase(hash))) {
                    sender.sendMessage(message(sender, "commands.trust-already"));
                    return;
                }
                trusted.add(hash);
                plugin.getConfig().set("trusted-jar-hashes", trusted);
                plugin.saveConfig();
                sender.sendMessage(message(sender, "commands.trust-added", "file", jarName));
                sender.sendMessage(message(sender, "commands.trust-hash", "hash", hash));
                sender.sendMessage(message(sender, "commands.trust-warning"));
            };
            try { Bukkit.getScheduler().runTask(plugin, complete); }
            catch (IllegalStateException ignored) { /* Plugin/server is shutting down. */ }
        });
    }


    private void handleCache(CommandSender sender, String[] args) {
        if (args.length < 2 || !args[1].equalsIgnoreCase("clear")) {
            sender.sendMessage(message(sender, "commands.cache-usage"));
            return;
        }
        plugin.getJarScanner().clearCache();
        sender.sendMessage(message(sender, "commands.cache-cleared"));
    }

    private void handleAudit(CommandSender sender) {
        if (plugin.getPluginAuditTask() == null) {
            sender.sendMessage(message(sender, "commands.audit-unavailable"));
            return;
        }
        plugin.getPluginAuditTask().auditNow();
        sender.sendMessage(message(sender, "commands.audit-run"));
    }

    private void handleViolation(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(message(sender, "commands.vl-usage"));
            return;
        }
        OfflinePlayer target = Bukkit.getOfflinePlayer(args[1]);
        UUID id = target.getUniqueId();
        double score = plugin.getViolationManager().getScore(id);
        sender.sendMessage(message(sender, "commands.vl-score", "player", args[1],
                "score", String.format(Locale.ROOT, "%.0f", score)));
    }

    @Override
    public List<String> onTabComplete(@NotNull CommandSender sender, @NotNull Command command,
                                      @NotNull String alias, String[] args) {
        if (!sender.hasPermission("backdoorguard.admin")) return List.of();
        if (args.length == 1) {
            return List.of("reload", "status", "scan", "trust", "vl", "cache", "audit").stream()
                    .filter(option -> option.startsWith(args[0].toLowerCase(Locale.ROOT)))
                    .collect(Collectors.toList());
        }
        if (args.length == 2 && args[0].equalsIgnoreCase("cache")) {
            return List.of("clear").stream().filter(option -> option.startsWith(args[1].toLowerCase(Locale.ROOT))).collect(Collectors.toList());
        }
        if (args.length == 2 && args[0].equalsIgnoreCase("vl")) {
            return Bukkit.getOnlinePlayers().stream().map(player -> player.getName())
                    .filter(name -> name.toLowerCase(Locale.ROOT).startsWith(args[1].toLowerCase(Locale.ROOT)))
                    .collect(Collectors.toList());
        }
        if (args.length == 2 && args[0].equalsIgnoreCase("trust")) {
            File directory = plugin.getDataFolder().getParentFile();
            File[] jars = directory.listFiles((dir, name) -> name.toLowerCase(Locale.ROOT).endsWith(".jar"));
            if (jars == null) return List.of();
            String prefix = args[1].toLowerCase(Locale.ROOT);
            List<String> names = new ArrayList<>();
            for (File jar : jars) if (jar.getName().toLowerCase(Locale.ROOT).startsWith(prefix)) names.add(jar.getName());
            return names;
        }
        return List.of();
    }
    private String message(CommandSender sender, String key, Object... replacements) {
        if (sender instanceof org.bukkit.entity.Player player) {
            return plugin.getMessages().getForPlayer(player, key, replacements);
        }
        return plugin.getMessages().get(key, replacements);
    }

}

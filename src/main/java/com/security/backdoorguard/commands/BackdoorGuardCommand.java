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
            case "scan" -> handleScan(sender, args);
            case "list" -> handleList(sender);
            case "info" -> handleInfo(sender, args);
            case "trust" -> handleTrust(sender, args);
            case "untrust" -> handleUntrust(sender, args);
            case "profile" -> handleProfile(sender, args);
            case "lang" -> handleLanguage(sender, args);
            case "vl" -> handleViolation(sender, args);
            case "cache" -> handleCache(sender, args);
            case "audit" -> handleAudit(sender);
            default -> sender.sendMessage(message(sender, "commands.usage"));
        }
        return true;
    }

    private void handleScan(CommandSender sender, String[] args) {
        JarScanner scanner = plugin.getJarScanner();
        if (args.length >= 2 && !args[1].equalsIgnoreCase("all") && !args[1].equalsIgnoreCase("force")) {
            File file = scanner.findJar(args[1]);
            if (file == null) {
                sender.sendMessage(message(sender, "commands.scan-file-not-found", "file", args[1]));
                return;
            }
            sender.sendMessage(message(sender, "commands.scan-file-start", "file", file.getName()));
            scanner.scanFileAsync(file.toPath(), "manual command", finding -> sendFinding(sender, finding));
            return;
        }
        if (args.length >= 2 && args[1].equalsIgnoreCase("force")) scanner.clearCache();
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
        sender.sendMessage(message(sender, "commands.status-profile", "profile",
                plugin.getConfig().getString("setup.profile", "newbie")));
    }

    private void handleList(CommandSender sender) {
        List<JarScanner.Finding> reports = plugin.getJarScanner().allReports();
        if (reports.isEmpty()) {
            sender.sendMessage(message(sender, "commands.list-empty"));
            return;
        }
        sender.sendMessage(message(sender, "commands.list-header", "count", reports.size()));
        for (JarScanner.Finding finding : reports) {
            sender.sendMessage(message(sender, "commands.list-entry", "file", finding.file().getName(),
                    "score", String.format(Locale.ROOT, "%.0f", finding.score())));
        }
    }

    private void handleInfo(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(message(sender, "commands.info-usage"));
            return;
        }
        File file = plugin.getJarScanner().findJar(args[1]);
        if (file == null) {
            sender.sendMessage(message(sender, "commands.scan-file-not-found", "file", args[1]));
            return;
        }
        sender.sendMessage(message(sender, "commands.scan-file-start", "file", file.getName()));
        plugin.getJarScanner().scanFileAsync(file.toPath(), "manual info", finding -> {
            if (finding == null) {
                sender.sendMessage(message(sender, "commands.info-clean", "file", file.getName()));
            } else {
                sendFinding(sender, finding);
            }
        });
    }

    private void sendFinding(CommandSender sender, JarScanner.Finding finding) {
        if (finding == null) return;
        sender.sendMessage(message(sender, "commands.info-header", "file", finding.file().getName(),
                "score", String.format(Locale.ROOT, "%.0f", finding.score()),
                "severity", plugin.getMessages().get(plugin.getJarScanner().classifyScore(finding.score()).key())));
        for (String detail : finding.details()) sender.sendMessage(detail);
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
            File candidate = plugin.getJarScanner().findJar(jarName);
            if (candidate == null || !candidate.isFile()
                    || !Files.isRegularFile(candidate.toPath()) || Files.isSymbolicLink(candidate.toPath())) {
                sender.sendMessage(message(sender, "commands.trust-not-found", "file", jarName));
                return;
            }
            jarFile = candidate.getCanonicalFile();
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


    private void handleUntrust(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(message(sender, "commands.untrust-usage"));
            return;
        }
        String supplied = args[1].trim();
        if (supplied.matches("(?i)[a-f0-9]{64}")) {
            removeTrustedHash(sender, supplied.toLowerCase(Locale.ROOT), supplied);
            return;
        }
        if (supplied.contains("/") || supplied.contains("\\") || supplied.contains(":")
                || supplied.contains("..") || !supplied.matches("(?i)[A-Za-z0-9 _().-]+(?:\\.jar)?")) {
            sender.sendMessage(message(sender, "commands.trust-invalid-name"));
            return;
        }
        File jar = plugin.getJarScanner().findJar(supplied);
        if (jar == null) {
            sender.sendMessage(message(sender, "commands.untrust-not-found", "file", supplied));
            return;
        }
        sender.sendMessage(message(sender, "commands.untrust-hashing", "file", jar.getName()));
        JarScanner scanner = plugin.getJarScanner();
        java.util.concurrent.CompletableFuture.supplyAsync(() -> {
            try { return scanner.computeHash(jar); }
            catch (Exception e) { throw new java.util.concurrent.CompletionException(e); }
        }).whenComplete((hash, failure) -> {
            Runnable complete = () -> {
                if (!plugin.isEnabled()) return;
                if (failure != null || hash == null) {
                    Throwable cause = failure;
                    while (cause != null && cause.getCause() != null) cause = cause.getCause();
                    sender.sendMessage(message(sender, "commands.trust-error", "error",
                            cause == null || cause.getMessage() == null ? "Hashing failed" : cause.getMessage()));
                } else {
                    removeTrustedHash(sender, hash, jar.getName());
                }
            };
            try { Bukkit.getScheduler().runTask(plugin, complete); }
            catch (IllegalStateException ignored) { }
        });
    }

    private void removeTrustedHash(CommandSender sender, String hash, String displayName) {
        List<String> trusted = new ArrayList<>(plugin.getConfig().getStringList("trusted-jar-hashes"));
        boolean removed = trusted.removeIf(existing -> existing != null && existing.equalsIgnoreCase(hash));
        if (!removed) {
            sender.sendMessage(message(sender, "commands.untrust-not-found", "file", displayName));
            return;
        }
        plugin.getConfig().set("trusted-jar-hashes", trusted);
        plugin.saveConfig();
        sender.sendMessage(message(sender, "commands.untrust-removed", "file", displayName));
    }

    private void handleProfile(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(message(sender, "commands.profile-usage"));
            return;
        }
        String profile = args[1].toLowerCase(Locale.ROOT);
        if (!profile.equals("newbie") && !profile.equals("senior")) {
            sender.sendMessage(message(sender, "commands.profile-usage"));
            return;
        }
        plugin.getConfig().set("setup.profile", profile);
        plugin.saveConfig();
        plugin.reloadPluginConfig();
        sender.sendMessage(message(sender, "commands.profile-changed", "profile", profile));
    }

    private void handleLanguage(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(message(sender, "commands.lang-usage"));
            return;
        }
        if (!plugin.getMessages().isSupported(args[1])) {
            sender.sendMessage(message(sender, "commands.lang-unknown", "language", args[1]));
            return;
        }
        plugin.getMessages().setLanguage(args[1]);
        sender.sendMessage(message(sender, "commands.lang-changed", "language", plugin.getMessages().getLanguage()));
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
            return List.of("reload", "status", "scan", "list", "info", "trust", "untrust", "profile", "lang", "vl", "cache", "audit").stream()
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
        if (args.length == 2 && (args[0].equalsIgnoreCase("trust") || args[0].equalsIgnoreCase("untrust") || args[0].equalsIgnoreCase("scan") || args[0].equalsIgnoreCase("info"))) {
            String prefix = args[1].toLowerCase(Locale.ROOT);
            List<String> names = new ArrayList<>();
            File directory = plugin.getDataFolder().getParentFile();
            try (var paths = (com.security.backdoorguard.config.ConfigProfile.recursiveScan(plugin)
                    ? Files.walk(directory.toPath()) : Files.list(directory.toPath()))) {
                paths.filter(Files::isRegularFile)
                        .filter(path -> !Files.isSymbolicLink(path))
                        .filter(path -> path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".jar"))
                        .map(path -> path.getFileName().toString())
                        .filter(name -> name.toLowerCase(Locale.ROOT).startsWith(prefix))
                        .distinct().limit(200).forEach(names::add);
            } catch (IOException ignored) { /* Tab completion is best-effort. */ }
            if (args[0].equalsIgnoreCase("scan") && "all".startsWith(prefix)) names.add("all");
            return names;
        }
        if (args.length == 2 && args[0].equalsIgnoreCase("profile")) {
            return List.of("newbie", "senior").stream().filter(p -> p.startsWith(args[1].toLowerCase(Locale.ROOT))).toList();
        }
        if (args.length == 2 && args[0].equalsIgnoreCase("lang")) {
            return java.util.Arrays.stream(com.security.backdoorguard.i18n.LanguageManager.SUPPORTED)
                    .filter(code -> code.toLowerCase(Locale.ROOT).startsWith(args[1].toLowerCase(Locale.ROOT))).toList();
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

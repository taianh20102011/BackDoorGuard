package com.security.backdoorguard.config;

import com.security.backdoorguard.BackdoorGuardPlugin;
import org.bukkit.configuration.file.FileConfiguration;

import java.util.Locale;

/** Resolves beginner-friendly preset settings or advanced, per-rule configuration. */
public final class ConfigProfile {
    private ConfigProfile() {}

    public static boolean isNewbie(BackdoorGuardPlugin plugin) {
        return !"senior".equals(profile(plugin));
    }

    public static String profile(BackdoorGuardPlugin plugin) {
        String value = plugin.getConfig().getString("setup.profile", "newbie");
        if (value == null) return "newbie";
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return normalized.equals("senior") ? "senior" : "newbie";
    }

    /** Beginner sensitivity is intentionally a one-setting control for the full scanner. */
    public static double alertThreshold(BackdoorGuardPlugin plugin) {
        FileConfiguration c = plugin.getConfig();
        if (!isNewbie(plugin)) return clamp(c.getDouble("jar-scanner.alert-threshold", 40), 5, 200);
        String sensitivity = c.getString("setup.newbie.sensitivity", "balanced");
        if (sensitivity == null) sensitivity = "balanced";
        return switch (sensitivity.trim().toLowerCase(Locale.ROOT)) {
            case "low-noise", "quiet", "conservative" -> 55.0;
            case "high", "strict", "sensitive" -> 28.0;
            default -> 40.0;
        };
    }


    public static double highThreshold(BackdoorGuardPlugin plugin) {
        FileConfiguration c = plugin.getConfig();
        if (!isNewbie(plugin)) return clamp(c.getDouble("jar-scanner.high-threshold", 70), 10, 500);
        String sensitivity = c.getString("setup.newbie.sensitivity", "balanced");
        if (sensitivity == null) sensitivity = "balanced";
        return switch (sensitivity.trim().toLowerCase(Locale.ROOT)) {
            case "low-noise", "quiet", "conservative" -> 85.0;
            case "high", "strict", "sensitive" -> 55.0;
            default -> 70.0;
        };
    }

    public static double criticalThreshold(BackdoorGuardPlugin plugin) {
        FileConfiguration c = plugin.getConfig();
        if (!isNewbie(plugin)) return clamp(c.getDouble("jar-scanner.critical-threshold", 120), 20, 1000);
        String sensitivity = c.getString("setup.newbie.sensitivity", "balanced");
        if (sensitivity == null) sensitivity = "balanced";
        return switch (sensitivity.trim().toLowerCase(Locale.ROOT)) {
            case "low-noise", "quiet", "conservative" -> 150.0;
            case "high", "strict", "sensitive" -> 100.0;
            default -> 120.0;
        };
    }

    public static boolean recursiveScan(BackdoorGuardPlugin plugin) {
        FileConfiguration c = plugin.getConfig();
        return isNewbie(plugin)
                ? c.getBoolean("setup.newbie.scan-subfolders", true)
                : c.getBoolean("jar-scanner.recursive", true);
    }

    public static boolean watchFiles(BackdoorGuardPlugin plugin) {
        FileConfiguration c = plugin.getConfig();
        return isNewbie(plugin)
                ? c.getBoolean("setup.newbie.watch-for-file-changes", true)
                : c.getBoolean("jar-scanner.watch-enabled", true);
    }

    public static boolean scanResources(BackdoorGuardPlugin plugin) {
        FileConfiguration c = plugin.getConfig();
        return isNewbie(plugin)
                ? c.getBoolean("setup.newbie.scan-text-resources", true)
                : c.getBoolean("jar-scanner.scan-resource-files", true);
    }

    public static boolean inspectEncodedContent(BackdoorGuardPlugin plugin) {
        FileConfiguration c = plugin.getConfig();
        return isNewbie(plugin)
                ? c.getBoolean("setup.newbie.inspect-encoded-content", true)
                : c.getBoolean("jar-scanner.encoded-string-check", true);
    }

    public static int workerThreads(BackdoorGuardPlugin plugin) {
        FileConfiguration c = plugin.getConfig();
        if (!isNewbie(plugin)) return clamp(c.getInt("jar-scanner.worker-threads", 2), 1, 4);
        String speed = c.getString("setup.newbie.scan-speed", "balanced");
        if (speed == null) speed = "balanced";
        return switch (speed.trim().toLowerCase(Locale.ROOT)) {
            case "low", "eco", "low-impact" -> 1;
            case "fast", "high", "performance" -> 4;
            default -> 2;
        };
    }

    public static boolean broadcastToAdmins(BackdoorGuardPlugin plugin) {
        FileConfiguration c = plugin.getConfig();
        return isNewbie(plugin)
                ? c.getBoolean("setup.newbie.notify-staff", true)
                : c.getBoolean("logging.broadcast-to-admins", true);
    }

    public static boolean pluginAuditEnabled(BackdoorGuardPlugin plugin) {
        FileConfiguration c = plugin.getConfig();
        return isNewbie(plugin)
                ? c.getBoolean("setup.newbie.audit-runtime", true)
                : c.getBoolean("plugin-audit.enabled", true);
    }

    private static int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }

    private static double clamp(double value, double min, double max) {
        return Math.max(min, Math.min(max, value));
    }
}

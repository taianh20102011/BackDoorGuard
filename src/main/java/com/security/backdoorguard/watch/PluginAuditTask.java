package com.security.backdoorguard.watch;

import com.security.backdoorguard.BackdoorGuardPlugin;
import com.security.backdoorguard.logging.SecurityLogger;
import org.bukkit.plugin.Plugin;

import java.net.URI;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/** Periodically audits loaded plugin identities and the code-source locations of their classes. */
public final class PluginAuditTask implements Runnable {
    private final BackdoorGuardPlugin plugin;
    private final SecurityLogger logger;
    private final Path pluginsRoot;
    private final Map<String, String> baseline = new LinkedHashMap<>();
    private final Map<String, String> externalSources = new LinkedHashMap<>();
    private boolean captured;

    public PluginAuditTask(BackdoorGuardPlugin plugin, SecurityLogger logger) {
        this.plugin = plugin; this.logger = logger;
        pluginsRoot = plugin.getDataFolder().toPath().getParent().toAbsolutePath().normalize();
    }

    public void captureBaseline() {
        baseline.clear();
        for (Plugin loaded : plugin.getServer().getPluginManager().getPlugins()) baseline.put(key(loaded), loaded.getDescription().getMain());
        captured = true;
        logger.info(plugin.getMessages().get("audit.baseline", "count", baseline.size()));
        auditSources(false);
    }

    @Override public void run() { auditNow(); }

    public void auditNow() {
        if (!captured) { captureBaseline(); return; }
        Map<String, String> current = new LinkedHashMap<>();
        for (Plugin loaded : plugin.getServer().getPluginManager().getPlugins()) current.put(key(loaded), loaded.getDescription().getMain());
        for (Map.Entry<String, String> e : current.entrySet()) {
            String oldMain = baseline.get(e.getKey());
            if (oldMain == null) {
                logger.alert(plugin.getMessages().get("audit.new-plugin-title"),
                        plugin.getMessages().get("audit.new-plugin-detail", "name", e.getKey(), "main", e.getValue()));
            } else if (!oldMain.equals(e.getValue())) {
                logger.alert(plugin.getMessages().get("audit.identity-change-title"),
                        plugin.getMessages().get("audit.identity-change-detail", "name", e.getKey(), "old", oldMain, "main", e.getValue()));
            }
        }
        auditSources(true);
        baseline.clear(); baseline.putAll(current);
    }

    private void auditSources(boolean alert) {
        if (!plugin.getConfig().getBoolean("plugin-audit.check-source-path", true)) return;
        for (Plugin loaded : plugin.getServer().getPluginManager().getPlugins()) {
            try {
                if (loaded.getClass().getProtectionDomain() == null || loaded.getClass().getProtectionDomain().getCodeSource() == null) continue;
                URI uri = loaded.getClass().getProtectionDomain().getCodeSource().getLocation().toURI();
                Path source = Path.of(uri).toAbsolutePath().normalize();
                String name = key(loaded);
                if (!source.startsWith(pluginsRoot)) {
                    String previous = externalSources.put(name, source.toString());
                    if (alert && !source.toString().equals(previous)) {
                        logger.alert(plugin.getMessages().get("audit.external-source-title"),
                                plugin.getMessages().get("audit.external-source-detail", "name", loaded.getName(), "source", safePath(source)));
                    }
                } else externalSources.remove(name);
            } catch (Exception ignored) { /* Some classloaders intentionally hide their code source. */ }
        }
    }

    private static String key(Plugin p) { return p.getName().toLowerCase(Locale.ROOT); }
    private static String safePath(Path p) {
        Path file = p.getFileName();
        return file == null ? "<unknown>" : "…/" + file;
    }
}

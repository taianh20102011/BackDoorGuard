package com.security.backdoorguard;

import com.security.backdoorguard.commands.BackdoorGuardCommand;
import com.security.backdoorguard.config.ConfigProfile;
import com.security.backdoorguard.i18n.LanguageManager;
import com.security.backdoorguard.listeners.ChatTriggerListener;
import com.security.backdoorguard.listeners.CommandGuardListener;
import com.security.backdoorguard.logging.DiscordWebhook;
import com.security.backdoorguard.logging.SecurityLogger;
import com.security.backdoorguard.scanner.JarScanner;
import com.security.backdoorguard.violation.ViolationManager;
import com.security.backdoorguard.violation.Weights;
import com.security.backdoorguard.util.KeywordMatcher;
import com.security.backdoorguard.watch.CommandMapWatcher;
import com.security.backdoorguard.watch.OpWatcherTask;
import com.security.backdoorguard.watch.PluginJarWatcher;
import com.security.backdoorguard.watch.PluginAuditTask;
import com.security.backdoorguard.watch.JvmArgumentAudit;
import com.security.backdoorguard.watch.SelfIntegrityTask;
import org.bukkit.event.HandlerList;
import org.bukkit.scheduler.BukkitTask;
import org.bukkit.plugin.java.JavaPlugin;

import java.util.ArrayList;
import java.util.List;

public final class BackdoorGuardPlugin extends JavaPlugin {
    private LanguageManager messages;
    private SecurityLogger securityLogger;
    private DiscordWebhook webhook;
    private JarScanner jarScanner;
    private ViolationManager violationManager;
    private CommandMapWatcher commandMapWatcher;
    private PluginJarWatcher pluginJarWatcher;
    private PluginAuditTask pluginAuditTask;
    private CommandGuardListener commandGuardListener;
    private ChatTriggerListener chatTriggerListener;
    private BackdoorGuardCommand commandExecutor;
    private List<String> whitelistedOps = List.of();
    private List<String> suspiciousKeywords = List.of();
    private volatile KeywordMatcher keywordMatcher = new KeywordMatcher(List.of());
    private Weights weights;
    private final List<BukkitTask> backgroundTasks = new ArrayList<>();

    @Override
    public void onEnable() {
        saveDefaultConfig();
        messages = new LanguageManager(this);
        messages.reload();
        loadFromConfig();

        webhook = new DiscordWebhook(this, getConfig().getString("discord.webhook-url", ""),
                getConfig().getString("discord.username", "BackdoorGuard"));
        securityLogger = new SecurityLogger(this, ConfigProfile.broadcastToAdmins(this), webhook);
        jarScanner = new JarScanner(this, securityLogger);
        JvmArgumentAudit.inspect(this, securityLogger);
        pluginJarWatcher = new PluginJarWatcher(this, jarScanner, securityLogger);
        pluginAuditTask = new PluginAuditTask(this, securityLogger);
        commandMapWatcher = new CommandMapWatcher(this, securityLogger);
        violationManager = createViolationManager();
        violationManager.start();

        chatTriggerListener = new ChatTriggerListener();
        commandGuardListener = new CommandGuardListener(this);
        registerListeners();

        commandExecutor = new BackdoorGuardCommand(this);
        var command = getCommand("bguard");
        if (command != null) {
            command.setExecutor(commandExecutor);
            command.setTabCompleter(commandExecutor);
        } else {
            getLogger().severe(messages.get("plugin.command-missing"));
        }

        scheduleBackgroundTasks();
        getLogger().info(messages.get("plugin.enabled"));
        getLogger().info(messages.get("plugin.language", "language", messages.getLanguage()));
    }

    private ViolationManager createViolationManager() {
        return new ViolationManager(this, securityLogger,
                getConfig().getDouble("violation.decay-per-interval", 5),
                Math.max(20, getConfig().getLong("violation.decay-interval-seconds", 60) * 20L),
                getConfig().getDouble("violation.restrict-threshold", 150),
                getConfig().getDouble("violation.kick-threshold", 250),
                getConfig().getLong("violation.restrict-duration-seconds", 60));
    }

    private void registerListeners() {
        if (commandGuardListener != null) getServer().getPluginManager().registerEvents(commandGuardListener, this);
        if (getConfig().getBoolean("chat-trigger.enabled", true) && chatTriggerListener != null) {
            getServer().getPluginManager().registerEvents(chatTriggerListener, this);
        }
    }

    private void scheduleBackgroundTasks() {
        if (getConfig().getBoolean("jar-scanner.enabled", true)) {
            backgroundTasks.add(getServer().getScheduler().runTaskLater(this, () -> jarScanner.scanAll(), 20L));
        }
        if (pluginJarWatcher != null) pluginJarWatcher.start();

        if (ConfigProfile.pluginAuditEnabled(this)) {
            long pluginAuditBaselineTicks = Math.max(1, getConfig().getLong("plugin-audit.baseline-delay-seconds", 15)) * 20L;
            long pluginAuditIntervalTicks = Math.max(10, getConfig().getLong("plugin-audit.check-interval-seconds", 60)) * 20L;
            backgroundTasks.add(getServer().getScheduler().runTaskLater(this, () -> {
                if (pluginAuditTask != null) pluginAuditTask.captureBaseline();
                backgroundTasks.add(getServer().getScheduler().runTaskTimer(this, pluginAuditTask, pluginAuditIntervalTicks, pluginAuditIntervalTicks));
            }, pluginAuditBaselineTicks));
        }

        if (getConfig().getBoolean("command-map-watch.enabled", true) && commandMapWatcher.isAvailable()) {
            long baselineDelayTicks = Math.max(1, getConfig().getLong("command-map-watch.baseline-delay-seconds", 5)) * 20L;
            long checkIntervalTicks = Math.max(1, getConfig().getLong("command-map-watch.check-interval-seconds", 30)) * 20L;
            backgroundTasks.add(getServer().getScheduler().runTaskLater(this, () -> {
                commandMapWatcher.captureBaseline();
                backgroundTasks.add(getServer().getScheduler().runTaskTimer(this, commandMapWatcher::diffAndReport,
                        checkIntervalTicks, checkIntervalTicks));
            }, baselineDelayTicks));
        }

        long opWatchTicks = Math.max(1, getConfig().getLong("op-watch.interval-seconds", 2)) * 20L;
        backgroundTasks.add(getServer().getScheduler().runTaskTimer(this,
                new OpWatcherTask(this, chatTriggerListener,
                        getConfig().getLong("chat-trigger.correlation-window-seconds", 15)), 20L, opWatchTicks));

        long integrityTicks = Math.max(1, getConfig().getLong("self-integrity.interval-seconds", 30)) * 20L;
        backgroundTasks.add(getServer().getScheduler().runTaskTimer(this,
                new SelfIntegrityTask(this, securityLogger, "bguard", commandExecutor, this::registerListeners),
                integrityTicks, integrityTicks));
    }

    private void cancelBackgroundTasks() {
        for (BukkitTask task : backgroundTasks) {
            if (task != null) task.cancel();
        }
        backgroundTasks.clear();
    }

    @Override
    public void onDisable() {
        cancelBackgroundTasks();
        if (violationManager != null) violationManager.stop();
        if (pluginJarWatcher != null) pluginJarWatcher.close();
        if (jarScanner != null) jarScanner.shutdown();
    }

    /** Re-applies service settings and restarts config-controlled scheduled checks. */
    public void reloadPluginConfig() {
        reloadConfig();
        messages.reload();
        loadFromConfig();
        if (webhook != null) webhook.configure(getConfig().getString("discord.webhook-url", ""),
                getConfig().getString("discord.username", "BackdoorGuard"));
        if (securityLogger != null) securityLogger.configure(getConfig().getBoolean("logging.enabled", true),
                ConfigProfile.broadcastToAdmins(this), webhook);
        if (violationManager != null) {
            violationManager.configure(getConfig().getDouble("violation.decay-per-interval", 5),
                    Math.max(20, getConfig().getLong("violation.decay-interval-seconds", 60) * 20L),
                    getConfig().getDouble("violation.restrict-threshold", 150),
                    getConfig().getDouble("violation.kick-threshold", 250),
                    getConfig().getLong("violation.restrict-duration-seconds", 60));
        }

        cancelBackgroundTasks();
        if (pluginJarWatcher != null) pluginJarWatcher.close();
        if (jarScanner != null) jarScanner.shutdown();
        jarScanner = new JarScanner(this, securityLogger);
        if (commandMapWatcher != null) {
            // Recreate the watcher so the next baseline reflects the newly loaded configuration state.
            commandMapWatcher = new CommandMapWatcher(this, securityLogger);
        }
        pluginJarWatcher = new PluginJarWatcher(this, jarScanner, securityLogger);
        pluginAuditTask = new PluginAuditTask(this, securityLogger);
        HandlerList.unregisterAll(this);
        registerListeners();
        scheduleBackgroundTasks();
    }

    private void loadFromConfig() {
        whitelistedOps = getConfig().getStringList("whitelisted-ops").stream()
                .filter(value -> value != null && !value.isBlank())
                .map(String::trim)
                .filter(value -> !value.equalsIgnoreCase("TenAdminChinh") && !value.startsWith("<"))
                .distinct().toList();
        suspiciousKeywords = getConfig().getStringList("suspicious-keywords").stream()
                .filter(value -> value != null && !value.isBlank()).map(String::trim).distinct().toList();
        keywordMatcher = new KeywordMatcher(suspiciousKeywords);
        String selectedProfile = getConfig().getString("setup.profile", "newbie");
        if (selectedProfile == null || (!selectedProfile.equalsIgnoreCase("newbie") && !selectedProfile.equalsIgnoreCase("senior"))) {
            getLogger().warning("Unknown setup.profile; using newbie preset. Supported: newbie, senior.");
        }
        weights = new Weights(
                getConfig().getDouble("violation-weights.suspicious-keyword", 15),
                getConfig().getDouble("violation-weights.unregistered-command", 25),
                getConfig().getDouble("violation-weights.injected-command", 100),
                getConfig().getDouble("violation-weights.unauthorized-op", 200),
                getConfig().getDouble("violation-weights.chat-triggered-op", 300));
    }

    public LanguageManager getMessages() { return messages; }
    public List<String> getWhitelistedOps() { return whitelistedOps; }
    public List<String> getSuspiciousKeywords() { return suspiciousKeywords; }
    public KeywordMatcher getKeywordMatcher() { return keywordMatcher; }
    public Weights getWeights() { return weights; }
    public DiscordWebhook getWebhook() { return webhook; }
    public JarScanner getJarScanner() { return jarScanner; }
    public SecurityLogger getSecurityLogger() { return securityLogger; }
    public ViolationManager getViolationManager() { return violationManager; }
    public CommandMapWatcher getCommandMapWatcher() { return commandMapWatcher; }
    public PluginJarWatcher getPluginJarWatcher() { return pluginJarWatcher; }
    public PluginAuditTask getPluginAuditTask() { return pluginAuditTask; }
}

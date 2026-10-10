package com.security.backdoorguard.listeners;

import com.security.backdoorguard.BackdoorGuardPlugin;
import com.security.backdoorguard.violation.ViolationManager;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;

import java.util.Locale;
import java.util.regex.Pattern;

/** Monitors execution of late-injected commands and configurable suspicious command names. */
public final class CommandGuardListener implements Listener {
    private final BackdoorGuardPlugin plugin;

    public CommandGuardListener(BackdoorGuardPlugin plugin) {
        this.plugin = plugin;
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onCommandPreprocess(PlayerCommandPreprocessEvent event) {
        Player player = event.getPlayer();
        if (player.hasPermission("backdoorguard.bypass")) return;
        String message = event.getMessage();
        if (message == null || message.length() < 2 || message.charAt(0) != '/') return;

        ViolationManager manager = plugin.getViolationManager();
        if (manager.isRestricted(player)) {
            event.setCancelled(true);
            player.sendMessage(plugin.getMessages().getForPlayer(player, "guard.restricted"));
            return;
        }

        String commandPart = message.substring(1).stripLeading();
        if (commandPart.isEmpty()) return;
        String baseCommand = commandPart.split("\\s+", 2)[0].toLowerCase(Locale.ROOT);
        if (baseCommand.isBlank()) return;
        String lowerMessage = message.toLowerCase(Locale.ROOT);

        ViolationManager.Action worst = ViolationManager.Action.NONE;
        worst = escalate(worst, checkInjectedCommand(player, baseCommand, message));
        worst = escalate(worst, checkSuspiciousKeyword(player, baseCommand, lowerMessage, message));
        worst = escalate(worst, checkUnknownCommand(player, baseCommand, message));
        applyAction(player, event, worst);
    }

    private ViolationManager.Action checkInjectedCommand(Player player, String baseCommand, String message) {
        if (!plugin.getCommandMapWatcher().isConfirmedInjected(baseCommand)) return ViolationManager.Action.NONE;
        return plugin.getViolationManager().addViolation(player,
                plugin.getMessages().get("violation.injected-category"), plugin.getWeights().injectedCommand(),
                plugin.getMessages().get("violation.injected-reason", "message", message));
    }

    private ViolationManager.Action checkSuspiciousKeyword(Player player, String baseCommand,
                                                            String lowerMessage, String message) {
        // A normally registered command such as /ban or /vault is not suspicious by name alone.
        // Late-registered commands are still scored independently by the injected-command check.
        if (plugin.getConfig().getBoolean("command-guard.ignore-known-commands", true)
                && plugin.getCommandMapWatcher().isKnownCommand(baseCommand)
                && !plugin.getCommandMapWatcher().isConfirmedInjected(baseCommand)) {
            return ViolationManager.Action.NONE;
        }
        for (String keyword : plugin.getSuspiciousKeywords()) {
            if (keyword == null || keyword.isBlank()) continue;
            if (matchesWord(baseCommand, keyword.toLowerCase(Locale.ROOT))) {
                return plugin.getViolationManager().addViolation(player,
                        plugin.getMessages().get("violation.suspicious-category"),
                        plugin.getWeights().suspiciousKeyword(),
                        plugin.getMessages().get("violation.keyword-reason", "keyword", keyword, "message", message));
            }
        }
        return ViolationManager.Action.NONE;
    }

    private ViolationManager.Action checkUnknownCommand(Player player, String baseCommand, String message) {
        // Unknown/typoed commands are not proof of a backdoor. This optional signal is off by default.
        if (!plugin.getConfig().getBoolean("command-guard.detect-unknown-command-attempts", false)) {
            return ViolationManager.Action.NONE;
        }
        if (plugin.getCommandMapWatcher().isKnownCommand(baseCommand)) return ViolationManager.Action.NONE;
        return plugin.getViolationManager().addViolation(player,
                plugin.getMessages().get("violation.unknown-category"), plugin.getWeights().unregisteredCommand(),
                plugin.getMessages().get("violation.unknown-reason", "message", message));
    }

    private ViolationManager.Action escalate(ViolationManager.Action current, ViolationManager.Action next) {
        return next.ordinal() > current.ordinal() ? next : current;
    }

    private void applyAction(Player player, PlayerCommandPreprocessEvent event, ViolationManager.Action action) {
        switch (action) {
            case RESTRICT -> {
                event.setCancelled(true);
                player.sendMessage(plugin.getMessages().getForPlayer(player, "guard.command-restricted"));
            }
            case KICK -> {
                event.setCancelled(true);
                Bukkit.getScheduler().runTask(plugin, () -> {
                    if (player.isOnline()) player.kickPlayer(plugin.getMessages().getForPlayer(player, "guard.command-kicked"));
                });
            }
            case NONE -> { }
        }
    }

    private boolean matchesWord(String text, String keyword) {
        return Pattern.compile("(?i)(^|[^a-z0-9])" + Pattern.quote(keyword) + "([^a-z0-9]|$)")
                .matcher(text).find();
    }
}

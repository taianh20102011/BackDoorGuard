package com.security.backdoorguard.watch;

import com.security.backdoorguard.BackdoorGuardPlugin;
import com.security.backdoorguard.listeners.ChatTriggerListener;
import org.bukkit.Bukkit;
import org.bukkit.OfflinePlayer;
import org.bukkit.entity.Player;

import java.util.Locale;

/** Periodically audits actual operator status because Bukkit has no OP-change event. */
public class OpWatcherTask implements Runnable {
    private final BackdoorGuardPlugin plugin;
    private final ChatTriggerListener chatTriggerListener;
    private final long correlationWindowMillis;
    private boolean firstRun = true;
    private boolean warnedEmptyWhitelist = false;

    public OpWatcherTask(BackdoorGuardPlugin plugin, ChatTriggerListener chatTriggerListener,
                         long correlationWindowSeconds) {
        this.plugin = plugin;
        this.chatTriggerListener = chatTriggerListener;
        this.correlationWindowMillis = Math.max(0, correlationWindowSeconds) * 1000L;
    }

    @Override
    public void run() {
        long now = System.currentTimeMillis();
        if (plugin.getWhitelistedOps().isEmpty()) {
            if (!warnedEmptyWhitelist) {
                plugin.getLogger().warning(plugin.getMessages().get("watch.empty-op-whitelist"));
                warnedEmptyWhitelist = true;
            }
            firstRun = false;
            return; // Fail safe: never strip every operator because the administrator forgot the list.
        }
        for (OfflinePlayer op : Bukkit.getOperators()) {
            String name = op.getName() != null ? op.getName() : op.getUniqueId().toString();
            if (isAllowed(name, op.getUniqueId().toString())) continue;

            // Remove the unauthorized privilege immediately, including for offline accounts.
            op.setOp(false);
            Player online = op.getPlayer();
            if (online == null) {
                String context = plugin.getMessages().get(firstRun ? "watch.op-startup-context" : "watch.op-runtime-context");
                plugin.getSecurityLogger().alert(plugin.getMessages().get("watch.unauthorized-op"),
                        plugin.getMessages().get("watch.unauthorized-op-offline", "name", name, "context", context));
                continue;
            }

            Long triggerTime = chatTriggerListener.getRecentTriggerTimestamp(online.getUniqueId());
            boolean correlated = triggerTime != null && now >= triggerTime && now - triggerTime <= correlationWindowMillis;
            if (correlated) chatTriggerListener.clear(online.getUniqueId());

            String category = plugin.getMessages().get(correlated ? "watch.chat-op" : "watch.unauthorized-op");
            String reason;
            if (correlated) {
                reason = plugin.getMessages().get("watch.chat-op-detail");
            } else {
                reason = plugin.getMessages().get(firstRun ? "watch.op-detail-startup" : "watch.op-detail-runtime");
            }
            plugin.getViolationManager().addViolation(online,
                    correlated ? plugin.getMessages().get("violation.chat-op-category") : plugin.getMessages().get("violation.op-category"),
                    correlated ? plugin.getWeights().chatTriggeredOp() : plugin.getWeights().unauthorizedOp(), reason);
            // OP has already been removed; disconnect the affected online account on the main thread.
            Bukkit.getScheduler().runTask(plugin, () -> {
                if (online.isOnline()) online.kickPlayer(plugin.getMessages().getForPlayer(online, "watch.op-kick"));
            });
        }
        firstRun = false;
    }

    private boolean isAllowed(String name, String uuid) {
        return plugin.getWhitelistedOps().stream().filter(v -> v != null)
                .anyMatch(v -> v.equalsIgnoreCase(name) || v.equalsIgnoreCase(uuid));
    }
}

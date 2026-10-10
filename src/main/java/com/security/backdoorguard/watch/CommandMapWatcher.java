package com.security.backdoorguard.watch;

import com.security.backdoorguard.logging.SecurityLogger;
import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.SimpleCommandMap;
import org.bukkit.plugin.Plugin;
import com.security.backdoorguard.BackdoorGuardPlugin;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Kiem tra "Unregistered Command" don gian (Bukkit.getPluginCommand == null) chi bat duoc
 * mot phan: mot backdoor co the tu dang ky thang vao SimpleCommandMap bang Reflection ma
 * KHONG can khai bao trong plugin.yml, va co the CO' Y delay vai giay sau khi enable de
 * tranh cac scanner quet luc boot.
 *
 * Co che nay chup lai toan bo danh sach lenh THAT trong SimpleCommandMap mot lan sau khi
 * server da khoi dong xong, roi dinh ky so sanh voi hien tai. Bat ky lenh moi nao xuat hien
 * SAU thoi diem chup anh, ma khong phai do chinh admin reload/install plugin moi, deu la
 * dau hieu manh cua injection ngam.
 *
 * Dung Bukkit.getServer().getClass().getMethod("getCommandMap") thay vi cast truc tiep ve
 * CraftServer, vi ten package CraftServer thay doi theo tung phien ban Minecraft (NMS) -
 * cach nay hoat dong on dinh qua cac version ma khong can cap nhat lai code.
 */
public class CommandMapWatcher {

    private final BackdoorGuardPlugin plugin;
    private final SecurityLogger logger;
    private final Set<String> baselineLabels = ConcurrentHashMap.newKeySet();
    private final Set<String> confirmedInjected = ConcurrentHashMap.newKeySet();
    private SimpleCommandMap commandMap;
    private boolean available = false;

    public CommandMapWatcher(BackdoorGuardPlugin plugin, SecurityLogger logger) {
        this.plugin = plugin;
        this.logger = logger;
        try {
            Method m = Bukkit.getServer().getClass().getMethod("getCommandMap");
            this.commandMap = (SimpleCommandMap) m.invoke(Bukkit.getServer());
            this.available = true;
        } catch (Exception e) {
            plugin.getLogger().warning(plugin.getMessages().get("watch.command-map-unavailable", "error",
                    e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
        }
    }

    public boolean isAvailable() {
        return available;
    }

    /** Goi 1 lan sau khi server khoi dong xong (delay vai giay) de lam anh chup goc. */
    public void captureBaseline() {
        if (!available) return;
        baselineLabels.clear();
        baselineLabels.addAll(currentLabels());
        plugin.getLogger().info(plugin.getMessages().get("watch.command-map-baseline", "count", baselineLabels.size()));
    }

    /** Goi dinh ky de so sanh voi anh chup goc; tra ve so lenh moi phat hien them. */
    public int diffAndReport() {
        if (!available || baselineLabels.isEmpty()) return 0;

        Map<String, Command> currentCommands = currentCommands();
        Set<String> current = currentCommands.keySet();
        int newCount = 0;
        for (Map.Entry<String, Command> entry : currentCommands.entrySet()) {
            String label = entry.getKey();
            if (!baselineLabels.contains(label) && confirmedInjected.add(label)) {
                newCount++;
                String owner = commandOwner(entry.getValue());
                logger.alert(plugin.getMessages().get("watch.injected-command"),
                        plugin.getMessages().get("watch.injected-command-detail", "command", label, "owner", owner));
            }
        }
        // Cap nhat baseline de khong bao lai lien tuc cung 1 lenh moi lan diff.
        baselineLabels.addAll(current);
        return newCount;
    }

    /** True if the command currently exists in Bukkit's command map. */
    public boolean isKnownCommand(String label) {
        if (!available || label == null || label.isBlank()) return false;
        return currentLabels().contains(label.toLowerCase(java.util.Locale.ROOT));
    }

    /** True if this command appeared after the captured startup baseline. */
    public boolean isConfirmedInjected(String label) {
        return confirmedInjected.contains(label.toLowerCase(java.util.Locale.ROOT));
    }

    private Set<String> currentLabels() { return currentCommands().keySet(); }

    private Map<String, Command> currentCommands() {
        try {
            Map<String, Command> known = commandMap.getKnownCommands();
            Map<String, Command> normalized = new java.util.LinkedHashMap<>();
            for (Map.Entry<String, Command> entry : known.entrySet()) {
                if (entry.getKey() != null && entry.getValue() != null) normalized.put(entry.getKey().toLowerCase(java.util.Locale.ROOT), entry.getValue());
            }
            return normalized;
        } catch (Exception e) { return Collections.emptyMap(); }
    }

    private static String commandOwner(Command command) {
        try {
            // PluginCommand exposes its owning JavaPlugin on Bukkit/Paper implementations.
            Method getter = command.getClass().getMethod("getPlugin");
            Object owner = getter.invoke(command);
            if (owner instanceof Plugin plugin) return plugin.getName();
        } catch (Exception ignored) { }
        return command.getClass().getName() + " (owner unavailable)";
    }
}

package com.security.backdoorguard.watch;

import com.security.backdoorguard.BackdoorGuardPlugin;
import com.security.backdoorguard.logging.SecurityLogger;

import java.lang.management.ManagementFactory;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

/** Reports high-impact JVM injection/patch flags; detection is informational, never auto-blocking. */
public final class JvmArgumentAudit {
    private JvmArgumentAudit() {}
    public static void inspect(BackdoorGuardPlugin plugin, SecurityLogger logger) {
        if (!plugin.getConfig().getBoolean("jvm-audit.enabled", true)) return;
        List<String> args = ManagementFactory.getRuntimeMXBean().getInputArguments();
        List<String> allowed = plugin.getConfig().getStringList("jvm-audit.allowed-agents").stream()
                .filter(value -> value != null && !value.isBlank())
                .map(value -> value.toLowerCase(Locale.ROOT).trim()).toList();
        for (String arg : args) {
            String lower = arg.toLowerCase(Locale.ROOT);
            boolean risky = lower.startsWith("-javaagent:") || lower.startsWith("-agentlib:")
                    || lower.startsWith("-agentpath:") || lower.startsWith("-xbootclasspath")
                    || lower.startsWith("--patch-module") || lower.startsWith("-djava.system.class.loader=");
            if (!risky) continue;
            boolean permitted = allowed.stream().anyMatch(lower::contains);
            if (permitted) continue;
            String display = summarize(arg);
            logger.alert(plugin.getMessages().get("audit.jvm-flag-title"),
                    plugin.getMessages().get("audit.jvm-flag-detail", "argument", display));
        }
    }
    private static String summarize(String arg) {
        // Never echo full agent/module/class-loader paths or option payloads into logs.
        if (arg.startsWith("--patch-module")) {
            int equals = arg.indexOf('=');
            return (equals >= 0 ? arg.substring(0, equals) : "--patch-module") + "=<path-hidden>";
        }
        if (arg.regionMatches(true, 0, "-Djava.system.class.loader=", 0,
                "-Djava.system.class.loader=".length())) {
            return "-Djava.system.class.loader=<value-hidden>";
        }
        int colon = arg.indexOf(':');
        String head = colon >= 0 ? arg.substring(0, colon + 1) : arg;
        if (colon < 0) return head;
        String value = arg.substring(colon + 1);
        int equals = value.indexOf('='); if (equals >= 0) value = value.substring(0, equals);
        try {
            Path file = Path.of(value).getFileName();
            return head + (file == null ? "<path-hidden>" : "…/" + file);
        } catch (RuntimeException e) { return head + "<path-hidden>"; }
    }
}

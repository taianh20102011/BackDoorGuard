package com.security.backdoorguard.logging;

import com.security.backdoorguard.BackdoorGuardPlugin;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Locale;
import java.util.Set;

/** Optional asynchronous Discord notification client; it never blocks the server tick thread. */
public final class DiscordWebhook {
    private static final Set<String> ALLOWED_HOSTS = Set.of("discord.com", "discordapp.com", "canary.discord.com", "ptb.discord.com");
    private final BackdoorGuardPlugin plugin;
    private final HttpClient client;
    private volatile String webhookUrl;
    private volatile String username;

    public DiscordWebhook(BackdoorGuardPlugin plugin, String webhookUrl, String username) {
        this.plugin = plugin;
        this.client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
        configure(webhookUrl, username);
    }

    public void configure(String webhookUrl, String username) {
        this.webhookUrl = webhookUrl == null ? "" : webhookUrl.trim();
        this.username = username == null || username.isBlank() ? "BackdoorGuard" : username;
        if (!this.webhookUrl.isBlank() && !isValidWebhook(this.webhookUrl)) {
            plugin.getLogger().warning(plugin.getMessages().get("logger.discord-invalid-webhook"));
            this.webhookUrl = "";
        }
    }

    public boolean isEnabled() {
        return webhookUrl != null && !webhookUrl.isBlank();
    }

    public void sendAsync(String category, String detail, String timestamp) {
        String url = webhookUrl;
        if (url == null || url.isBlank()) return;
        try {
            String content = String.format("**[%s]** %s\n> %s", category, timestamp, detail);
            if (content.length() > 1900) content = content.substring(0, 1897) + "...";
            String body = String.format("{\"username\":\"%s\",\"content\":\"%s\"}", jsonEscape(username), jsonEscape(content));
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(8))
                    .header("Content-Type", "application/json; charset=utf-8")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            client.sendAsync(request, HttpResponse.BodyHandlers.discarding())
                    .thenAccept(response -> {
                        if (response.statusCode() < 200 || response.statusCode() >= 300) {
                            plugin.getLogger().warning(plugin.getMessages().get("logger.discord-http-status", "status", response.statusCode()));
                        }
                    })
                    .exceptionally(ex -> {
                        plugin.getLogger().warning(plugin.getMessages().get("logger.discord-failed", "error", safeMessage(ex)));
                        return null;
                    });
        } catch (RuntimeException ex) {
            plugin.getLogger().warning(plugin.getMessages().get("logger.discord-failed", "error", safeMessage(ex)));
        }
    }

    private static boolean isValidWebhook(String value) {
        try {
            URI uri = URI.create(value);
            return "https".equalsIgnoreCase(uri.getScheme()) && uri.getHost() != null
                    && ALLOWED_HOSTS.contains(uri.getHost().toLowerCase(Locale.ROOT))
                    && uri.getPath() != null && uri.getPath().startsWith("/api/webhooks/");
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private static String jsonEscape(String value) {
        StringBuilder out = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\' -> out.append("\\\\");
                case '"' -> out.append("\\\"");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> { if (c < 0x20) out.append(String.format("\\u%04x", (int) c)); else out.append(c); }
            }
        }
        return out.toString();
    }

    private static String safeMessage(Throwable ex) {
        Throwable cause = ex.getCause() == null ? ex : ex.getCause();
        return cause.getMessage() == null ? cause.getClass().getSimpleName() : cause.getMessage();
    }
}

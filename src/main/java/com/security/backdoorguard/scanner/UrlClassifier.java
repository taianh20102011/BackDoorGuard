package com.security.backdoorguard.scanner;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Classifies common exfiltration/command-and-control URL indicators without logging full URLs. */
final class UrlClassifier {
    enum Kind { WEBHOOK, TELEGRAM, PASTE, TUNNEL, IP, CUSTOM }
    private record UrlPattern(Kind kind, String needle, String sample) {}

    private static final List<UrlPattern> PATTERNS = List.of(
            new UrlPattern(Kind.WEBHOOK, "discord.com/api/webhooks/", "Discord webhook URL"),
            new UrlPattern(Kind.WEBHOOK, "discordapp.com/api/webhooks/", "Discord webhook URL"),
            new UrlPattern(Kind.TELEGRAM, "api.telegram.org/bot", "Telegram Bot API URL"),
            new UrlPattern(Kind.PASTE, "pastebin.com", "pastebin.com"),
            new UrlPattern(Kind.PASTE, "paste.ee", "paste.ee"),
            new UrlPattern(Kind.PASTE, "hastebin.com", "hastebin.com"),
            new UrlPattern(Kind.PASTE, "ghostbin", "ghostbin host"),
            new UrlPattern(Kind.PASTE, "rentry.co", "rentry.co"),
            new UrlPattern(Kind.PASTE, "controlc.com", "controlc.com"),
            new UrlPattern(Kind.PASTE, "justpaste.it", "justpaste.it"),
            new UrlPattern(Kind.PASTE, "termbin.com", "termbin.com"),
            new UrlPattern(Kind.PASTE, "transfer.sh", "transfer.sh"),
            new UrlPattern(Kind.PASTE, "gofile.io", "gofile.io"),
            new UrlPattern(Kind.PASTE, "file.io", "file.io"),
            new UrlPattern(Kind.PASTE, "raw.githubusercontent.com", "raw.githubusercontent.com"),
            new UrlPattern(Kind.PASTE, "gist.githubusercontent.com", "gist.githubusercontent.com"),
            new UrlPattern(Kind.PASTE, "cdn.discordapp.com/attachments", "Discord attachment URL"),
            new UrlPattern(Kind.PASTE, "media.discordapp.net/attachments", "Discord attachment URL"),
            new UrlPattern(Kind.PASTE, "0x0.st", "0x0.st"),
            new UrlPattern(Kind.PASTE, "temp.sh", "temp.sh"),
            new UrlPattern(Kind.TUNNEL, "ngrok.io", "ngrok tunnel"),
            new UrlPattern(Kind.TUNNEL, "ngrok-free.app", "ngrok tunnel"),
            new UrlPattern(Kind.TUNNEL, "ngrok.app", "ngrok tunnel"),
            new UrlPattern(Kind.TUNNEL, "ngrok.dev", "ngrok tunnel"),
            new UrlPattern(Kind.TUNNEL, "serveo.net", "serveo tunnel"),
            new UrlPattern(Kind.TUNNEL, "duckdns.org", "dynamic DNS host"),
            new UrlPattern(Kind.TUNNEL, "no-ip.", "dynamic DNS host"),
            new UrlPattern(Kind.TUNNEL, "ddns.net", "dynamic DNS host"),
            new UrlPattern(Kind.TUNNEL, "hopto.org", "dynamic DNS host"),
            new UrlPattern(Kind.TUNNEL, "zapto.org", "dynamic DNS host"),
            new UrlPattern(Kind.TUNNEL, "sytes.net", "dynamic DNS host"),
            new UrlPattern(Kind.TUNNEL, "trycloudflare.com", "Cloudflare tunnel"),
            new UrlPattern(Kind.TUNNEL, "loca.lt", "local tunnel"),
            new UrlPattern(Kind.TUNNEL, "localtonet", "local tunnel"),
            new UrlPattern(Kind.TUNNEL, "pagekite.me", "pagekite tunnel"),
            new UrlPattern(Kind.TUNNEL, "servehttp.com", "tunnel host")
    );
    private static final Pattern IPV4 = Pattern.compile(
            "(?:(https?|tcp|udp|ws|wss)://)?((?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)){3})(?::(\\d{2,5}))?");

    private UrlClassifier() {}

    static Map<Kind, String> classifyAll(String content, List<String> extraHosts) {
        Map<Kind, String> found = new LinkedHashMap<>();
        if (content == null || content.length() < 8 || content.length() > 2_000_000) return found;
        String lower = content.toLowerCase(Locale.ROOT);
        for (UrlPattern pattern : PATTERNS) {
            boolean pathMarker = pattern.needle().contains("/");
            if ((pathMarker ? lower.contains(pattern.needle()) : containsHostToken(lower, pattern.needle()))) {
                found.putIfAbsent(pattern.kind(), pattern.sample());
            }
        }
        if (extraHosts != null) {
            for (String host : extraHosts) {
                if (host == null || host.isBlank()) continue;
                String normalizedHost = host.toLowerCase(Locale.ROOT);
                if (containsHostToken(lower, normalizedHost)) {
                    found.putIfAbsent(Kind.CUSTOM, host.length() > 60 ? host.substring(0, 60) : host);
                }
            }
        }
        Matcher matcher = IPV4.matcher(content);
        while (matcher.find()) {
            boolean hasContext = matcher.group(1) != null || matcher.group(3) != null;
            if (!hasContext || isPrivateOrLocal(matcher.group(2))) continue;
            found.putIfAbsent(Kind.IP, "public IPv4 endpoint" + (matcher.group(3) == null ? "" : " with port"));
            break;
        }
        return found;
    }

    private static boolean containsHostToken(String text, String host) {
        int from = 0;
        while ((from = text.indexOf(host, from)) >= 0) {
            int end = from + host.length();
            boolean leftOk = from == 0 || !isHostChar(text.charAt(from - 1));
            boolean rightOk = end >= text.length() || !isHostChar(text.charAt(end));
            if (leftOk && rightOk) return true;
            from = Math.max(end, from + 1);
        }
        return false;
    }

    private static boolean isHostChar(char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == '_';
    }

    private static boolean isPrivateOrLocal(String ip) {
        String[] p = ip.split("\\.");
        int a = Integer.parseInt(p[0]);
        int b = Integer.parseInt(p[1]);
        if (a == 0 || a == 10 || a == 127 || a >= 224) return true;
        if (a == 169 && b == 254) return true;
        if (a == 172 && b >= 16 && b <= 31) return true;
        if (a == 192 && b == 168) return true;
        return a == 100 && b >= 64 && b <= 127;
    }
}

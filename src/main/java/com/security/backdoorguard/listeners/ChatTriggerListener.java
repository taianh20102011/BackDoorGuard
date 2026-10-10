package com.security.backdoorguard.listeners;

import com.security.backdoorguard.util.EntropyUtil;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerChatEvent;

import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Rat nhieu backdoor khong kich hoat bang lenh (/xyz) ma bang mot CAU CHAT THUONG chua
 * mot "mat khau" bi mat - vi vay CommandGuardListener khong the bat duoc kieu nay.
 *
 * Dung org.bukkit.event.player.AsyncPlayerChatEvent (KHONG dung Paper's AsyncChatEvent)
 * vi event nay tra ve thang mot String qua getMessage(), khong can bat ky serializer
 * Adventure nao (net.kyori.adventure.text.serializer.*) - cac module do duoc paper-api
 * khai bao voi scope "provided" trong chinh pom cua no nen KHONG duoc keo transitively
 * xuong project cua plugin, tung gay loi bien dich "package ... does not exist". De
 * tranh hoan toan van de nay, dung thang String co san la lua chon don gian va chac chan
 * nhat. AsyncPlayerChatEvent bi danh dau @Deprecated (khuyen dung AsyncChatEvent) nhung
 * Paper van goi no de tuong thich nguoc, nen van hoat dong binh thuong.
 *
 * Listener nay dung heuristic don gian de danh dau tin nhan CO THE la mot chuoi kich hoat:
 * mot "tu" duy nhat (khong khoang trang), do dai vua phai, va hoac la co ca chu+so xen ke
 * hoac co entropy cao (giong chuoi ngau nhien hon la tu ngu tu nhien). Day KHONG phai bang
 * chung chac chan (nguoi choi go 1 tu binh thuong van co the bi danh dau) nen tu no
 * KHONG bao dong ngay - chi duoc ghi lai voi timestamp de OpWatcherTask doi chieu:
 * neu nguoi vua go tin nhan dang ngo ma duoc phat hien co OP trong vai giay sau do, do la
 * tuong quan rat manh cho thay day la mot backdoor kich hoat bang chat.
 */
public class ChatTriggerListener implements Listener {

    private static final int MIN_LEN = 6;
    private static final int MAX_LEN = 40;
    private static final double ENTROPY_THRESHOLD = 4.0;

    private final Map<UUID, Long> recentTriggerTimestamps = new ConcurrentHashMap<>();

    @SuppressWarnings("deprecation")
    @EventHandler(ignoreCancelled = false)
    public void onChat(AsyncPlayerChatEvent event) {
        Player player = event.getPlayer();
        String text = event.getMessage().trim();

        if (looksLikeTrigger(text)) {
            recentTriggerTimestamps.put(player.getUniqueId(), System.currentTimeMillis());
        }
    }

    private boolean looksLikeTrigger(String text) {
        if (text.contains(" ") || text.length() < MIN_LEN || text.length() > MAX_LEN) {
            return false;
        }
        if (text.toLowerCase(Locale.ROOT).startsWith("http")) {
            return false; // link, khong phai trigger
        }

        boolean hasLetter = text.chars().anyMatch(Character::isLetter);
        boolean hasDigit = text.chars().anyMatch(Character::isDigit);
        boolean mixedAlnum = hasLetter && hasDigit;

        double entropy = EntropyUtil.shannonEntropy(text);

        return mixedAlnum || entropy >= ENTROPY_THRESHOLD;
    }

    /**
     * Tra ve timestamp (millis) cua tin nhan dang ngo gan nhat cua nguoi choi nay,
     * hoac null neu khong co / da qua lau. Noi goi tu chiu trach nhiem so sanh cua so thoi gian.
     */
    public Long getRecentTriggerTimestamp(UUID playerId) {
        return recentTriggerTimestamps.get(playerId);
    }

    public void clear(UUID playerId) {
        recentTriggerTimestamps.remove(playerId);
    }
}

package com.security.backdoorguard.violation;

import com.security.backdoorguard.logging.SecurityLogger;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import com.security.backdoorguard.BackdoorGuardPlugin;
import org.bukkit.scheduler.BukkitTask;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * He thong cham diem nghi van (Violation Level), cung tinh than voi VL system cua
 * TuTienAntiCheat: nhieu tin hieu nho cong don lai theo trong so, tu giam dan theo
 * thoi gian (decay) neu khong co hanh vi moi, va tu leo thang hanh dong khi vuot nguong.
 *
 * Ly do can cai nay thay vi "1 tu khoa = 1 canh bao": mot nguoi choi go nham 1 lenh
 * chua tu khoa nhay cam 1 lan khong phai backdoor. Nhung neu ho lien tuc go nhieu lenh
 * nghi van, hoac ket hop voi tin hieu manh hon (lenh an, chat trigger, cap OP la),
 * diem se cong don rat nhanh va he thong phan ung dut khoat hon.
 */
public class ViolationManager {

    public enum Action { NONE, RESTRICT, KICK }

    private record Entry(double score, long lastUpdate, long restrictedUntil) {}

    private final BackdoorGuardPlugin plugin;
    private final SecurityLogger logger;
    private final Map<UUID, Entry> scores = new ConcurrentHashMap<>();

    private volatile double decayPerInterval;
    private volatile long decayIntervalTicks;
    private volatile double restrictThreshold;
    private volatile double kickThreshold;
    private volatile long restrictDurationMillis;

    private BukkitTask decayTask;

    public ViolationManager(BackdoorGuardPlugin plugin, SecurityLogger logger,
                             double decayPerInterval, long decayIntervalTicks,
                             double restrictThreshold, double kickThreshold,
                             long restrictDurationSeconds) {
        this.plugin = plugin;
        this.logger = logger;
        this.decayPerInterval = Math.max(0, decayPerInterval);
        this.decayIntervalTicks = Math.max(20, decayIntervalTicks);
        this.restrictThreshold = Math.max(1, restrictThreshold);
        this.kickThreshold = Math.max(this.restrictThreshold, kickThreshold);
        this.restrictDurationMillis = Math.max(1, restrictDurationSeconds) * 1000L;
    }


    public void configure(double decayPerInterval, long decayIntervalTicks, double restrictThreshold,
                          double kickThreshold, long restrictDurationSeconds) {
        this.decayPerInterval = Math.max(0, decayPerInterval);
        this.decayIntervalTicks = Math.max(20, decayIntervalTicks);
        this.restrictThreshold = Math.max(1, restrictThreshold);
        this.kickThreshold = Math.max(this.restrictThreshold, kickThreshold);
        this.restrictDurationMillis = Math.max(1, restrictDurationSeconds) * 1000L;
        if (decayTask != null) {
            decayTask.cancel();
            decayTask = null;
        }
        if (plugin.isEnabled()) start();
    }

    public void start() {
        if (decayTask != null) decayTask.cancel();
        decayTask = Bukkit.getScheduler().runTaskTimer(plugin, this::decayAll,
                Math.max(20, decayIntervalTicks), Math.max(20, decayIntervalTicks));
    }

    public void stop() {
        if (decayTask != null) decayTask.cancel();
    }

    /**
     * Cong diem nghi van cho mot nguoi choi va tra ve hanh dong nen thuc hien.
     * Viec thuc thi hanh dong (kick, huy lenh...) do noi goi quyet dinh, ham nay
     * chi tinh toan va ghi log - giu tach biet logic cham diem khoi hanh dong Bukkit.
     */
    public Action addViolation(Player player, String category, double weight, String reason) {
        UUID id = player.getUniqueId();
        long now = System.currentTimeMillis();

        Entry prev = scores.get(id);
        double newScore = (prev != null ? prev.score() : 0) + Math.max(0, weight);
        long restrictedUntil = prev != null ? prev.restrictedUntil() : 0;

        Action action = Action.NONE;
        if (newScore >= kickThreshold) {
            action = Action.KICK;
        } else if (newScore >= restrictThreshold) {
            action = Action.RESTRICT;
            restrictedUntil = now + restrictDurationMillis;
        }

        scores.put(id, new Entry(newScore, now, restrictedUntil));

        logger.alert(category, plugin.getMessages().get("violation.score-line",
                "player", player.getName(), "score", String.format(java.util.Locale.ROOT, "%.0f", newScore), "reason", reason));

        return action;
    }

    /** True neu nguoi choi dang trong thoi gian bi han che lenh vi diem nghi van cao. */
    public boolean isRestricted(Player player) {
        Entry e = scores.get(player.getUniqueId());
        return e != null && e.restrictedUntil() > System.currentTimeMillis();
    }

    public double getScore(UUID id) {
        Entry e = scores.get(id);
        return e != null ? e.score() : 0;
    }

    public void reset(UUID id) {
        scores.remove(id);
    }

    private void decayAll() {
        long now = System.currentTimeMillis();
        scores.replaceAll((id, entry) -> new Entry(Math.max(0, entry.score() - decayPerInterval),
                entry.lastUpdate(), entry.restrictedUntil()));
        scores.entrySet().removeIf(entry -> entry.getValue().score() <= 0
                && entry.getValue().restrictedUntil() < now);
    }
}

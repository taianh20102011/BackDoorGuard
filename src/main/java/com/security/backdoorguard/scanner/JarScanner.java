package com.security.backdoorguard.scanner;

import com.security.backdoorguard.BackdoorGuardPlugin;
import com.security.backdoorguard.config.ConfigProfile;
import com.security.backdoorguard.analysis.BytecodeAnalyzer;
import com.security.backdoorguard.i18n.LanguageManager;
import com.security.backdoorguard.logging.SecurityLogger;
import com.security.backdoorguard.util.EntropyUtil;
import org.bukkit.Bukkit;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

/** Bounded static security scanner. It alerts only and never deletes/modifies plugin files. */
public final class JarScanner {
    private record Signature(String key, List<String> needles, double defaultWeight) {}
    public record Finding(File file, String hash, double score, List<String> details, boolean blocked) {}
    private record FileResult(Finding finding, boolean trusted, boolean oversized, boolean skippedCache, String error) {}
    private record ScanOutput(ScanSummary summary, List<Finding> findings, List<String> errors) {}
    public record ScanSummary(int scanned, int alerts, int trustedSkipped, int oversizedSkipped, int cacheSkipped, int errors) {}

    private static final String ANALYZER_VERSION = "hybrid-classfile-v5";
    private static final Set<String> LIBRARY_DAMPENABLE_SIGNATURES = Set.of(
            "runtime", "process-builder", "network", "socket", "classloader", "script-engine",
            "base64", "unsafe", "native-load", "deserialization", "jar-mutation");
    private static final List<Signature> SIGNATURES = List.of(
            new Signature("runtime", List.of("java/lang/Runtime", "java.lang.Runtime"), 18),
            new Signature("process-builder", List.of("java/lang/ProcessBuilder", "java.lang.ProcessBuilder"), 22),
            new Signature("network", List.of("java/net/HttpURLConnection", "java/net/http/HttpClient", "java/net/URL", "java/net/URLConnection", "java/net/http/WebSocket"), 8),
            new Signature("socket", List.of("java/net/Socket", "java/net/DatagramSocket", "java/nio/channels/SocketChannel", "java/net/ServerSocket"), 10),
            new Signature("classloader", List.of("java/net/URLClassLoader", "java/lang/ClassLoader.defineClass", "java/lang/invoke/MethodHandles$Lookup.defineClass", "java/lang/invoke/MethodHandles$Lookup.defineHiddenClass"), 10),
            new Signature("reflection", List.of("java/lang/reflect/Method", "java/lang/reflect/Field", "setAccessible", "java/lang/invoke/MethodHandles", "forName", "getDeclaredMethod", "getDeclaredField"), 5),
            new Signature("script-engine", List.of("javax/script/ScriptEngine", "javax/script/ScriptEngineManager", "getEngineByName"), 15),
            new Signature("op", List.of("setOp", "org/bukkit/OfflinePlayer.setOp", "org/bukkit/entity/Player.setOp"), 14),
            new Signature("permission-manipulation", List.of("addAttachment", "org/bukkit/permissions/PermissionAttachment.setPermission", "PermissionAttachment.setPermission"), 4),
            new Signature("dispatch-command", List.of("dispatchCommand", "org/bukkit/command/ConsoleCommandSender"), 5),
            new Signature("file-write", List.of("java/io/FileOutputStream", "java/nio/file/Files.write", "newOutputStream", "writeString", "deleteIfExists", "java/io/File.delete", "java/nio/file/Files.move"), 4),
            new Signature("file-read", List.of("java/io/FileInputStream", "java/nio/file/Files.readAllBytes", "java/nio/file/Files.readString", "java/io/RandomAccessFile", "java/util/Scanner.<init>"), 4),
            new Signature("base64", List.of("java/util/Base64", "sun/misc/BASE64Decoder", "javax/xml/bind/DatatypeConverter"), 4),
            new Signature("instrumentation", List.of("java/lang/instrument/Instrumentation", "Premain-Class", "Agent-Class", "Launcher-Agent-Class", "javaagent:"), 22),
            new Signature("unsafe", List.of("sun/misc/Unsafe", "jdk/internal/misc/Unsafe"), 10),
            new Signature("plugin-loading", List.of("loadPlugin", "loadPlugins", "enablePlugin", "disablePlugin"), 12),
            new Signature("chat-trigger", List.of("org/bukkit/event/player/AsyncPlayerChatEvent", "io/papermc/paper/event/player/AsyncChatEvent", "org/bukkit/event/player/PlayerCommandPreprocessEvent"), 3),
            new Signature("hook-removal", List.of("unregisterAll", "HandlerList.unregisterAll", "unregister"), 8),
            new Signature("credential-access", List.of("java/lang/System.getenv", "java/lang/System.getProperties", "java/net/Authenticator", "java/net/PasswordAuthentication", "java/security/KeyStore"), 9),
            new Signature("secret-terms", List.of("password", "passwd", "credential", "access_token", "access-token", "refresh_token", "refresh-token", "api_key", "api-key", "authorization", "session_id", "session-id", "private_key", "private-key"), 2),
            new Signature("outbound-upload", List.of("java/net/HttpURLConnection.getOutputStream", "java/net/http/HttpClient.send", "java/net/http/HttpClient.sendAsync", "java/net/Socket.getOutputStream", "java/net/URLConnection.getOutputStream"), 8),
            new Signature("native-load", List.of("java/lang/System.load", "java/lang/System.loadLibrary", "java/lang/Runtime.load", "java/lang/Runtime.loadLibrary"), 15),
            new Signature("deserialization", List.of("java/io/ObjectInputStream.readObject", "java/io/ObjectInputStream.readUnshared", "java/beans/XMLDecoder.readObject"), 7),
            new Signature("jar-mutation", List.of("java/util/jar/JarOutputStream", "java/util/zip/ZipOutputStream", "java/util/jar/JarFile", "java/util/zip/ZipFile"), 4)
    );

    private static final Pattern ENCODED_CANDIDATE = Pattern.compile("(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{44,}={0,2}(?![A-Za-z0-9+/=])");
    private static final Pattern CREDENTIAL_TERMS = Pattern.compile("(?i)(password|passwd|credential|access[_-]?token|refresh[_-]?token|api[_-]?key|authorization|session[_-]?id|discord.{0,10}webhook|private[_-]?key)");
    private static final Pattern RESOURCE_INDICATOR = Pattern.compile("(?is)(javaagent:|premain-class|agent-class|(?:https?://[^\\s\\\"']{5,180}\\.(?:jar|class)(?:\\?|$))|(?:download.{0,50}(?:jar|class|payload))|(?:setOp.{0,40}(?:true|1))|(?:Runtime\\.getRuntime.{0,80}exec))");
    private static final Pattern SUSPICIOUS_ENDPOINT = Pattern.compile("(?i)(https?://(?:[0-9]{1,3}\\.){3}[0-9]{1,3}(?::[0-9]{1,5})?(?:/[^\\s\\\"']*)?|https?://[^/\\s\\\"']+\\.onion(?:/[^\\s\\\"']*)?|https?://[^/\\s\\\"']*(?:ngrok(?:-free)?\\.(?:io|app)|trycloudflare\\.com|localtunnel\\.me|serveo\\.net|duckdns\\.org|pastebin\\.com/raw|paste\\.ee|rentry\\.co|transfer\\.sh)(?:/[^\\s\\\"']*)?)");
    private static final int MAX_ENCODED_HITS = 6;
    private static final int MAX_CACHE_ENTRIES = 15000;

    private final BackdoorGuardPlugin plugin;
    private final SecurityLogger logger;
    private final ExecutorService coordinator = Executors.newSingleThreadExecutor(namedDaemon("BackdoorGuard-Scan-Coordinator"));
    private final ExecutorService workers;
    private final Set<Path> fileScansInFlight = ConcurrentHashMap.newKeySet();
    private final Set<String> cleanCache = ConcurrentHashMap.newKeySet();
    private final Map<String, Finding> flaggedReports = new ConcurrentHashMap<>();
    private final Object cacheLock = new Object();
    private final Path cacheFile;
    private volatile boolean scanning;

    public JarScanner(BackdoorGuardPlugin plugin, SecurityLogger logger) {
        this.plugin = plugin;
        this.logger = logger;
        int threadCount = ConfigProfile.workerThreads(plugin);
        // Bound queued work so a burst of filesystem events cannot grow the heap without limit.
        // CallerRunsPolicy keeps pressure bounded and still runs scanner work off the Bukkit main thread.
        this.workers = new ThreadPoolExecutor(threadCount, threadCount, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(Math.max(64, threadCount * 32)), namedDaemon("BackdoorGuard-Scan-Worker"),
                new ThreadPoolExecutor.CallerRunsPolicy());
        this.cacheFile = plugin.getDataFolder().toPath().resolve("scan-cache.txt");
        loadCache();
    }

    private static ThreadFactory namedDaemon(String name) {
        return r -> { Thread t = new Thread(r, name); t.setDaemon(true); return t; };
    }

    public boolean isScanning() { return scanning; }

    /** Latest in-memory findings, ordered from highest to lowest score. */
    public List<Finding> allReports() {
        List<Finding> reports = new ArrayList<>(flaggedReports.values());
        reports.sort(Comparator.comparingDouble(Finding::score).reversed());
        return List.copyOf(reports);
    }

    /** Finds the latest report by basename (case-insensitive). */
    public Finding getReport(String jarName) {
        if (jarName == null) return null;
        return flaggedReports.values().stream()
                .filter(report -> report.file().getName().equalsIgnoreCase(jarName))
                .max(Comparator.comparingDouble(Finding::score)).orElse(null);
    }

    public void shutdown() {
        coordinator.shutdownNow(); workers.shutdownNow();
        try { workers.awaitTermination(2, TimeUnit.SECONDS); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    public CompletableFuture<ScanSummary> scanAllAsync(Consumer<ScanSummary> completion) {
        synchronized (this) {
            if (scanning) {
                ScanSummary busy = new ScanSummary(0, 0, 0, 0, 0, 0);
                dispatch(() -> { if (completion != null) completion.accept(busy); });
                return CompletableFuture.completedFuture(busy);
            }
            scanning = true;
        }
        return CompletableFuture.supplyAsync(this::scanAllWork, coordinator).handle((output, failure) -> {
            ScanOutput safe = output;
            if (failure != null || safe == null) {
                safe = new ScanOutput(new ScanSummary(0, 0, 0, 0, 0, 1), List.of(),
                        List.of("Scanner failure: " + (failure == null ? "unknown error" : safeMessage(failure))));
            }
            ScanOutput completed = safe;
            dispatch(() -> {
                try {
                    for (String error : completed.errors()) logScanError(error);
                    for (Finding f : completed.findings()) publish(f);
                    logger.info(plugin.getMessages().get("scanner.summary", "scanned", completed.summary().scanned(),
                            "alerts", completed.summary().alerts(), "trusted", completed.summary().trustedSkipped(),
                            "oversized", completed.summary().oversizedSkipped(), "cached", completed.summary().cacheSkipped(),
                            "errors", completed.summary().errors()));
                    if (completion != null) completion.accept(completed.summary());
                } finally { scanning = false; }
            });
            return completed.summary();
        });
    }

    public CompletableFuture<ScanSummary> scanAllAsync() { return scanAllAsync(null); }
    public void scanAll() { scanAllAsync(); }

    /** Queue a stable newly-created/changed plugin JAR for a bounded incremental scan. */
    public void scanFileAsync(Path candidate, String reason) {
        scanFileAsync(candidate, reason, null);
    }

    public void scanFileAsync(Path candidate, String reason, Consumer<Finding> completion) {
        if (!plugin.getConfig().getBoolean("jar-scanner.enabled", true)) return;
        Path root = plugin.getDataFolder().toPath().getParent().toAbsolutePath().normalize();
        Path path = candidate.toAbsolutePath().normalize();
        if (!path.startsWith(root) || Files.isSymbolicLink(path) || isSelfJar(path)
                || !path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".jar")) return;
        if (!fileScansInFlight.add(path)) {
            dispatch(() -> { if (completion != null) completion.accept(flaggedReports.get(reportKey(path))); });
            return;
        }
        CompletableFuture.supplyAsync(() -> scanChangedFile(path), workers).whenComplete((result, failure) -> {
            fileScansInFlight.remove(path);
            if (failure != null) {
                dispatch(() -> {
                    logger.warning(plugin.getMessages().get("scanner.scan-error", "file", path.getFileName(), "error", safeMessage(failure)));
                    if (completion != null) completion.accept(null);
                });
                return;
            }
            if (result == null) {
                dispatch(() -> { if (completion != null) completion.accept(null); });
                return;
            }
            saveCache();
            if (result.finding() != null) flaggedReports.put(reportKey(path), result.finding());
            else if (result.error() == null) flaggedReports.remove(reportKey(path));
            dispatch(() -> {
                if (result.error() != null) logScanError(path.getFileName() + "\0" + result.error());
                if (result.oversized()) logger.warning(plugin.getMessages().get("scanner.too-large-jar", "file", path.getFileName()));
                if (result.finding() != null) publish(result.finding());
                if (result.finding() == null && result.error() == null && !result.trusted() && !result.oversized() && !result.skippedCache()) {
                    if (plugin.getConfig().getBoolean("jar-scanner.alert-on-every-new-jar", false)) {
                        logger.alert(plugin.getMessages().get("watch.new-jar-title"),
                                plugin.getMessages().get("watch.new-jar-detail", "file", path.getFileName(), "reason", reason));
                    } else {
                        logger.info(plugin.getMessages().get("scanner.watch-clean", "file", path.getFileName(), "reason", reason));
                    }
                }
                if (completion != null) completion.accept(result.finding());
            });
        });
    }

    private static String reportKey(Path path) {
        return path.toAbsolutePath().normalize().toString();
    }

    private FileResult scanChangedFile(Path path) {
        try {
            if (!Files.isRegularFile(path) || Files.isSymbolicLink(path)) return null;
            Path realRoot = plugin.getDataFolder().toPath().getParent().toRealPath();
            if (!path.toRealPath().startsWith(realRoot)) return new FileResult(null, false, false, false, "resolved path is outside plugins directory");
            // Wait for uploads/copies to stop changing before opening the ZIP central directory.
            long previous = -1; int stable = 0;
            for (int i = 0; i < 8 && stable < 2; i++) {
                long current = Files.size(path);
                if (current == previous && current > 0) stable++; else stable = 0;
                previous = current;
                if (stable < 2) Thread.sleep(350L);
            }
            return scanOne(path);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); return new FileResult(null, false, false, false, "scan interrupted");
        } catch (Exception e) {
            return new FileResult(null, false, false, false, safeMessage(e));
        }
    }

    private ScanOutput scanAllWork() {
        List<Finding> findings = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        int scanned = 0, trusted = 0, oversized = 0, cached = 0;
        Path root = plugin.getDataFolder().toPath().getParent().toAbsolutePath().normalize();
        boolean recursive = ConfigProfile.recursiveScan(plugin);
        int maxJars = clamp(plugin.getConfig().getInt("jar-scanner.max-jars-per-scan", 500), 1, 10000);
        List<Path> jars = new ArrayList<>();
        try (Stream<Path> paths = recursive ? Files.walk(root) : Files.list(root)) {
            paths.filter(Files::isRegularFile)
                    .filter(p -> !Files.isSymbolicLink(p))
                    .filter(p -> !isSelfJar(p))
                    .filter(p -> p.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".jar"))
                    .sorted().limit(maxJars + 1L).forEach(jars::add);
        } catch (IOException e) {
            errors.add("\0Could not list plugin directory: " + safeMessage(e));
            return new ScanOutput(new ScanSummary(0, 0, 0, 0, 0, errors.size()), findings, errors);
        }
        if (jars.size() > maxJars) {
            jars = new ArrayList<>(jars.subList(0, maxJars));
            errors.add("\0JAR scan cap reached; remaining files were not scanned.");
        }
        List<CompletableFuture<FileResult>> futures = new ArrayList<>();
        for (Path jar : jars) futures.add(CompletableFuture.supplyAsync(() -> scanOne(jar), workers));
        for (int i = 0; i < futures.size(); i++) {
            Path jar = jars.get(i);
            try {
                FileResult result = futures.get(i).join();
                if (result == null) continue;
                if (result.error() != null) errors.add(jar.getFileName() + "\0" + result.error());
                if (result.finding() != null) {
                    findings.add(result.finding());
                    flaggedReports.put(reportKey(jar), result.finding());
                } else if (result.error() == null) {
                    flaggedReports.remove(reportKey(jar));
                }
                if (result.trusted()) trusted++;
                if (result.oversized()) oversized++;
                if (result.skippedCache()) cached++;
                if (!result.oversized() && result.error() == null && !result.skippedCache() && !result.trusted()) scanned++;
            } catch (RuntimeException ex) {
                errors.add(jar.getFileName() + "\0" + safeMessage(ex));
            }
        }
        saveCache();
        return new ScanOutput(new ScanSummary(scanned, findings.size(), trusted, oversized, cached, errors.size()), findings, errors);
    }

    private FileResult scanOne(Path path) {
        File file = path.toFile();
        try {
            if (Files.isSymbolicLink(path)) return new FileResult(null, false, false, false, "symbolic-link JAR paths are skipped");
            Path realRoot = plugin.getDataFolder().toPath().getParent().toRealPath();
            if (!path.toRealPath().startsWith(realRoot)) return new FileResult(null, false, false, false, "resolved JAR path is outside plugins directory");
            long maxJarBytes = mb(plugin.getConfig().getLong("jar-scanner.max-jar-size-mb", 256));
            if (Files.size(path) > maxJarBytes) return new FileResult(null, false, true, false, null);
            String hash = computeHash(file).toLowerCase(Locale.ROOT);
            Set<String> blocked = normalizeHashes(plugin.getConfig().getStringList("known-bad-jar-hashes"));
            Set<String> trusted = normalizeHashes(plugin.getConfig().getStringList("trusted-jar-hashes"));
            if (blocked.contains(hash)) {
                return new FileResult(new Finding(file, hash, 1000,
                        List.of(plugin.getMessages().get("scanner.blocked"), plugin.getMessages().get("scanner.hash-line", "hash", hash)), true), false, false, false, null);
            }
            if (trusted.contains(hash)) return new FileResult(null, true, false, false, null);
            String cacheKey = cacheKey(hash);
            if (cleanCache.contains(cacheKey)) return new FileResult(null, false, false, true, null);
            Finding finding = scanJar(file, hash);
            if (finding == null) addCleanCache(cacheKey);
            return new FileResult(finding, false, false, false, null);
        } catch (Exception e) {
            return new FileResult(null, false, false, false, safeMessage(e));
        }
    }

    /** Find a JAR by basename inside plugins/, without following symbolic links or accepting paths. */
    public File findJar(String requestedName) {
        if (requestedName == null || requestedName.isBlank() || requestedName.contains("/")
                || requestedName.contains("\\") || requestedName.equals(".") || requestedName.equals("..")) return null;
        String name = requestedName.toLowerCase(Locale.ROOT).endsWith(".jar")
                ? requestedName.toLowerCase(Locale.ROOT) : (requestedName + ".jar").toLowerCase(Locale.ROOT);
        Path root = plugin.getDataFolder().toPath().getParent().toAbsolutePath().normalize();
        boolean recursive = ConfigProfile.recursiveScan(plugin);
        try (Stream<Path> paths = recursive ? Files.walk(root) : Files.list(root)) {
            return paths.filter(Files::isRegularFile)
                    .filter(path -> !Files.isSymbolicLink(path) && !isSelfJar(path))
                    .filter(path -> path.getFileName().toString().equalsIgnoreCase(name))
                    .filter(path -> {
                        try { return path.toRealPath().startsWith(root.toRealPath()); }
                        catch (IOException ex) { return false; }
                    })
                    .sorted((a, b) -> {
                        int depth = Integer.compare(a.getNameCount(), b.getNameCount());
                        return depth != 0 ? depth : a.toString().compareToIgnoreCase(b.toString());
                    })
                    .findFirst().map(Path::toFile).orElse(null);
        } catch (IOException | RuntimeException ignored) {
            return null;
        }
    }

    private boolean isSelfJar(Path candidate) {
        try {
            File self = plugin.getFile();
            return self != null && candidate.toFile().getCanonicalFile().equals(self.getCanonicalFile());
        } catch (Exception ignored) {
            return false;
        }
    }

    public String computeHash(File jarFile) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream in = Files.newInputStream(jarFile.toPath())) {
            byte[] buffer = new byte[8192]; int read;
            while ((read = in.read(buffer)) != -1) digest.update(buffer, 0, read);
        }
        StringBuilder result = new StringBuilder(64);
        for (byte b : digest.digest()) result.append(String.format(Locale.ROOT, "%02x", b & 0xff));
        return result.toString();
    }

    private static final class Context {
        final Map<String, Set<String>> hits = new LinkedHashMap<>();
        final Set<String> encoded = new LinkedHashSet<>();
        final Set<String> decodedPayloads = new LinkedHashSet<>();
        final Set<String> obfuscatedIdentifiers = new LinkedHashSet<>();
        final Set<String> suspiciousEndpoints = new LinkedHashSet<>();
        final Map<String, String> urlIndicators = new LinkedHashMap<>();
        final Set<String> resourceFlags = new LinkedHashSet<>();
        final Set<String> extraHosts = new LinkedHashSet<>();
        final Set<String> libraryEntries = new HashSet<>();
        final Set<String> seenEntries = new HashSet<>();
        final List<String> structural = new ArrayList<>();
        long uncompressedRead;
        int entries, nestedArchives;
        boolean entryLimit;
        String mainClass;
        String pluginName;
        String expectedMainClass;
        boolean identityMismatch;
        boolean loadBeforeGuard;
    }

    private Finding scanJar(File file, String hash) throws IOException {
        Context c = new Context();
        for (String host : plugin.getConfig().getStringList("jar-scanner.extra-suspicious-hosts")) {
            String normalized = normalizeHost(host);
            if (!normalized.isBlank()) c.extraHosts.add(normalized);
        }
        long maxEntryBytes = Math.min(mb(plugin.getConfig().getLong("jar-scanner.max-entry-size-mb", 8)), mb(64));
        long maxTotalBytes = mb(plugin.getConfig().getLong("jar-scanner.max-uncompressed-mb-per-jar", 512));
        int maxEntries = clamp(plugin.getConfig().getInt("jar-scanner.max-entries-per-jar", 40000), 100, 250000);
        int maxNested = clamp(plugin.getConfig().getInt("jar-scanner.max-nested-archives-per-jar", 8), 0, 64);
        int maxDepth = clamp(plugin.getConfig().getInt("jar-scanner.max-nested-depth", 2), 0, 4);
        boolean scanResources = ConfigProfile.scanResources(plugin);
        boolean checkEncoded = ConfigProfile.inspectEncodedContent(plugin);
        try (ZipFile zip = new ZipFile(file)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory()) continue;
                if (++c.entries > maxEntries) { c.entryLimit = true; break; }
                String name = entry.getName();
                registerStructuralEntry(name, entry.getSize(), entry.getCompressedSize(), c);
                if (entry.getSize() > maxEntryBytes) {
                    c.structural.add("entry-size-limit");
                    continue;
                }
                if (entry.getSize() >= 0 && c.uncompressedRead + entry.getSize() > maxTotalBytes) {
                    c.structural.add("entry-limit");
                    c.entryLimit = true;
                    break;
                }
                if (!shouldInspect(name, scanResources) && !isArchiveName(name) && !hasClassOrZipMagic(zip, entry)) continue;
                byte[] bytes;
                try (InputStream in = zip.getInputStream(entry)) {
                    bytes = readBounded(in, (int) Math.min(maxEntryBytes, Integer.MAX_VALUE));
                } catch (IOException boundedReadFailure) {
                    // A forged central-directory size or malformed stream must not make the whole
                    // JAR look clean; record that scanning coverage was incomplete and continue.
                    c.structural.add("entry-size-limit");
                    continue;
                }
                c.uncompressedRead += bytes.length;
                if (c.uncompressedRead > maxTotalBytes) { c.entryLimit = true; break; }
                inspectEntry(name, bytes, 0, c, maxNested, maxDepth, maxEntryBytes, maxTotalBytes, maxEntries, scanResources, checkEncoded);
            }
        }
        if (c.entryLimit) c.structural.add("entry-limit");
        checkKnownPluginIdentity(c);

        double score = 0;
        List<String> details = new ArrayList<>();
        for (Signature signature : SIGNATURES) {
            Set<String> classes = c.hits.get(signature.key());
            if (classes != null && !classes.isEmpty()) {
                double weight = ruleWeight(signature.key(), signature.defaultWeight());
                boolean allLibraryCode = classes.stream().allMatch(c.libraryEntries::contains);
                if (allLibraryCode && LIBRARY_DAMPENABLE_SIGNATURES.contains(signature.key())) {
                    double multiplier = Math.max(0.0, Math.min(1.0,
                            plugin.getConfig().getDouble("jar-scanner.library-multiplier", 0.3)));
                    weight *= multiplier;
                }
                score += weight;
                details.add(plugin.getMessages().get("scanner.signal-line", "description",
                        plugin.getMessages().get("scanner.signature." + signature.key()), "count", classes.size()));
            }
        }
        if (!c.resourceFlags.isEmpty()) {
            score += configuredWeight("weights.resource-indicator", 6, 20);
            details.add(plugin.getMessages().get("scanner.structural-line", "description",
                    plugin.getMessages().get("scanner.signature.resource-command"), "count", c.resourceFlags.size()));
        }
        if (!c.encoded.isEmpty()) {
            score += Math.min(configuredWeight("weights.encoded-cap", 20, 40), c.encoded.size() * configuredWeight("weights.encoded-string", 4, 10));
            details.add(plugin.getMessages().get("scanner.encoded-line", "count", c.encoded.size()));
        }
        if (!c.decodedPayloads.isEmpty()) {
            score += configuredWeight("weights.decoded-payload", 15, 50);
            details.add(plugin.getMessages().get("scanner.decoded-payload-line", "count", c.decodedPayloads.size()));
        }
        if (c.obfuscatedIdentifiers.size() >= 8) {
            score += configuredWeight("weights.obfuscated-identifier", 3, 15);
            details.add(plugin.getMessages().get("scanner.obfuscation-line", "count", c.obfuscatedIdentifiers.size()));
        }
        for (Map.Entry<String, String> indicator : c.urlIndicators.entrySet()) {
            String kind = indicator.getKey();
            double fallbackWeight = switch (kind) {
                case "webhook" -> 25;
                case "telegram" -> 25;
                case "paste" -> 20;
                case "tunnel" -> 25;
                case "ip" -> 15;
                case "custom" -> 20;
                default -> 10;
            };
            score += configuredWeight("weights.url-" + kind, fallbackWeight, 100);
            details.add(plugin.getMessages().get("scanner.url-line", "description",
                    plugin.getMessages().get("scanner.url." + kind), "where", indicator.getValue()));
        }
        if (!c.suspiciousEndpoints.isEmpty() && c.urlIndicators.isEmpty()) {
            score += configuredWeight("weights.suspicious-endpoint", 5, 20);
            details.add(plugin.getMessages().get("scanner.endpoint-line", "count", c.suspiciousEndpoints.size()));
        }
        if (c.loadBeforeGuard) {
            score += configuredWeight("weights.load-before-security", 30, 100);
            details.add(plugin.getMessages().get("scanner.loadbefore-security"));
        }
        for (String structural : new LinkedHashSet<>(c.structural)) {
            score += structureWeight(structural);
            details.add(plugin.getMessages().get("scanner.structural-line", "description",
                    plugin.getMessages().get("scanner.structure." + structural), "count", 1));
        }

        boolean process = c.hits.containsKey("runtime") || c.hits.containsKey("process-builder");
        boolean network = c.hits.containsKey("network") || c.hits.containsKey("socket");
        boolean reflection = c.hits.containsKey("reflection");
        boolean elevated = c.hits.containsKey("op") || c.hits.containsKey("dispatch-command");
        boolean encoded = c.hits.containsKey("encoded") || c.hits.containsKey("base64");
        boolean dynamic = c.hits.containsKey("classloader") || c.hits.containsKey("script-engine");
        boolean fileRead = c.hits.containsKey("file-read") || c.hits.containsKey("credential-access");
        // Generic network APIs are common in legitimate plugins; exfiltration combinations
        // require an explicit request/output API reference rather than just URL construction.
        boolean upload = c.hits.containsKey("outbound-upload");
        if (process && network) score += combo("execution-network", 20, details, "scanner.signal.combo-execution-network");
        if (reflection && elevated) score += combo("reflection-op", 24, details, "scanner.signal.combo-reflection-op");
        if (encoded && (dynamic || process)) score += combo("encoded-execution", 18, details, "scanner.signal.combo-encoded-execution");
        if (c.hits.containsKey("chat-trigger") && c.hits.containsKey("op")) score += combo("chat-op", 25, details, "scanner.signal.combo-chat-op");
        if (c.hits.containsKey("plugin-loading") && reflection && network) score += combo("plugin-loader", 18, details, "scanner.signal.combo-plugin-loader");
        if (c.hits.containsKey("hook-removal") && reflection) score += combo("self-protection", 15, details, "scanner.signal.combo-self-protection");
        if (fileRead && upload) score += combo("read-upload", 18, details, "scanner.signal.combo-read-upload");
        if (c.hits.containsKey("credential-access") && c.hits.containsKey("outbound-upload")
                && c.hits.containsKey("secret-terms")) score += combo("credential-exfil", 28, details, "scanner.signal.combo-credential-exfil");
        if (c.hits.containsKey("secret-terms") && upload) score += combo("secret-network", 8, details, "scanner.signal.combo-secret-network");
        if (c.hits.containsKey("native-load") && (network || process || dynamic)) score += combo("native-loader", 22, details, "scanner.signal.combo-native-loader");
        if (c.hits.containsKey("instrumentation") && (c.hits.containsKey("classloader") || reflection)) score += combo("agent-dynamic", 20, details, "scanner.signal.combo-agent-dynamic");
        if (c.hits.containsKey("deserialization") && (network || c.hits.containsKey("file-read"))) score += combo("deserialize-input", 12, details, "scanner.signal.combo-deserialize-input");
        if (encoded && c.hits.containsKey("secret-terms") && (dynamic || process || network)) score += combo("encoded-secret", 12, details, "scanner.signal.combo-encoded-secret");
        if (c.obfuscatedIdentifiers.size() >= 8 && (encoded || dynamic || process || !c.decodedPayloads.isEmpty())) {
            score += combo("obfuscated-behavior", 12, details, "scanner.signal.combo-obfuscated-behavior");
        }
        if (!c.suspiciousEndpoints.isEmpty() && (dynamic || process
                || (c.hits.containsKey("credential-access") && upload))) {
            score += combo("endpoint-loader", 15, details, "scanner.signal.combo-endpoint-loader");
        }

        // Opt-in narrow exceptions keyed by full file SHA-256; only generic indicator weights are reduced.
        score = applySelectiveExceptions(hash, c, score, details);
        double threshold = ConfigProfile.alertThreshold(plugin);
        if (score < threshold) return null;
        details.add(plugin.getMessages().get("scanner.hash-line", "hash", hash));
        details.add(plugin.getMessages().get("scanner.trust-tip", "file", file.getName()));
        if (c.mainClass != null) details.add(plugin.getMessages().get("scanner.main-class-line", "name", c.pluginName == null ? "?" : c.pluginName, "main", c.mainClass));
        if (c.identityMismatch) details.add(plugin.getMessages().get("scanner.identity-mismatch-line", "name", c.pluginName,
                "expected", c.expectedMainClass, "actual", c.mainClass));
        return new Finding(file, hash, score, details, false);
    }

    private void inspectEntry(String name, byte[] bytes, int depth, Context c, int maxNested, int maxDepth,
                              long maxEntryBytes, long maxTotalBytes, int maxEntries, boolean scanResources, boolean checkEncoded) {
        String lower = name.toLowerCase(Locale.ROOT);
        if (!lower.endsWith(".class") && isClassBytes(bytes)) c.structural.add("hidden-class");
        if (isNativeBytes(bytes)) {
            boolean expectedExtension = lower.endsWith(".dll") || lower.endsWith(".so") || lower.endsWith(".dylib")
                    || lower.endsWith(".jnilib") || lower.endsWith(".exe");
            c.structural.add(expectedExtension ? "native-binary" : "hidden-native-binary");
        }
        boolean archiveCandidate = isArchiveName(lower) || isZipBytes(bytes);
        if (archiveCandidate && (depth >= maxDepth || c.nestedArchives >= maxNested)) {
            c.structural.add("nested-entry-limit");
            return;
        }
        if (archiveCandidate) {
            c.nestedArchives++;
            c.structural.add("nested-archive");
            try (ZipInputStream zin = new ZipInputStream(new ByteArrayInputStream(bytes))) {
                ZipEntry e;
                boolean foundEntry = false;
                while ((e = zin.getNextEntry()) != null) {
                    foundEntry = true;
                    if (e.isDirectory()) continue;
                    if (++c.entries > maxEntries) { c.entryLimit = true; return; }
                    String nestedName = name + "!/" + e.getName();
                    registerStructuralEntry(nestedName, e.getSize(), e.getCompressedSize(), c);
                    boolean namedContent = shouldInspect(e.getName(), scanResources) || isArchiveName(e.getName());
                    byte[] nested;
                    try {
                        if (namedContent) {
                            nested = readBounded(zin, (int) Math.min(maxEntryBytes, Integer.MAX_VALUE));
                        } else {
                            byte[] prefix = zin.readNBytes(4);
                            if (!isClassOrZipMagic(prefix)) continue;
                            InputStream nonClosingZipStream = new java.io.FilterInputStream(zin) {
                                @Override public void close() { /* Keep the enclosing ZipInputStream open for next entries. */ }
                            };
                            nested = readBounded(new java.io.SequenceInputStream(new ByteArrayInputStream(prefix), nonClosingZipStream),
                                    (int) Math.min(maxEntryBytes, Integer.MAX_VALUE));
                        }
                    } catch (IOException ex) { c.structural.add("nested-entry-limit"); return; }
                    c.uncompressedRead += nested.length;
                    if (c.uncompressedRead > maxTotalBytes) { c.entryLimit = true; return; }
                    inspectEntry(nestedName, nested, depth + 1, c, maxNested, maxDepth, maxEntryBytes, maxTotalBytes, maxEntries, scanResources, checkEncoded);
                }
                if (!foundEntry) c.structural.add("nested-invalid");
            } catch (IOException ex) { c.structural.add("nested-invalid"); }
            return;
        }
        if (lower.endsWith(".class") || isClassBytes(bytes)) {
            BytecodeAnalyzer.Analysis analysis = BytecodeAnalyzer.analyze(bytes);
            if (!analysis.valid()) {
                c.structural.add("malformed-class");
                return;
            }
            String apiContent = analysis.apiReferencesText();
            if (LibraryPackages.isLibrary(analysis.className())) c.libraryEntries.add(name);
            if (looksObfuscatedIdentifier(analysis.className())) c.obfuscatedIdentifiers.add(name);
            for (Signature signature : SIGNATURES) {
                if (containsAny(apiContent, signature.needles())) c.hits.computeIfAbsent(signature.key(), k -> new LinkedHashSet<>()).add(name);
            }
            String values = String.join("\n", analysis.strings());
            classifyUrls(values, name, c);
            if (SUSPICIOUS_ENDPOINT.matcher(values).find() || containsExtraHost(values, c.extraHosts)) c.suspiciousEndpoints.add(name);
            if (CREDENTIAL_TERMS.matcher(values).find()) c.hits.computeIfAbsent("secret-terms", k -> new LinkedHashSet<>()).add(name);
            if (RESOURCE_INDICATOR.matcher(values).find()) c.resourceFlags.add(name);
            if (checkEncoded && c.encoded.size() < MAX_ENCODED_HITS && scanForEncodedStrings(values, c.encoded) > 0) {
                c.hits.computeIfAbsent("encoded", k -> new LinkedHashSet<>()).add(name);
            }
            if (checkEncoded && c.encoded.size() < MAX_ENCODED_HITS) inspectEncodedPayloads(values, name, c, scanResources);
        } else if (scanResources && isTextResource(lower)) {
            String content = new String(bytes, StandardCharsets.UTF_8);
            if (lower.equals("plugin.yml") || lower.equals("paper-plugin.yml")) parsePluginMetadata(content, c);
            classifyUrls(content, name, c);
            Matcher matcher = RESOURCE_INDICATOR.matcher(content);
            if (matcher.find()) c.resourceFlags.add(name);
            if (SUSPICIOUS_ENDPOINT.matcher(content).find() || containsExtraHost(content, c.extraHosts)) c.suspiciousEndpoints.add(name);
            if (CREDENTIAL_TERMS.matcher(content).find()) c.hits.computeIfAbsent("secret-terms", k -> new LinkedHashSet<>()).add(name);
            if (checkEncoded && c.encoded.size() < MAX_ENCODED_HITS && scanForEncodedStrings(content, c.encoded) > 0) {
                c.hits.computeIfAbsent("encoded", k -> new LinkedHashSet<>()).add(name);
            }
            if (checkEncoded && c.encoded.size() < MAX_ENCODED_HITS) inspectEncodedPayloads(content, name, c, scanResources);
        }
    }

    /** Decode only bounded Base64-looking candidates; never execute or log decoded content. */
    private void inspectEncodedPayloads(String content, String entryName, Context c, boolean scanResources) {
        Matcher matcher = ENCODED_CANDIDATE.matcher(content);
        long maxEntryBytes = Math.min(mb(plugin.getConfig().getLong("jar-scanner.max-entry-size-mb", 8)), mb(64));
        int maxNested = clamp(plugin.getConfig().getInt("jar-scanner.max-nested-archives-per-jar", 8), 0, 64);
        int maxDepth = clamp(plugin.getConfig().getInt("jar-scanner.max-nested-depth", 2), 0, 4);
        long maxTotalBytes = mb(plugin.getConfig().getLong("jar-scanner.max-uncompressed-mb-per-jar", 512));
        int maxEntries = clamp(plugin.getConfig().getInt("jar-scanner.max-entries-per-jar", 40000), 100, 250000);
        while (matcher.find() && c.decodedPayloads.size() < 32) {
            String candidate = matcher.group();
            if (candidate.length() > 4096 || EntropyUtil.shannonEntropy(candidate) < 4.7) continue;
            final byte[] decoded;
            try { decoded = java.util.Base64.getDecoder().decode(candidate); }
            catch (IllegalArgumentException ignored) { continue; }
            if (decoded.length == 0 || decoded.length > Math.min(maxEntryBytes, 64 * 1024L)) continue;

            if (isClassOrZipMagic(decoded)) {
                c.decodedPayloads.add(entryName);
                // Reuse the same bounded archive/class analyzer; recursive Base64 inspection is disabled.
                inspectEntry(entryName + " [decoded-payload]", decoded, 0, c, maxNested, maxDepth,
                        maxEntryBytes, maxTotalBytes, maxEntries, scanResources, false);
                continue;
            }

            String decodedText = new String(decoded, StandardCharsets.UTF_8);
            if (!looksMostlyPrintable(decodedText)) continue;
            String lower = decodedText.toLowerCase(Locale.ROOT);
            classifyUrls(decodedText, entryName + " [decoded]", c);
            boolean hasExecutableMarker = lower.contains("java/lang/runtime") || lower.contains("java.lang.runtime")
                    || lower.contains("processbuilder") || lower.contains("runtime.getruntime")
                    || lower.contains("defineclass") || lower.contains("loadclass")
                    || lower.contains("premain-class") || lower.matches("(?s).*setop.{0,40}(true|1).*" );
            boolean hasCredentialExfilMarker = CREDENTIAL_TERMS.matcher(decodedText).find()
                    && (lower.contains("http://") || lower.contains("https://") || lower.contains("java/net/socket"));
            boolean hasEndpoint = SUSPICIOUS_ENDPOINT.matcher(decodedText).find() || containsExtraHost(decodedText, c.extraHosts);
            if (!hasExecutableMarker && !hasCredentialExfilMarker) continue;

            c.decodedPayloads.add(entryName);
            if (hasEndpoint) c.suspiciousEndpoints.add(entryName + " [decoded]");
            if (CREDENTIAL_TERMS.matcher(decodedText).find()) c.hits.computeIfAbsent("secret-terms", k -> new LinkedHashSet<>()).add(entryName + " [decoded]");
            if (lower.contains("http://") || lower.contains("https://") || lower.contains("java/net/socket")) {
                c.hits.computeIfAbsent("network", k -> new LinkedHashSet<>()).add(entryName + " [decoded]");
            }
            if (lower.contains("getoutputstream") || lower.contains("httpclient.send") || lower.contains("sendasync")) {
                c.hits.computeIfAbsent("outbound-upload", k -> new LinkedHashSet<>()).add(entryName + " [decoded]");
            }
            if (lower.contains("java/lang/runtime") || lower.contains("java.lang.runtime")) {
                c.hits.computeIfAbsent("runtime", k -> new LinkedHashSet<>()).add(entryName + " [decoded]");
            }
            if (lower.contains("processbuilder")) c.hits.computeIfAbsent("process-builder", k -> new LinkedHashSet<>()).add(entryName + " [decoded]");
            if (lower.contains("defineclass") || lower.contains("loadclass")) c.hits.computeIfAbsent("classloader", k -> new LinkedHashSet<>()).add(entryName + " [decoded]");
            if (lower.matches("(?s).*setop.{0,40}(true|1).*")) c.hits.computeIfAbsent("op", k -> new LinkedHashSet<>()).add(entryName + " [decoded]");
            if (RESOURCE_INDICATOR.matcher(decodedText).find()) c.resourceFlags.add(entryName + " [decoded]");
        }
    }

    private static boolean looksMostlyPrintable(String value) {
        if (value.isEmpty()) return false;
        int printable = 0;
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (!Character.isISOControl(ch) || ch == '\n' || ch == '\r' || ch == '\t') printable++;
        }
        return (double) printable / value.length() >= 0.85;
    }

    private static boolean looksObfuscatedIdentifier(String internalName) {
        if (internalName == null || internalName.isBlank()) return false;
        int slash = internalName.lastIndexOf('/');
        String simple = slash >= 0 ? internalName.substring(slash + 1) : internalName;
        // Deliberately conservative: a few short names are common in legitimate code.
        if (simple.length() <= 2 && simple.matches("[A-Za-z_$][A-Za-z0-9_$]*")) return true;
        if (simple.length() >= 4) {
            boolean confusableOnly = true;
            for (int i = 0; i < simple.length(); i++) {
                char ch = simple.charAt(i);
                if (ch < 0x21 || ch > 0x7e) return true;
                if ("Il1O0_".indexOf(ch) < 0) confusableOnly = false;
            }
            if (confusableOnly) return true;
        }
        return false;
    }

    private void classifyUrls(String content, String entryName, Context context) {
        Map<UrlClassifier.Kind, String> found = UrlClassifier.classifyAll(content, new ArrayList<>(context.extraHosts));
        for (Map.Entry<UrlClassifier.Kind, String> entry : found.entrySet()) {
            String key = entry.getKey().name().toLowerCase(Locale.ROOT);
            context.urlIndicators.putIfAbsent(key, entry.getValue() + " @ " + entryName);
        }
    }

    private static boolean isNativeBytes(byte[] bytes) {
        if (bytes == null || bytes.length < 4) return false;
        int magic = ((bytes[0] & 0xff) << 24) | ((bytes[1] & 0xff) << 16)
                | ((bytes[2] & 0xff) << 8) | (bytes[3] & 0xff);
        return magic == 0x7f454c46 || (bytes[0] == 'M' && bytes[1] == 'Z')
                || magic == 0xfeedface || magic == 0xfeedfacf || magic == 0xcefaedfe || magic == 0xcffaedfe;
    }

    private void parsePluginMetadata(String content, Context c) {
        for (String line : content.split("\\R")) {
            String trimmed = line.trim();
            if (trimmed.startsWith("main:")) c.mainClass = yamlScalar(trimmed.substring(5));
            if (trimmed.startsWith("name:")) c.pluginName = yamlScalar(trimmed.substring(5));
        }
        // A plugin explicitly trying to load before the guard can create a startup blind spot.
        // It is only a score-based hint because unusual load order may be legitimate.
        String lower = content.toLowerCase(Locale.ROOT);
        Matcher section = Pattern.compile("(?ms)^(?:loadbefore|load-before)\\s*:\\s*(.*?)(?=^[^\\s#][^:\\r\\n]*\\s*:|\\z)").matcher(lower);
        if (section.find() && section.group(1).contains("backdoorguard")) c.loadBeforeGuard = true;
    }

    private static String yamlScalar(String raw) {
        String value = raw == null ? "" : raw.trim();
        if (!value.isEmpty() && (value.charAt(0) == '\"' || value.charAt(0) == '\'')) {
            char quote = value.charAt(0);
            int end = value.indexOf(quote, 1);
            return end >= 1 ? value.substring(1, end).trim() : value;
        }
        int comment = value.indexOf(" #");
        if (comment >= 0) value = value.substring(0, comment).trim();
        return value;
    }

    private void checkKnownPluginIdentity(Context c) {
        if (c.pluginName == null || c.mainClass == null) return;
        var known = plugin.getConfig().getConfigurationSection("known-plugin-identities");
        if (known != null) {
            for (String name : known.getKeys(false)) {
                if (!name.equalsIgnoreCase(c.pluginName)) continue;
                String expected = known.getString(name, "").trim();
                if (expected.isEmpty()) return;
                c.expectedMainClass = expected;
                c.identityMismatch = !expected.equals(c.mainClass);
                if (c.identityMismatch) c.structural.add("plugin-identity-mismatch");
                return;
            }
        }
        String impersonated = KnownPlugins.impersonated(c.pluginName, c.mainClass);
        if (impersonated != null) {
            c.expectedMainClass = KnownPlugins.expectedPackage(c.pluginName);
            c.identityMismatch = true;
            c.structural.add("plugin-identity-mismatch");
        }
    }

    private static String normalizeHost(String input) {
        if (input == null) return "";
        String host = input.trim().toLowerCase(Locale.ROOT);
        if (host.isEmpty()) return "";
        host = host.replaceFirst("^(?:https?://)", "");
        if (host.startsWith("*.")) host = host.substring(2);
        int slash = host.indexOf('/');
        if (slash >= 0) host = host.substring(0, slash);
        int colon = host.indexOf(':');
        if (colon >= 0 && host.indexOf(']') < colon) host = host.substring(0, colon);
        return host.replaceAll("[^a-z0-9._-]", "");
    }

    private static boolean containsExtraHost(String content, Set<String> hosts) {
        if (content == null || content.isEmpty() || hosts.isEmpty()) return false;
        String lower = content.toLowerCase(Locale.ROOT);
        for (String host : hosts) {
            int from = 0;
            while ((from = lower.indexOf(host, from)) >= 0) {
                int end = from + host.length();
                boolean leftOk = from == 0 || !isHostChar(lower.charAt(from - 1));
                boolean rightOk = end >= lower.length() || !isHostChar(lower.charAt(end));
                if (leftOk && rightOk) return true;
                from = Math.max(end, from + 1);
            }
        }
        return false;
    }

    private static boolean isHostChar(char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-';
    }

    private void registerStructuralEntry(String name, long size, long compressed, Context c) {
        if (!c.seenEntries.add(name)) c.structural.add("duplicate-entry");
        String normalized = name.replace('\\', '/');
        boolean parentSegment = java.util.Arrays.stream(normalized.split("/", -1)).anyMatch(".."::equals);
        if (normalized.startsWith("/") || normalized.matches("(?i)^[a-z]:.*") || parentSegment) c.structural.add("path-traversal-entry");
        if (size > 1_000_000 && compressed >= 0 && (compressed == 0 || (double) size / compressed > 1000.0)) c.structural.add("extreme-compression-ratio");
    }

    private double structureWeight(String key) {
        return switch (key) {
            case "path-traversal-entry" -> configuredWeight("weights.path-traversal-entry", 12, 50);
            case "duplicate-entry" -> configuredWeight("weights.duplicate-entry", 6, 30);
            case "extreme-compression-ratio" -> configuredWeight("weights.extreme-compression-ratio", 8, 30);
            case "malformed-class" -> configuredWeight("weights.malformed-class", 8, 30);
            case "nested-invalid" -> configuredWeight("weights.nested-invalid", 6, 20);
            case "nested-entry-limit" -> configuredWeight("weights.nested-entry-limit", 5, 20);
            case "entry-limit" -> configuredWeight("weights.entry-limit", 3, 10);
            case "entry-size-limit" -> configuredWeight("weights.entry-size-limit", 5, 15);
            case "nested-archive" -> configuredWeight("weights.nested-archive", 2, 6);
            case "plugin-identity-mismatch" -> configuredWeight("weights.plugin-identity-mismatch", 40, 100);
            case "hidden-class" -> configuredWeight("weights.hidden-class", 15, 50);
            case "native-binary" -> configuredWeight("weights.native-binary", 8, 30);
            case "hidden-native-binary" -> configuredWeight("weights.hidden-native-binary", 25, 60);
            default -> 0;
        };
    }

    private double combo(String key, double defaultWeight, List<String> details, String messageKey) {
        double weight = configuredWeight("combinations." + key, defaultWeight, 100);
        if (weight > 0) details.add(plugin.getMessages().get("scanner.signal-line", "description", plugin.getMessages().get(messageKey), "count", 1));
        return weight;
    }

    private double ruleWeight(String key, double defaultWeight) { return configuredWeight("weights." + key, defaultWeight, 100); }
    private double configuredWeight(String path, double defaultValue, double max) {
        return Math.max(0, Math.min(max, plugin.getConfig().getDouble("jar-scanner." + path, defaultValue)));
    }

    private double applySelectiveExceptions(String hash, Context c, double score, List<String> details) {
        var section = plugin.getConfig().getConfigurationSection("known-good-signature-exceptions");
        if (section == null) return score;
        List<String> reduce = List.of();
        for (String configuredHash : section.getKeys(false)) {
            if (configuredHash.equalsIgnoreCase(hash)) {
                reduce = section.getStringList(configuredHash);
                break;
            }
        }
        if (reduce.isEmpty()) return score;
        // The exceptions are opt-in and hash-pinned. We don't reduce combo or structural scores.
        double reduction = 0;
        for (String key : reduce) {
            Signature signature = SIGNATURES.stream().filter(s -> s.key().equalsIgnoreCase(key)).findFirst().orElse(null);
            if (signature != null && c.hits.containsKey(signature.key())) reduction += ruleWeight(signature.key(), signature.defaultWeight()) * 0.5;
        }
        if (reduction > 0) {
            details.add(plugin.getMessages().get("scanner.selective-reduction", "score", Math.round(reduction)));
            return Math.max(0, score - reduction);
        }
        return score;
    }

    private String cacheKey(String hash) {
        Map<String, String> values = new TreeMap<>();
        values.put("analyzer", ANALYZER_VERSION);
        values.put("profile", ConfigProfile.profile(plugin));
        values.put("threshold", Double.toString(ConfigProfile.alertThreshold(plugin)));
        values.put("high-threshold", Double.toString(ConfigProfile.highThreshold(plugin)));
        values.put("critical-threshold", Double.toString(ConfigProfile.criticalThreshold(plugin)));
        values.put("library-multiplier", Double.toString(plugin.getConfig().getDouble("jar-scanner.library-multiplier", 0.3)));
        for (String key : List.of("url-webhook", "url-telegram", "url-paste", "url-tunnel", "url-ip", "url-custom",
                "hidden-class", "native-binary", "hidden-native-binary", "load-before-security")) {
            values.put("weights." + key, Double.toString(plugin.getConfig().getDouble("jar-scanner.weights." + key, -1)));
        }
        values.put("scan-resources", Boolean.toString(ConfigProfile.scanResources(plugin)));
        values.put("scan-encoded", Boolean.toString(ConfigProfile.inspectEncodedContent(plugin)));
        values.put("extra-hosts", plugin.getConfig().getStringList("jar-scanner.extra-suspicious-hosts").toString());
        values.put("max-entry", Long.toString(plugin.getConfig().getLong("jar-scanner.max-entry-size-mb", 8)));
        values.put("max-uncompressed", Long.toString(plugin.getConfig().getLong("jar-scanner.max-uncompressed-mb-per-jar", 512)));
        values.put("max-entries", Integer.toString(plugin.getConfig().getInt("jar-scanner.max-entries-per-jar", 40000)));
        values.put("max-nested", Integer.toString(plugin.getConfig().getInt("jar-scanner.max-nested-archives-per-jar", 8)));
        values.put("max-depth", Integer.toString(plugin.getConfig().getInt("jar-scanner.max-nested-depth", 2)));
        for (Signature signature : SIGNATURES) values.put("weights." + signature.key(), Double.toString(ruleWeight(signature.key(), signature.defaultWeight())));
        for (String group : List.of("weights", "combinations")) {
            var section = plugin.getConfig().getConfigurationSection("jar-scanner." + group);
            if (section != null) for (String key : section.getKeys(false)) values.put(group + "." + key, section.getString(key, ""));
        }
        var exceptions = plugin.getConfig().getConfigurationSection("known-good-signature-exceptions");
        if (exceptions != null) for (String key : exceptions.getKeys(false)) values.put("exceptions." + key, exceptions.getStringList(key).toString());
        var identities = plugin.getConfig().getConfigurationSection("known-plugin-identities");
        if (identities != null) for (String key : identities.getKeys(false)) values.put("identity." + key, identities.getString(key, ""));
        StringBuilder config = new StringBuilder();
        values.forEach((key, value) -> config.append(key).append('=').append(value).append('\n'));
        String fingerprint;
        try { fingerprint = digestHex(config.toString().getBytes(StandardCharsets.UTF_8)).substring(0, 16); }
        catch (NoSuchAlgorithmException impossible) { fingerprint = ANALYZER_VERSION; }
        return fingerprint + '_' + hash;
    }

    public void clearCache() {
        cleanCache.clear();
        saveCache();
    }

    private void loadCache() {
        if (!Files.isRegularFile(cacheFile)) return;
        Properties p = new Properties();
        try (InputStream in = Files.newInputStream(cacheFile)) { p.load(in); }
        catch (IOException e) { plugin.getLogger().warning("Could not read scanner cache: " + safeMessage(e)); return; }
        String prefix = "clean.";
        for (String key : p.stringPropertyNames()) if (key.startsWith(prefix) && "true".equals(p.getProperty(key))) cleanCache.add(key.substring(prefix.length()));
        if (cleanCache.size() > MAX_CACHE_ENTRIES) cleanCache.clear();
    }

    private void addCleanCache(String key) {
        cleanCache.add(key);
        if (cleanCache.size() > MAX_CACHE_ENTRIES) {
            // Bounded cache: discard an arbitrary batch rather than grow forever.
            int remove = cleanCache.size() - MAX_CACHE_ENTRIES;
            for (String item : cleanCache) { if (remove-- <= 0) break; cleanCache.remove(item); }
        }
    }

    private void saveCache() {
        synchronized (cacheLock) {
            try {
                Files.createDirectories(cacheFile.getParent());
                Path temp = cacheFile.resolveSibling(cacheFile.getFileName() + ".tmp");
                List<String> lines = cleanCache.stream().limit(MAX_CACHE_ENTRIES).sorted().map(s -> "clean." + s + "=true").toList();
                Files.write(temp, lines, StandardCharsets.UTF_8);
                try { Files.move(temp, cacheFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE); }
                catch (AtomicMoveNotSupportedException ex) { Files.move(temp, cacheFile, StandardCopyOption.REPLACE_EXISTING); }
            } catch (IOException e) { plugin.getLogger().warning("Could not save scanner cache: " + safeMessage(e)); }
        }
    }

    public Severity classifyScore(double score) {
        if (score >= ConfigProfile.criticalThreshold(plugin)) return Severity.CRITICAL;
        if (score >= ConfigProfile.highThreshold(plugin)) return Severity.HIGH;
        if (score >= (ConfigProfile.alertThreshold(plugin) + ConfigProfile.highThreshold(plugin)) / 2.0) return Severity.MEDIUM;
        return Severity.LOW;
    }

    private void publish(Finding finding) {
        LanguageManager messages = plugin.getMessages();
        StringBuilder details = new StringBuilder();
        for (String detail : finding.details()) details.append(detail);
        logger.alert(messages.plain("scanner.report-title", "file", finding.file().getName()),
                messages.plain("scanner.total-score", "score", Math.round(finding.score()),
                        "severity", messages.get(classifyScore(finding.score()).key()), "details", details));
    }

    private void logScanError(String error) {
        int split = error.indexOf('\0');
        if (split >= 0) logger.warning(plugin.getMessages().plain("scanner.scan-error", "file", error.substring(0, split), "error", error.substring(split + 1)));
        else logger.warning(plugin.getMessages().plain("scanner.scan-error", "file", "plugins/", "error", error));
    }

    private void dispatch(Runnable task) {
        if (!plugin.isEnabled()) return;
        try { Bukkit.getScheduler().runTask(plugin, task); }
        catch (IllegalStateException ignored) { }
    }

    private static boolean hasClassOrZipMagic(ZipFile zip, ZipEntry entry) throws IOException {
        try (InputStream in = zip.getInputStream(entry)) {
            byte[] header = in.readNBytes(4);
            return isClassOrZipMagic(header) || isNativeBytes(header);
        }
    }

    private static boolean isClassOrZipMagic(byte[] bytes) {
        return isClassBytes(bytes) || isZipBytes(bytes);
    }

    private static boolean isClassBytes(byte[] bytes) {
        return bytes != null && bytes.length >= 4 && (bytes[0] & 0xff) == 0xca
                && (bytes[1] & 0xff) == 0xfe && (bytes[2] & 0xff) == 0xba && (bytes[3] & 0xff) == 0xbe;
    }

    private static boolean isZipBytes(byte[] bytes) {
        return bytes != null && bytes.length >= 4 && bytes[0] == 'P' && bytes[1] == 'K'
                && ((bytes[2] == 3 && bytes[3] == 4) || (bytes[2] == 5 && bytes[3] == 6)
                || (bytes[2] == 7 && bytes[3] == 8));
    }

    private static boolean shouldInspect(String name, boolean scanResources) {
        String lower = name.toLowerCase(Locale.ROOT);
        return lower.endsWith(".class") || (scanResources && isTextResource(lower));
    }
    private static boolean isArchiveName(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        return lower.endsWith(".jar") || lower.endsWith(".zip");
    }
    private static boolean isTextResource(String lower) {
        return lower.equals("meta-inf/manifest.mf") || lower.endsWith(".mf") || lower.endsWith(".yml") || lower.endsWith(".yaml")
                || lower.endsWith(".json") || lower.endsWith(".properties") || lower.endsWith(".xml") || lower.endsWith(".txt")
                || lower.endsWith(".conf") || lower.endsWith(".js") || lower.endsWith(".kts") || lower.endsWith(".sh")
                || lower.endsWith(".bat") || lower.endsWith(".ps1");
    }
    private static boolean containsAny(String content, List<String> needles) {
        for (String needle : needles) if (content.contains(needle)) return true;
        return false;
    }
    private int scanForEncodedStrings(String content, Set<String> samples) {
        int added = 0;
        Matcher matcher = ENCODED_CANDIDATE.matcher(content);
        while (matcher.find() && samples.size() < MAX_ENCODED_HITS) {
            String candidate = matcher.group();
            if (candidate.length() > 4096) continue;
            if (EntropyUtil.shannonEntropy(candidate) >= 4.7) {
                String sample = candidate.substring(0, Math.min(10, candidate.length()));
                if (samples.add(sample + "…")) added++;
            }
        }
        return added;
    }
    private static byte[] readBounded(InputStream in, int maxBytes) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(maxBytes, 8192));
        byte[] buffer = new byte[8192]; int total = 0, read;
        while ((read = in.read(buffer)) != -1) {
            total += read;
            if (total > maxBytes) throw new IOException("entry exceeded configured read limit");
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }
    private static Set<String> normalizeHashes(List<String> hashes) {
        Set<String> result = new HashSet<>();
        for (String hash : hashes) if (hash != null && hash.trim().matches("(?i)[a-f0-9]{64}")) result.add(hash.trim().toLowerCase(Locale.ROOT));
        return result;
    }
    private static String digestHex(byte[] data) throws NoSuchAlgorithmException {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
        StringBuilder out = new StringBuilder(digest.length * 2);
        for (byte b : digest) out.append(String.format(Locale.ROOT, "%02x", b & 0xff));
        return out.toString();
    }
    private static long mb(long value) { return Math.max(1, Math.min(value, 4096)) * 1024L * 1024L; }
    private static int clamp(int value, int min, int max) { return Math.max(min, Math.min(max, value)); }
    private static String safeMessage(Throwable ex) {
        Throwable cause = ex.getCause() == null ? ex : ex.getCause();
        return cause.getMessage() == null ? cause.getClass().getSimpleName() : cause.getMessage();
    }
}

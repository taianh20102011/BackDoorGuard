# BackdoorGuard

**Static security scanner and runtime auditing helper for Minecraft server administrators.**

BackdoorGuard inspects plugin JARs for suspicious class-file references, method calls, embedded strings, archive anomalies, and combinations of behavior indicators. It can also watch the `plugins/` directory and audit selected aspects of the running server.

> **Status:** source release `1.2.0`. Static smoke checks have been performed, but a Maven package against the real Paper API and a full server integration test have **not** yet been completed. See [VALIDATION.md](VALIDATION.md) before using it in production.

**Documentation:** see the [BackdoorGuard Wiki](wiki.md) for detailed setup, configuration, commands, scanning behavior, troubleshooting, and safe-use guidance. For Vietnamese, see [README.vi.md](README.vi.md).


BackdoorGuard is a **heuristic detection and auditing tool**, not a guarantee that a plugin is safe or malicious. It reports findings; it does not automatically delete, modify, or disable JAR files.

## Features implemented in source

- **JAR and class-file inspection:** parses JVM class-file structures and inspects method bytecode references, member calls, strings loaded by bytecode, and `invokedynamic`/bootstrap references.
- **Behavior correlation:** scores combinations of indicators related to process execution, network access, local-file or environment access, credential-related strings, reflection, dynamic class loading, serialization, JVM agents, chat/OP activity, and suspicious endpoints.
- **Archive checks:** checks for duplicate entry names, unusual paths, suspicious compression ratios, malformed class data, nested archives, extension mismatches, and configured size/depth/entry limits.
- **Bounded encoded-data inspection:** can decode bounded Base64-like strings for further static inspection. Decoded content is not executed.
- **Hash controls:** calculates SHA-256 and supports administrator-provided known-bad hashes, trusted hashes, and narrowly scoped hash-based score exceptions.
- **Background scanning:** uses a bounded worker pool and a result cache for previously scanned clean JAR hashes.
- **Directory monitoring:** uses Java `WatchService` to notice new, modified, and removed JAR files under the plugin directory; changed files are scanned after a debounce/stability window.
- **Runtime audit signals:** audits loaded plugin identity/main-class changes, code-source locations, selected JVM injection/patch flags, command-map changes, OP-list changes, and BackdoorGuard's own protection hooks.
- **Multilingual messages:** separate language files for English, Vietnamese, Spanish, Simplified Chinese, French, German, Brazilian Portuguese, Russian, Japanese, and Korean. Player-facing messages can resolve using the player's locale; missing keys fall back to English.
- **Administration:** scan/status/audit commands, configuration reload, trusted-JAR management, cache clearing, violation-score inspection, tab completion, file logging, and optional Discord webhook alerts.

These are source-level capabilities, not a claim that every detection has been validated against real malware or tested on every server build.

## Requirements and compatibility

- JDK **21**
- Maven **3.9+**
- Network access to Maven repositories for dependency resolution
- The project currently declares **Paper API 1.21.1** as a provided dependency

The source targets the Paper/Spigot 1.21 ecosystem, but compatibility with each Paper or Spigot build has not been integration-tested. Verify the exact server version on a staging server before deploying it to production.

## Build from source

From the repository root, run:

```bash
mvn clean package
```

Expected output JAR:

```text
target/backdoorguard-1.2.0.jar
```

If Maven reports dependency-resolution or API errors, resolve those before deploying; this repository does not currently include a prebuilt JAR or Maven Wrapper.

## Installation

1. Build the project using the steps above.
2. Copy `target/backdoorguard-1.2.0.jar` into the server's `plugins/` directory.
3. Start the server and review the console for startup errors.
4. Open `plugins/BackdoorGuard/config.yml` and review scanning limits, the alert threshold, trusted hashes, webhook settings, and the selected language.
5. Run `/bguard status` and `/bguard scan`, then review the reports on a staging server before production use.

Choose a language in `plugins/BackdoorGuard/config.yml`:

```yaml
language: "en"
```

Available language codes: `en`, `vi`, `es`, `zh_CN`, `fr`, `de`, `pt_BR`, `ru`, `ja`, `ko`.

## Admin commands

| Command | Purpose |
|---|---|
| `/bguard status` | Show scanner and watcher status. |
| `/bguard scan` | Start a manual background scan. |
| `/bguard audit` | Audit the loaded plugin inventory and code-source locations. |
| `/bguard reload` | Reload configuration and restart configured watchers. |
| `/bguard trust <file.jar>` | Hash a JAR directly in the `plugins/` directory and add that exact hash to the static-scan trust list. **Only use after independent verification.** |
| `/bguard cache clear` | Clear cached scan results. |
| `/bguard vl <player>` | Inspect the command-heuristic violation score for a player. |

The primary administrative permission is `backdoorguard.admin`. Alert recipients use `backdoorguard.notify`; `backdoorguard.bypass` bypasses player-command heuristics and should be granted sparingly.

## Configuration and safe operation

- Lowering `jar-scanner.alert-threshold` increases sensitivity and may increase false positives.
- `jar-scanner.worker-threads` controls parallel scan workers; keep resource limits appropriate for the host.
- `known-bad-jar-hashes` should contain SHA-256 hashes from trusted, independently verified incident information.
- `trusted-jar-hashes` skips static scanning for the exact matching file hash. A file update changes its hash; do not trust by filename alone.
- `known-good-signature-exceptions` can reduce selected generic indicator weights for an exact SHA-256 hash. It does not prove a file is safe, and structural findings/correlations may still raise alerts.
- `known-plugin-identities` is optional. Verify a plugin's published `name` and `main` class before pinning them; legitimate releases may change metadata.
- Keep webhook URLs and tokens private. Do not commit live secrets, server logs containing private data, or production JARs to a public repository.
- Back up the server and verify suspicious files with their official publisher before taking action. BackdoorGuard never automatically removes or disables a file based on a score.

## Validation status

See [VALIDATION.md](VALIDATION.md) for the detailed check record. The documented smoke checks include Java compilation against temporary lightweight Bukkit/Paper API stubs, parsing of sample compiled class files, malformed class-file tests, a behavior-indicator probe, and consistency checks across the ten YAML language files.

**Not yet verified:** `mvn clean package` against the real Paper API, a live Paper/Spigot server startup, cross-version compatibility, sustained load/performance, and detection precision/recall on a representative labeled malware/benign corpus.

## Detection limitations

The analyzer is a bounded static heuristic. It does not currently build a complete control-flow graph, perform full interprocedural data-flow/taint analysis, emulate plugin runtime behavior, or prove that sensitive data was actually exfiltrated. Obfuscation, reflection, remote payloads, delayed triggers, and environment-specific behavior can evade static detection. Legitimate plugins can also use networking, file I/O, reflection, encoded data, and dynamic class loading.

A finding is an **investigation lead**, not proof. Review the exact hash, publisher, source code, and surrounding behavior before classifying a plugin as malicious.

## License

Released under the [MIT License](LICENSE). See the license text for the applicable terms.

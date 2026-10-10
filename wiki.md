# BackdoorGuard Wiki

English documentation for BackdoorGuard 1.2.0. For Vietnamese, see [README.vi.md](README.vi.md).

> **Important status note:** this repository is a source release. The project has passed documented static smoke checks, but a Maven build against the real Paper API and a live-server integration test have not yet been verified. Read [VALIDATION.md](VALIDATION.md) before deploying it.

## Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Build and install](#build-and-install)
- [First-run checklist](#first-run-checklist)
- [Commands and permissions](#commands-and-permissions)
- [Configuration reference](#configuration-reference)
- [Understanding scan results](#understanding-scan-results)
- [Trusted and known-bad hashes](#trusted-and-known-bad-hashes)
- [Trusted plugin identities](#trusted-plugin-identities)
- [Languages and Discord alerts](#languages-and-discord-alerts)
- [Troubleshooting](#troubleshooting)
- [Limitations and safe use](#limitations-and-safe-use)
- [Reporting a bug or false positive](#reporting-a-bug-or-false-positive)

## Overview

BackdoorGuard is a heuristic static scanner and runtime auditing helper for Minecraft server administrators. It inspects JAR archives and JVM class files for suspicious references, method calls, strings, structural anomalies, and combinations of behavior indicators. It also monitors selected changes in the plugin directory and running server.

Current source capabilities include:

- JAR and class-file inspection, including bytecode member references and embedded strings.
- Risk scoring for combinations of process execution, networking, file or environment access, credential-related indicators, reflection, dynamic class loading, serialization, JVM agent flags, and privilege-related behavior.
- Bounded archive inspection, including duplicate entries, suspicious paths and compression ratios, nested archives, malformed class files, and configured size/depth limits.
- Bounded inspection of Base64-like strings. Decoded content is analyzed statically; it is never executed.
- SHA-256 hashing, a configurable known-bad hash list, trusted hashes, and narrow hash-based scoring exceptions.
- Background scans with a bounded worker pool and cached results for previously scanned clean hashes.
- `WatchService` monitoring of JAR files under the `plugins/` directory.
- Runtime audit signals for plugin identity/source changes, selected JVM options, command-map changes, OP-list changes, and BackdoorGuard protection hooks.
- Ten language files and optional Discord webhook alerts.

These are code-level capabilities, not proof that every feature has been validated against a real malicious sample or every server build.

## Requirements

- JDK 21
- Maven 3.9 or newer
- Internet access to resolve Maven dependencies
- Paper API 1.21.1 is declared in `pom.xml` as a `provided` dependency

The source targets the Paper/Spigot 1.21 ecosystem, but compatibility with every Paper or Spigot build has not been integration-tested. Start with a test server matching your production environment.

## Build and install

1. Download or clone this repository.
2. Open a terminal in the directory containing `pom.xml`.
3. Build the project:

   ```bash
   mvn clean package
   ```

4. If the build succeeds, the expected JAR is `target/backdoorguard-1.2.0.jar`.
5. Copy that JAR into the server's `plugins/` directory.
6. Start the server and check the console for startup errors.
7. Review `plugins/BackdoorGuard/config.yml` and test on a staging server before production use.

The repository does not include a prebuilt release JAR or Maven Wrapper. If Maven cannot resolve the Paper dependency, check the JDK/Maven versions and repository access before assuming the source is broken.

## First-run checklist

1. **Back up the server** before testing a new security plugin.
2. Set `language` in `plugins/BackdoorGuard/config.yml` to your preferred language code.
3. Read the `whitelisted-ops` warning below before populating it. Keep the list empty unless you intend to enable strict OP enforcement and have verified every allowed operator.
4. Start the server and run `/bguard status`.
5. Run `/bguard scan` and review the scan summary and logs.
6. Investigate flagged JARs manually. Confirm the publisher, release source, SHA-256, and behavior before taking action.
7. Configure a Discord webhook only if you want off-server alerts; keep the webhook URL secret.

## Commands and permissions

All listed subcommands are available under `/bguard` and require `backdoorguard.admin`.

| Command | Description |
|---|---|
| `/bguard status` | Displays scanner/watcher status and selected protection status. |
| `/bguard scan` | Starts a manual background scan. A completion message reports totals such as scanned, alerted, trusted-skipped, cached, and errors. |
| `/bguard audit` | Requests an audit of the loaded plugin inventory and code-source locations. |
| `/bguard reload` | Reloads configuration and restarts configured watchers/tasks. |
| `/bguard trust <file.jar>` | Computes the SHA-256 of a JAR directly in the root `plugins/` directory and adds that exact hash to `trusted-jar-hashes`. Read the warning below before using it. |
| `/bguard cache clear` | Clears cached scan results. |
| `/bguard vl <player>` | Displays the player's command-heuristic violation score. This is not the score of a JAR scan. |

### Permissions

| Permission | Default | Purpose |
|---|---|---|
| `backdoorguard.admin` | Operators | Use administrative commands. |
| `backdoorguard.notify` | Operators | Receive security alerts in chat. |
| `backdoorguard.bypass` | Nobody | Bypass player-command heuristics. Grant only to accounts you trust. |

There is no `/bguard help` subcommand in this version; use this page for command documentation.

## Configuration reference

The main configuration is `plugins/BackdoorGuard/config.yml`. Comments in the generated configuration explain many individual options. Reload with `/bguard reload` after editing, unless a change specifically requires a full server restart.

### General and alerts

| Key | Purpose |
|---|---|
| `language` | Default language and fallback for the console or unknown locales. |
| `logging.enabled` | Enables BackdoorGuard's file logging. |
| `logging.broadcast-to-admins` | Sends supported alerts to online staff with notify permission. |
| `discord.webhook-url` | Optional Discord webhook URL. Leave empty to disable. |
| `discord.username` | Username displayed by webhook messages. |

### JAR scanner

| Key | Purpose |
|---|---|
| `jar-scanner.enabled` | Enables or disables the JAR scanner. |
| `jar-scanner.recursive` | Includes JARs in plugin subdirectories. |
| `jar-scanner.max-jars-per-scan` | Maximum number of JARs considered in one scan. |
| `jar-scanner.max-jar-size-mb` | Maximum JAR file size accepted for scanning. |
| `jar-scanner.max-entry-size-mb` | Per-entry size limit. |
| `jar-scanner.max-uncompressed-mb-per-jar` | Total uncompressed-data limit per JAR. |
| `jar-scanner.max-entries-per-jar` | Maximum archive entry count. |
| `jar-scanner.scan-resource-files` | Includes configured resource-file checks. |
| `jar-scanner.encoded-string-check` | Enables bounded encoded-string checks. |
| `jar-scanner.alert-threshold` | Score at which scanner findings trigger an alert. Lower values are more sensitive and may increase false positives. |
| `jar-scanner.worker-threads` | Number of background scan workers. Use conservative values on small servers. |
| `jar-scanner.watch-enabled` | Enables monitoring for JAR changes under `plugins/`. |
| `jar-scanner.watch-debounce-ms` | Delay used to avoid scanning a JAR while it is still being copied or modified. |
| `jar-scanner.max-nested-archives-per-jar` | Maximum nested archives inspected per JAR. |
| `jar-scanner.max-nested-depth` | Maximum nested archive depth. |
| `jar-scanner.weights` | Individual static-scan indicator weights. |
| `jar-scanner.combinations` | Additional weights for correlated indicator combinations. |

Archive and worker limits are safeguards. Raising them may consume additional memory and CPU. Tune them on a staging server before changing production defaults.

### Hashes and identity checks

| Key | Purpose |
|---|---|
| `known-bad-jar-hashes` | SHA-256 hashes of files independently verified as malicious. A match raises a critical alert. |
| `trusted-jar-hashes` | SHA-256 hashes explicitly trusted by the administrator. Matching JARs are skipped by static scanning. |
| `known-good-signature-exceptions` | Hash-pinned exceptions that reduce selected generic signature weights. Correlation rules can still contribute points. |
| `known-plugin-identities` | Optional mapping of plugin metadata names to their expected main class. Only add values confirmed from the publisher's official release. |
| `plugin-audit.baseline-delay-seconds` | Delay before the initial runtime plugin baseline is recorded. |
| `plugin-audit.check-interval-seconds` | Runtime plugin audit interval. |
| `plugin-audit.check-source-path` | Checks plugin code-source paths where available. |
| `jvm-audit.enabled` | Enables checks for selected suspicious JVM startup options. |

**Important:** a trusted hash is an allowlist bypass, not proof that a file is safe. A file updated by its publisher has a different hash and must be reviewed again. The known-bad list is intended to take precedence for known-bad matches; do not treat trust as a substitute for verification.

Example identity pin configuration (verify the actual main class from the official plugin release before enabling):

```yaml
known-plugin-identities:
  ExamplePlugin: com.example.plugin.ExamplePluginMain
```

Do not copy example values into your real configuration without independently verifying them.

### OP enforcement and player-command heuristics

| Key | Purpose |
|---|---|
| `whitelisted-ops` | Names or UUIDs of operators permitted by strict OP enforcement. |
| `suspicious-keywords` | Command tokens/phrases considered suspicious by the command heuristic. |
| `command-guard.ignore-known-commands` | Avoids treating recognized commands as suspicious based solely on their name. |
| `command-guard.detect-unknown-command-attempts` | Controls whether unknown command attempts contribute to the heuristic. Disabled by default. |
| `violation.decay-per-interval` | Amount by which player violation scores decay. |
| `violation.decay-interval-seconds` | Score decay interval. |
| `violation.restrict-threshold` | Score at which player commands are temporarily restricted. |
| `violation.kick-threshold` | Score at which the player may be kicked. |
| `violation.restrict-duration-seconds` | Duration of command restriction. |
| `violation-weights` | Weights for command/OP-related events. |
| `chat-trigger.enabled` | Enables correlation of suspicious chat strings with subsequent OP changes. |
| `chat-trigger.correlation-window-seconds` | Time window for the chat-to-OP correlation. |
| `command-map-watch.enabled` | Enables periodic command-map checks. |
| `command-map-watch.baseline-delay-seconds` | Delay before the command map baseline is stored. |
| `command-map-watch.check-interval-seconds` | Command-map audit interval. |
| `op-watch.interval-seconds` | Polling interval for the OP list. |
| `self-integrity.interval-seconds` | Interval for BackdoorGuard self-integrity checks. |

**Read before enabling strict OP enforcement:** when `whitelisted-ops` is empty, the plugin fails safe and does not remove operators. If you populate this list, operators not present in it may be de-opped and kicked. Add all legitimate operator names/UUIDs carefully and test this behavior on a staging server first.

The player-command violation score is separate from JAR risk scoring. A command score is heuristic and should not be treated as proof that a player or plugin is malicious.

## Understanding scan results

BackdoorGuard assigns weights to indicators and adds extra points for selected combinations. It reports files whose score reaches `jar-scanner.alert-threshold`, as well as certain critical structural or hash-based signals.

Examples of indicators include process execution APIs, network clients/sockets, file access, environment-variable access, reflection, class loaders, encoded data, native loading, and suspicious archive structure. These APIs may also be used by legitimate software.

When an alert appears:

1. Record the filename and SHA-256.
2. Check the plugin's official publisher and download source.
3. Review which indicators and combinations caused the score.
4. Compare the hash with a trusted source or known-good release, where available.
5. Test the plugin in an isolated staging server or inspect its source before deciding whether it is malicious.

A high score means **investigate this file**, not “malware proven.” Lowering the alert threshold increases sensitivity and usually increases false positives.

## Trusted and known-bad hashes

### Trust a JAR carefully

`/bguard trust <file.jar>` hashes a JAR in the root of the server's `plugins/` directory and adds that exact SHA-256 to `trusted-jar-hashes`. The JAR is then skipped by static scanning when its hash matches.

Only trust a file if you have independently verified the publisher and exact artifact. Never trust a suspicious file just to silence an alert. Do not rely on its filename alone. Review the saved hash in `config.yml` and keep a separate record of why it was trusted.

### Known-bad hashes

Use `known-bad-jar-hashes` only for SHA-256 values verified from reliable incident-response information. Incorrect entries can cause legitimate files to be flagged. BackdoorGuard reports matches; it does not automatically delete or disable the JAR.

## Trusted plugin identities

`known-plugin-identities` is an optional metadata consistency check. It can help flag a plugin whose metadata claims a known name while the declared main class differs from the configured expected class. It is not a global signature database, and it does not prove a plugin's publisher is genuine. Main classes may change across legitimate releases, so update pins only after checking the official release.

## Languages and Discord alerts

Supported language codes:

- `en` — English
- `vi` — Vietnamese
- `es` — Spanish
- `zh_CN` — Simplified Chinese
- `fr` — French
- `de` — German
- `pt_BR` — Brazilian Portuguese
- `ru` — Russian
- `ja` — Japanese
- `ko` — Korean

Set the `language` key in `config.yml`, then run `/bguard reload`. Player-facing messages can use a supported player locale; the configured language is the fallback.

To enable Discord alerts, set `discord.webhook-url` to a webhook URL you control. Treat it like a password: do not commit it to GitHub, include it in screenshots, or post it in public bug reports. If the URL has been exposed, rotate/delete that webhook and create a new one.

## Troubleshooting

### The plugin does not load

- Confirm the server is using a compatible Java runtime (JDK 21 for building; the server runtime must meet the Paper API requirements).
- Confirm the built JAR is from `target/backdoorguard-1.2.0.jar` and placed in `plugins/`.
- Inspect the full console stack trace and check that Paper API dependency resolution/build succeeded.
- Remember that this source release has not yet been verified by a real Paper API Maven build or live-server test.

### No scan alert appears

- Run `/bguard status` and verify scanning is enabled.
- Run `/bguard scan` and check the completion summary for errors, trusted skips, or cached results.
- Confirm the JAR is inside the watched/scanned `plugins/` tree and below configured size and entry limits.
- A clean result is not proof of safety; static heuristics can miss obfuscated, delayed, remote, or runtime-only behavior.

### Too many false positives

- Review the individual indicators and correlations rather than trusting the total score alone.
- Verify the JAR's publisher and hash first.
- Adjust `jar-scanner.alert-threshold` carefully in a staging environment.
- Prefer a reviewed, exact SHA-256-based exception over a broad rule change, and understand that trusting a hash skips static scanning for that artifact.

### A changed JAR is scanned more than once

File watchers can receive multiple events during a file copy/update. The debounce/stability window is intended to reduce duplicate scans; if this persists, review `jar-scanner.watch-debounce-ms` and avoid uploading JARs while the server is under active maintenance.

## Limitations and safe use

BackdoorGuard uses bounded static heuristics. It does not build a complete control-flow graph, perform exhaustive interprocedural data-flow/taint analysis, emulate every plugin at runtime, or prove that sensitive data was actually exfiltrated. Obfuscation, reflection, delayed triggers, environment-dependent behavior, native code, and remote payloads may evade detection. Legitimate plugins also use APIs that can look suspicious in isolation.

- Always test on a staging server first.
- Keep backups and maintain server access outside the game in case a configuration locks down expected operator accounts.
- Do not automatically classify, delete, or disable a plugin solely from a score.
- Keep secrets and private server data out of public repositories and logs.
- Treat audit messages as indicators to investigate; they are not cryptographic proof of compromise.

## Reporting a bug or false positive

When opening a GitHub issue, include:

- BackdoorGuard version and server software/version.
- Java runtime version.
- Relevant configuration with webhook URLs, IPs, player identifiers, and other secrets removed.
- The exact warning/rule ID, if present, and the relevant sanitized log lines.
- Whether the behavior is reproducible on a test server.

Do not upload suspicious or proprietary JARs publicly unless you have permission and understand the risk. Share the SHA-256 and a safe description first when possible.

---

[Back to README](README.md) · [Vietnamese README](README.vi.md) · [Validation notes](VALIDATION.md) · [MIT License](LICENSE)

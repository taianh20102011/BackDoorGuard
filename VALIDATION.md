# BackdoorGuard 2.0.0 — validation notes

This archive combines the detailed JAR scanner and audit routines from the 1.2.0 line with selected v2 utilities/heuristics and configurable beginner/advanced profiles.

## Checks completed for this merged source

- All bundled YAML files parsed successfully, including `config.yml`, `plugin.yml`, and the ten language files.
- `pom.xml` parsed successfully as XML.
- All 24 Java source files compiled with `javac --release 21 -Xlint:all -proc:none` against temporary lightweight Bukkit/Paper-shaped stubs; no compiler errors or warnings were emitted. This validates Java syntax and the APIs represented in those stubs, not the actual Paper API integration.
- URL classifier smoke checks passed for Discord webhooks, Telegram Bot API, paste hosts, tunnel/dynamic DNS hosts, public endpoint IPs, version strings that resemble IPs, host-suffix lookalikes, and configured custom hosts.
- Plugin descriptor `loadbefore` / `load-before` parser smoke checks passed for inline and block-list formats.
- Reviewed profile routing, commands, watcher controls, URL scoring, cache fingerprint inputs, and JVM-argument log redaction.

## Build/integration status

A real `mvn clean package` was **not run**: Maven is not installed in this environment, and outbound repository access/DNS was unavailable, so the Paper API dependency could not be resolved here. The included GitHub Actions workflow can perform a real Maven build when run in an environment with access to Maven Central/Paper repositories. No prebuilt JAR is included in this source ZIP.

The project targets JDK 21 and Paper API `1.21.1-R0.1-SNAPSHOT`. A successful syntax/config check is not equivalent to a successful Maven build or live-server test. Still unverified: actual Paper API linkage, startup on a live Paper/Spigot server, cross-version compatibility, sustained load/performance, and detection precision/recall against a representative labeled malware/benign corpus.

## Detection limitations

BackdoorGuard is a bounded static heuristic, not complete control-flow/data-flow analysis. It may miss obfuscated, encrypted, remote, delayed, or environment-dependent payloads. Legitimate plugins may use similar APIs, so findings require investigation. It never automatically deletes, modifies, or disables a JAR based on score.

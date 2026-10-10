# BackdoorGuard 1.2.0 — validation notes

Checks run for this source archive on 2026-10-10:

- All Java source files compiled with `javac -Xlint:all` against temporary lightweight Bukkit/Paper API stubs. The stubs were used only for a local syntax/API-shape smoke test and are not included in this archive.
- The bytecode analyzer parsed 58 compiled class files from the smoke-test output without rejecting any of them.
- A dedicated class-file test confirmed that a representative class is accepted while truncated data and trailing bytes are rejected.
- A compiled probe containing environment-variable access, HTTP output, and process execution exposed the expected bytecode member references.
- All 10 language files parse as YAML, contain 159 unique keys each, and have matching key sets. `config.yml`, `plugin.yml`, and `pom.xml` also parse successfully.

**Not verified:** Maven is not installed in the build environment and no Paper API JAR is cached locally, so a real `mvn clean package` against Paper API has not been completed here. Build on a machine with JDK 21, Maven 3.9+, and repository access. The analyzer is a bounded static heuristic, not full control-flow/data-flow analysis; it cannot guarantee detection of every backdoor.

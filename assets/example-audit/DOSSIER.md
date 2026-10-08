# ultrasec audit dossier

- repo: `examples/vuln-express`
- languages: javascript
- external tools run: none (graph + taint only)
- findings: **4** — 🟥 CRIT 1  🟧 HIGH 1  🟨 MED 1  🟩 LOW 1  ⬜ INFO 0

> Candidates are deterministic and **recall-oriented** — every one needs
> adjudication. Open each with `ultrasec dossier <id>` (real code + the
> cross-file path), confirm whether the flow is real and exploitable, then
> record a verdict via `ultrasec verify`. An uncertain high-severity stays
> **needs-human** — never silently dropped.

## Candidates (index — 3 live, 1 dismissed not listed)

One line per candidate, decided first, then by risk. Open one with `ultrasec dossier <id> --run <run>`
(`--brief` for batches); filter with `ultrasec paths --run <run> --surface code`. Never load
findings.json or .work/graph.json whole.

- `3ffa0917b004` 🟥 CRIT OS command injection: untrusted input reaches execSync() — `src/server.js:18 → src/report.js:5` · confirmed · risk 60
- `54b733703450` 🟧 HIGH SQL injection: untrusted input reaches query() — `src/server.js:10 → src/db.js:6` · confirmed · risk 48
- `698ed561f7dd` 🟩 LOW Web misconfig — No security-headers middleware where the app is built — `src/server.js:5` · needs-human · risk 15

---
Engine: ultrasec 0.0.0-development. Taint candidates are deterministic; external-tool results depend on installed scanners.

# ultrasec audit dossier

- repo: `examples/vuln-express`
- languages: javascript
- external tools run: none (graph + taint only)
- findings: **3** — 🟥 CRIT 1  🟧 HIGH 1  🟨 MED 1  🟩 LOW 0  ⬜ INFO 0

> Candidates are deterministic and **recall-oriented** — every one needs
> adjudication. Open each with `ultrasec dossier <id>` (real code + the
> cross-file path), confirm whether the flow is real and exploitable, then
> record a verdict via `ultrasec verify`. An uncertain high-severity stays
> **needs-human** — never silently dropped.

## Candidates

### 3ffa0917b004 — 🟥 CRIT OS command injection: untrusted input reaches execSync()

- category: taint · CWE-78 · confidence high · status confirmed
- path: `src/server.js:18` → `src/server.js:19` → `src/report.js:5`
- Cross-file candidate: http input at src/server.js:18 may reach the command sink execSync() at src/report.js:5 through 2 hop(s). Tainted data in a shell command. Prefer argv-array exec (execFile/execve) over a shell string; verify no shell metacharacters reach a shell. Heuristic — verify the data actually reaches the sink unsanitized before trusting it.

Verdict (supported): req.query.name flows into execSync shell string in report.runReport

### 54b733703450 — 🟧 HIGH SQL injection: untrusted input reaches query()

- category: taint · CWE-89 · confidence high · status confirmed
- path: `src/server.js:10` → `src/server.js:11` → `src/db.js:6`
- Cross-file candidate: http input at src/server.js:10 may reach the sql sink query() at src/db.js:6 through 2 hop(s). Tainted data concatenated into a SQL statement. Verify it isn't a parameterized/prepared query. Heuristic — verify the data actually reaches the sink unsanitized before trusting it.

Verdict (supported): req.query.id concatenated into SQL across files; getUser builds a raw query

### 9b0bcc91ea6a — 🟨 MED Cross-site scripting (reflected): untrusted input reaches send()

- category: taint · CWE-79 · confidence low · status dismissed
- path: `src/server.js:18` → `src/server.js:20`
- Intra-file candidate: http input at src/server.js:18 may reach the xss sink send() at src/server.js:20 through 1 hop(s). Tainted data written to an HTML response. Verify it is contextually escaped before reaching the browser. Heuristic — verify the data actually reaches the sink unsanitized before trusting it.

Verdict (refuted): res.send echoes server-generated report text, not attacker HTML in a browser-executable context

---
Engine: ultrasec 0.0.0-development. Taint candidates are deterministic; external-tool results depend on installed scanners.

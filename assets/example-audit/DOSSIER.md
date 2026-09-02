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

## Candidates

### 3ffa0917b004 — 🟥 CRIT OS command injection: untrusted input reaches execSync()

- category: taint · CWE-78 · confidence high · status confirmed
- risk 60
- path: `src/server.js:18` → `src/server.js:19` → `src/report.js:5`
- Cross-file candidate: http input at src/server.js:18 may reach the command sink execSync() at src/report.js:5 through 2 hop(s). Tainted data in a shell command. Prefer argv-array exec (execFile/execve) over a shell string; verify no shell metacharacters reach a shell. Heuristic — verify the data actually reaches the sink unsanitized before trusting it.

Verdict (supported): req.query.name is concatenated into a shell string at report.js:5 and executed with execSync; no validation on any hop, and the route has no auth.

Revalidation (still-valid): report.js:5 is unchanged at HEAD — still execSync on a concatenated string.

### 54b733703450 — 🟧 HIGH SQL injection: untrusted input reaches query()

- category: taint · CWE-89 · confidence high · status confirmed
- risk 48
- path: `src/server.js:10` → `src/server.js:11` → `src/db.js:6`
- Cross-file candidate: http input at src/server.js:10 may reach the sql sink query() at src/db.js:6 through 2 hop(s). Tainted data concatenated into a SQL statement. Verify it isn't a parameterized/prepared query. Heuristic — verify the data actually reaches the sink unsanitized before trusting it.

Verdict (supported): req.query.id is concatenated into SQL at db.js:5 and reaches sqlite.query() with no parameter array. The parameterized sibling getUserSafe (db.js:11) is NOT on this path.

Revalidation (still-valid): db.js:6 is unchanged at HEAD, and the concatenation it consumes is still at db.js:5.

### 698ed561f7dd — 🟩 LOW Web misconfig — No security-headers middleware where the app is built

- category: config · CWE-693 · confidence medium · status needs-human
- risk 15
- at: `src/server.js:5`
- The file constructs the application and registers no `helmet()` / `secureHeaders()` / equivalent. Without it the responses carry no CSP, HSTS, X-Frame-Options or X-Content-Type-Options. Register it first, before any route — unless a reverse proxy in front sets these headers, which is the thing to check.

Evidence: `const app = express();`

Verdict (partial): server.js:5 builds the Express app and registers no helmet()/security-headers middleware, so responses carry no CSP, HSTS or X-Frame-Options. Real, but a hardening gap rather than an exploit on its own: what it costs depends on whether a reverse proxy in front sets these headers, which the repo cannot show.

### 9b0bcc91ea6a — 🟨 MED Cross-site scripting (reflected): untrusted input reaches send()

- category: taint · CWE-79 · confidence low · status dismissed
- risk 30
- path: `src/server.js:18` → `src/server.js:20`
- Intra-file candidate: http input at src/server.js:18 may reach the xss sink send() at src/server.js:20 through 1 hop(s). Tainted data written to an HTML response. Verify it is contextually escaped before reaching the browser. Heuristic — verify the data actually reaches the sink unsanitized before trusting it.

Verdict (unsupported): The argument to res.send() at server.js:20 is `out` — the return value of runReport() — not req.query.name, so the query parameter is never reflected. The attacker does control that output, but only by way of the command injection at report.js:5, whose impact (RCE) subsumes it; reporting a separate MEDIUM XSS would double-count one bug. Tracked by 3ffa0917b004.

---
Engine: ultrasec 0.0.0-development. Taint candidates are deterministic; external-tool results depend on installed scanners.

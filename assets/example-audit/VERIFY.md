# ultrasec verification worklist (3)

For each item: open the cited code (`ultrasec dossier <id>`), decide whether
the flow is **real and exploitable**, and set a verdict:
`supported` · `partial` · `unsupported` · `refuted` (+ a short note, and an
`exploitPath` when supported). Save as verdicts.json (array of
{id, verdict, note, exploitPath}) and run `ultrasec verify --apply verdicts.json`.

> Be skeptical, but do NOT dismiss a high/critical finding unless you can
> positively **refute** it. Uncertain ⇒ leave it for a human.

## Project context
_From `CONTEXT.md` — the project's trust model; background, never a verdict._

# Project context — vuln-express

A tiny Express HTTP API (demo). Two GET routes under `/`:
- `GET /user?id=` — looks a user up by id.
- `GET /report?name=` — runs a named report.

**Trust model.** Every request is untrusted: `req.query.*` is attacker-controlled.
There is **no authentication or authorization** — all routes are public by design
for the demo, so the risk is purely injection, not access control.

**Framework protections.** None configured. No ORM (raw SQL strings), no input
validation middleware, no output encoding. Treat every `req.query` value as hostile.

**Known-safe.** `db.getUserSafe` uses a parameterized query (`?` placeholder) and is
NOT exploitable — do not flag it.

## 3ffa0917b004 — [critical] OS command injection: untrusted input reaches execSync()
- CWE-78 · taint
- files: `src/server.js:18`, `src/server.js:19`, `src/report.js:5`
- claim: Cross-file candidate: http input at src/server.js:18 may reach the command sink execSync() at src/report.js:5 through 2 hop(s). Tainted data in a shell command. Prefer argv-array exec (execFile/execve) over a shell string; verify no shell metacharacters reach a shell. Heuristic — verify the data actually reaches the sink unsanitized before trusting it.

## 54b733703450 — [high] SQL injection: untrusted input reaches query()
- CWE-89 · taint
- files: `src/server.js:10`, `src/server.js:11`, `src/db.js:6`
- claim: Cross-file candidate: http input at src/server.js:10 may reach the sql sink query() at src/db.js:6 through 2 hop(s). Tainted data concatenated into a SQL statement. Verify it isn't a parameterized/prepared query. Heuristic — verify the data actually reaches the sink unsanitized before trusting it.

## 9b0bcc91ea6a — [medium] Cross-site scripting (reflected): untrusted input reaches send()
- CWE-79 · taint
- files: `src/server.js:18`, `src/server.js:20`
- claim: Intra-file candidate: http input at src/server.js:18 may reach the xss sink send() at src/server.js:20 through 1 hop(s). Tainted data written to an HTML response. Verify it is contextually escaped before reaching the browser. Heuristic — verify the data actually reaches the sink unsanitized before trusting it.


<!-- ultrasec IMPLEMENT draft — feed this file to the `to-prd` skill to author the remediation PRD, or hand it to an implementer/AI. Every item is grounded in a confirmed [file:line]. -->
# Remediation PRD draft — 2 fixes, 0 to investigate
_AI-authored — verify against the cited findings before acting._

> Deterministic draft from the ultrasec dossier. Feed it to the **`to-prd`** skill to
> author the remediation PRD, or hand it to an implementer/AI. It never changes a
> finding's status, severity, or set — every work item cites a confirmed `[file:line]`.

## Project context
_From `CONTEXT.md`._

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

## Problem statement

The audit confirmed **2** exploitable finding(s) (1 critical, 1 high) that must be remediated.

## Solution

Fix at the root cause where possible:

### Root cause: Request values handed to a helper that builds an interpreter string
- findings: `3ffa0917b004`, `54b733703450`
- Both handlers read req.query.* and pass it, unvalidated, to a helper that concatenates it into SQL or a shell command. The fix is structural, not per-site: bind parameters at the data layer and use argv arrays for process execution, then add validation at the route boundary so a future helper inherits neither habit.

## User stories / work items

1. **Fix `OS command injection: untrusted input reaches execSync()`** at `src/server.js:18 → src/server.js:19 → src/report.js:5` so it is no longer exploitable. _([critical] CWE-78 · `3ffa0917b004` · owner @backend)_
   - Suggested fix (AI): Replace execSync with execFile and an argv array: execFile("generate-report", ["--for", name]). An argv array removes the shell, but it does not stop argument injection — validate `name` against an allow-list (or pass it after a `--` terminator) so it can't be read as an option.
   - Suggested patch:
     ```diff
     - return execSync("generate-report --for " + name).toString();
     + return execFileSync("generate-report", ["--for", "--", name]).toString();
     ```
   - Acceptance criteria:
     - [ ] The cited line `src/server.js:18 → src/server.js:19 → src/report.js:5` is no longer exploitable for this finding.
     - [ ] A regression test reproduces the issue before the fix and passes after it.
2. **Fix `SQL injection: untrusted input reaches query()`** at `src/server.js:10 → src/server.js:11 → src/db.js:6` so it is no longer exploitable. _([high] CWE-89 · `54b733703450` · owner @backend)_
   - Suggested fix (AI): Bind the value instead of concatenating it, exactly as getUserSafe already does: sqlite.query("SELECT * FROM users WHERE id = ?", [id]).
   - Suggested patch:
     ```diff
     - const sql = "SELECT * FROM users WHERE id = " + id;
     - return sqlite.query(sql);
     + return sqlite.query("SELECT * FROM users WHERE id = ?", [id]);
     ```
   - Acceptance criteria:
     - [ ] The cited line `src/server.js:10 → src/server.js:11 → src/db.js:6` is no longer exploitable for this finding.
     - [ ] A regression test reproduces the issue before the fix and passes after it.

## Out of scope
- 1 finding(s) were dismissed during the audit — not in scope for this work.


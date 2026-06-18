<!-- ultrasec IMPLEMENT draft — feed this file to the `to-prd` skill to author the remediation PRD, or hand it to an implementer/AI. Every item is grounded in a confirmed [file:line]. -->
# Remediation PRD draft — 3 fixes, 0 to investigate
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

The audit confirmed **3** exploitable finding(s) (1 critical, 1 high, 1 medium) that must be remediated.

## Solution

Fix at the root cause where possible:

### Root cause: Untrusted request input concatenated into interpreters
- findings: `3ffa0917b004`, `54b733703450`, `9b0bcc91ea6a`
- Centralize input handling: parameterized queries + argv-array exec, plus an input-validation layer.

## User stories / work items

1. **Fix `OS command injection: untrusted input reaches execSync()`** at `src/server.js:18 → src/server.js:19 → src/report.js:5` so it is no longer exploitable. _([critical] CWE-78 · `3ffa0917b004` · owner @backend)_
   - Suggested fix (AI): Use execFile with an argv array; never build a shell string from input.
   - Acceptance criteria:
     - [ ] The cited line `src/server.js:18 → src/server.js:19 → src/report.js:5` is no longer exploitable for this finding.
     - [ ] A regression test reproduces the issue before the fix and passes after it.
2. **Fix `SQL injection: untrusted input reaches query()`** at `src/server.js:10 → src/server.js:11 → src/db.js:6` so it is no longer exploitable. _([high] CWE-89 · `54b733703450` · owner @backend)_
   - Suggested fix (AI): Use a parameterized query (placeholders), never string concatenation.
   - Acceptance criteria:
     - [ ] The cited line `src/server.js:10 → src/server.js:11 → src/db.js:6` is no longer exploitable for this finding.
     - [ ] A regression test reproduces the issue before the fix and passes after it.
3. **Fix `Cross-site scripting (reflected): untrusted input reaches send()`** at `src/server.js:18 → src/server.js:20` so it is no longer exploitable. _([medium] CWE-79 · `9b0bcc91ea6a` · owner @backend)_
   - Suggested fix (AI): Use execFile with an argv array; never build a shell string from input.
   - Acceptance criteria:
     - [ ] The cited line `src/server.js:18 → src/server.js:20` is no longer exploitable for this finding.
     - [ ] A regression test reproduces the issue before the fix and passes after it.

## Out of scope
- Nothing dismissed.


# ultrasec revalidation worklist (3)

Each finding below was already ranked **real** (confirmed / needs-human). Using the
git facts, decide whether it is still a live issue and set a `verdict`:
`still-valid` · `fixed` · `false-positive` · `uncertain` (+ a short `note`, and
`fixedIn` — the fixing commit sha — when `fixed`). Save as REVALIDATE.json (array of
{id, verdict, fixedIn?, note?}) and run `ultrasec revalidate --apply REVALIDATE.json`.

> Conservative on apply: `fixed` → dismissed (records the fixing commit);
> a high/critical `false-positive` → **needs-human** (never auto-dismissed);
> `uncertain`/unknown → needs-human. `still-valid` keeps the finding as-is.

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
- at: `src/report.js:5` · file exists at HEAD: yes
- current line: `return execSync("generate-report --for " + name).toString();`
- line last changed: `5e902a3` (2026-01-15) by ultrasec example

## 54b733703450 — [high] SQL injection: untrusted input reaches query()
- at: `src/db.js:6` · file exists at HEAD: yes
- current line: `return sqlite.query(sql);`
- line last changed: `5e902a3` (2026-01-15) by ultrasec example

## 9b0bcc91ea6a — [medium] Cross-site scripting (reflected): untrusted input reaches send()
- at: `src/server.js:20` · file exists at HEAD: yes
- current line: `res.send(out);`
- line last changed: `5e902a3` (2026-01-15) by ultrasec example


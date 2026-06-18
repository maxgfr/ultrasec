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

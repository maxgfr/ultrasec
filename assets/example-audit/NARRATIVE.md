# ultrasec report-narrative worklist (2)

Author **NARRATIVE.json** (a Narrative object), then fold it into the report with
`ultrasec render --narrative NARRATIVE.json --run <run>`. Fields (all optional, all additive):
- `executiveSummary`: a few sentences for non-experts atop the report.
- `positivePatterns`: what the codebase does **well** (solid auth, parameterized queries…) — calibrates trust in the findings and helps prioritise. Free prose, advisory.
- `remediations`: `{id, fix, patch?, owner?}` — a concrete fix per **confirmed** finding.
- `attackChains`: `{title, findingIds[], narrative}` — how findings combine into an exploit.
- `rootCauses`: `{cause, findingIds[], note}` — group findings by shared underlying cause.
- `hardeningNotes`: `string[]` — defense-in-depth suggestions that are **not** findings (the attack is already prevented elsewhere). Advisory; excluded from the severity counts.

> Grounding is strict for finding-citing sections: any `remediations`/`attackChains`/`rootCauses`
> entry citing an **unknown or non-confirmed** finding id is dropped on merge. `executiveSummary`,
> `positivePatterns`, and `hardeningNotes` are advisory prose that cite no finding ids. Narrative
> prose **never** changes a finding's status, severity, or set.

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

## Reportable findings (cite these ids)

- `3ffa0917b004` — [critical] OS command injection: untrusted input reaches execSync() (CWE-78) · status confirmed · at src/server.js:18 → src/server.js:19 → src/report.js:5
- `54b733703450` — [high] SQL injection: untrusted input reaches query() (CWE-89) · status confirmed · at src/server.js:10 → src/server.js:11 → src/db.js:6

## Scaffold (starting point for NARRATIVE.json)
```json
{
  "executiveSummary": "",
  "positivePatterns": "",
  "remediations": [
    {
      "id": "3ffa0917b004",
      "fix": ""
    },
    {
      "id": "54b733703450",
      "fix": ""
    }
  ],
  "attackChains": [],
  "rootCauses": [],
  "hardeningNotes": []
}
```

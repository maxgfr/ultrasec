# Citation format

Every finding is grounded in real code. The contract:

- A finding's `source`, `sink`, and each `path` step carry a repo-relative
  `file` and a 1-based `line`. These render as `file:line` and **must resolve** —
  `check` fails on any that don't (file missing, or line out of range). This is the
  anti-hallucination gate: don't write a location you haven't seen in the dossier.

- The cross-file path reads source → hop(s) → sink, e.g.
  `src/server.js:10 → src/server.js:11 → src/db.js:6`. Each step's `why` explains
  the propagation ("untrusted input (http): req.query", "calls getUser()",
  "sql sink: query()").

- `cwe` uses the canonical id (`CWE-89`) and `references` link the CWE page and any
  advisory URLs. Severity is critical/high/medium/low/info; confidence is
  high/medium/low (taint candidates start `low` and rise to `high` only when you
  mark them `supported`).

- When you add a finding the engine didn't enumerate (authz, business logic…),
  give it the same shape: a real `[file:line]` for `sink` (and a `path` if it
  spans files), a `cwe`, a `severity`, and a `message` that states the exploit.
  `check` will hold it to the same grounding bar.

- `exploitPath` is a concrete trigger ("GET /user?id=1 OR 1=1") — include it for
  every `supported` finding; it's what makes a report actionable and what proves
  you reasoned the flow through, not just pattern-matched it.

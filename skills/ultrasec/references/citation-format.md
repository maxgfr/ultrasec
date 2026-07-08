# Citation format

Every finding is grounded in real code. The contract:

- A finding's `source`, `sink`, and each `path` step carry a repo-relative
  `file` and a 1-based `line`. These render as `file:line` and **must resolve** —
  `check` fails on any that don't (file missing, or line out of range). This is the
  anti-hallucination gate: don't write a location you haven't seen in the dossier.

- `line: 0` is an explicit **whole-file citation** — for IaC/config checks
  (checkov, trivy misconfig) that apply to a file, not a line. `check` verifies the
  file exists but does **not** range-check the line, so a fresh `--docker` scan never
  fails its own gate on a config finding. A negative or out-of-range positive line
  still fails. Dep advisories merged across versions keep their per-instance
  `locations[]` (each `{file, line?, version}`), graded the same way (line 0/absent
  = whole-file).

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

- **AI-discovered findings (`tool: "ultrasec-ai"`)** — those you add via
  `investigate` — are held to the **exact same grounding bar**. Their citations are
  checked *before* they're ingested: an out-of-range or nonexistent `[file:line]`
  (primary or any path step) is **rejected**, so `check` can never fail on an
  AI-invented line. A discovery at an existing finding's location folds into that
  finding's `sources` rather than duplicating it. `ultrasec-ai` is just a `tool`
  convention — no new category; they adjudicate like any candidate.

- **Upstream `priorAnalysis` is a signal, not a citation.** Reasoning ingested from
  an upstream agent (e.g. deepsec's `revalidationVerdict`) is surfaced in the dossier
  and the verify worklist clearly labelled "signal, not a verdict" — it never changes
  a status. ultrasec's own conservative `verify` gate is the only thing that does.

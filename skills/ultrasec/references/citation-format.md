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
  `check` will hold it to the same grounding bar. The complete `Finding` JSON, field by field
  with a filled example, is in [schemas.md](schemas.md).

- **Citing something that isn't there.** The hardest citation in an audit is a *missing* control —
  "there is no ownership check here". `check` only verifies that the line you cite exists, so an
  authz finding is structurally under-specified unless you make the absence concrete. Cite the
  line where the check **should** be and say what should be there: the load that returns the
  object (`invoice.js:42` — `findById(req.params.id)` with no owner predicate), plus a path step
  at the route registration showing which guards *do* apply (`routes.js:88` — "requireAuth only").
  Two resolvable lines that bracket the gap beat one vague one, and they survive a refactor.

- **`why` carries the argument.** Each path step's `why` should say what makes the value keep
  flowing — "concatenated into the SQL string", "passed as argv[1] to a shell", "stored, then
  rendered unescaped by the profile template". `"calls f()"` is what the engine writes when it
  only knows the edge exists; when you author a path, do better, because `why` is what a reviewer
  reads to check your reasoning without re-deriving it.

- **Line ranges, generated and vendored files.** Cite the single most specific line, not a range:
  the sink call, the assignment that taints, the guard that's missing. If the only honest citation
  is in generated, minified or vendored code, cite the **generator or the dependency
  declaration** instead — a finding pinned to a build artifact is unactionable and breaks on the
  next build.

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

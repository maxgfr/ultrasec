# Artifact & worklist schemas

Every file the engine writes for you to read, and every file you write for `--apply` to fold in.
Each entry: what produces it, the fields, and a **complete filled example** you can copy.

Two rules apply to everything below:

- **Every `--apply` parser is fail-closed on shape.** A row missing `id`, or carrying a verdict
  outside its enum, is dropped; if *no* row is usable the command exits 2 rather than folding
  nothing and reporting success. Enum values are exact lowercase strings.
- **Every `file`/`line` you write is grounding-checked.** `check` fails on a citation that
  doesn't resolve, and `investigate --apply` rejects a bad one *before* ingest. `line` is
  1-based; `line: 0` means "the whole file" (config/IaC findings) and skips the range check.

## Vocabularies

| enum | values |
|---|---|
| `severity` | `critical` · `high` · `medium` · `low` · `info` |
| `confidence` | `high` · `medium` · `low` |
| `category` | `taint` · `sast` · `dep` · `secret` · `config` · `authz` · `crypto` · `logs` · `privacy` · `other` (a vulnerability-class name is folded — see below) |
| `status` | `open` · `confirmed` · `needs-human` · `dismissed` |
| verify `verdict` | `supported` · `partial` · `unsupported` · `refuted` |
| triage `verdict` | `noise` · `keep` |
| revalidate `verdict` | `still-valid` · `fixed` · `false-positive` · `uncertain` |

`category` records **how** a finding was surfaced, not what class of bug it is. An auditor filing
a discovery naturally writes the class — `xss`, `ssrf`, `idor`, `dos`, `disclosure`,
`input-validation` — so those are accepted as **aliases** and folded onto the vocabulary, with
every rewrite reported (`↷ row 3: category "xss" folded to "taint"`). Anything that is untrusted
input reaching a dangerous operation folds to `taint`; `idor`/`csrf`/`access-control` to `authz`;
classes that assert no data flow (`dos`, `disclosure`, `robustness`, `business-logic`) to `other`.
A name nothing maps to is still refused, and names the accepted set.

This is not cosmetic. Before it, `investigate --apply` refused every one of those names and
exited 0 — on the first real audit that silently dropped 11 of 12 manual findings, in the one
stage that exists to carry the classes the engine cannot enumerate.

**How a verdict becomes a status** (`nextStatus`, shared by every adjudicating stage — this is
the conservative gate, and it is the same code for manual, powered and fan-out runs):

| verdict | low / medium / info | high / critical |
|---|---|---|
| `supported` | confirmed | confirmed |
| `refuted` | dismissed | dismissed |
| `unsupported` | **dismissed** | **needs-human** |
| `partial` | **needs-human** | **needs-human** |
| anything unrecognized | needs-human | needs-human |

Note `partial` → `needs-human` at *every* severity; only `unsupported` is severity-gated.
`triage`'s `noise` maps to `unsupported`, which is why it can only clear low/medium/info.

---

## `findings.json` — the Finding model

Written by `scan`/`import`, rewritten by every `--apply`. The dossier's core record.

```json
{
  "id": "7e51071c4783",
  "category": "taint",
  "cwe": "CWE-89",
  "title": "SQL injection: untrusted input reaches query()",
  "severity": "high",
  "confidence": "low",
  "source": { "file": "src/routes.js", "line": 12, "kind": "http" },
  "sink":   { "file": "src/db.js", "line": 7, "symbol": "runQuery", "kind": "sql" },
  "path": [
    { "file": "src/routes.js", "line": 12, "why": "untrusted input (http): req.query" },
    { "file": "src/routes.js", "line": 13, "why": "calls lookupUser()" },
    { "file": "src/service.js", "line": 6, "symbol": "lookupUser", "why": "calls runQuery()" },
    { "file": "src/db.js", "line": 7, "symbol": "runQuery", "why": "sql sink: query()" }
  ],
  "message": "Cross-file candidate: http input at src/routes.js:12 may reach the sql sink query() at src/db.js:7 through 3 hop(s).",
  "tool": "ultrasec",
  "sources": ["ultrasec", "semgrep"],
  "references": ["https://cwe.mitre.org/data/definitions/89.html"],
  "risk": 48,
  "verdict": "supported",
  "exploitPath": "GET /user?id=1%20OR%201=1 · unauthenticated → returns every row of `users`",
  "status": "confirmed"
}
```

| field | notes |
|---|---|
| `id` | content-derived and stable, so re-scans and `--merge` are idempotent. **Never hand-edit `findings.json`** — you break the invariant and bypass the citation gate. Add findings through `investigate --apply`. |
| `source` / `sink` | `CodeLoc` + optional `kind`: `{file, line, col?, symbol?}`. Present on taint findings. |
| `path[]` | `CodeLoc` + a required `why` naming the propagation. Reads source → hop(s) → sink. |
| `tool` | producer: `ultrasec` (engine), `ultrasec-ai` (your `investigate` discovery), else the scanner name. |
| `sources[]` | every tool that independently reported it. Length > 1 is corroboration, a prior for verify — not a verdict. |
| `cve`, `aliases[]`, `pkg`, `version`, `locations[]` | dependency identity. `locations[]` holds each `{file, line?, version}` instance when one advisory was merged across versions/lockfiles. |
| `epss`, `kev`, `kevDateAdded`, `risk` | deterministic post-scan enrichment. `risk` 0–100 (severity ⊕ EPSS ⊕ KEV ⊕ reachability) orders findings WITHIN a decision tier. Absent under `--offline`, and then derived from severity alone — a finding with no score is never sorted below one that has one. |
| `reachability` | `runtime` \| `toolchain` \| `unproven` — whether anything puts this on a path that runs. Damps `risk` and floors the displayed severity. `unproven` is the orphan-sink case (a dangerous callee with no source path: 182 of them on one real audit, **zero** confirmed); `toolchain` is a build-only dependency. Evidence, not a verdict — find the path the engine missed and it is confirmable. Absent means the run established nothing, and nothing is damped. |
| `verified` | secret findings only: a scanner actively confirmed the credential is live. Treat a `true` as an incident, not a finding. |
| `provenance` | `{author?, commit?, date?, owner?}` from `--blame`. Evidence only — never a suppression rule. |
| `fixedIn` | commit recorded by `revalidate --apply` on a `fixed` verdict. |
| `brocard` | the named ground for a `refuted` verdict (see the list below). Optional and never blocking, but it is the ONLY field `check --semantic` reads as a ground — a refutation argued in `note` still reports as unargued. |
| `noise` | the noise-by-construction class the finding was DEMOTED under (never dismissed). Engine-set, re-derived every scan. See below. |
| `flow` | `{assigned?, tainted?}` — for an assignment sink the value assigned, plus the bindings the def-use walk followed. Evidence for the **Reachability evidence** block; the engine never acts on it. Note the walk is PER FILE, so on a cross-file path the assigned value is a parameter and "no tracked binding" is expected, not suspicious. |
| `atCommit` | set when the finding came from a scan of git HISTORY: the commit its `file:line` belongs to. `check` resolves the citation against THAT tree, so a secret in a file since deleted is still graded — and a fabricated path still fails. |
| `priorAnalysis` | `{tool, reasoning?, mitigationsChecked?, revalidationVerdict?}` ingested from an upstream agent. A **signal**, never a status. |

## `manifest.json` — run metadata (read this every run)

Written by `scan`/`import`/`logs`. Three fields answer "did this audit run at full strength?"

```json
{
  "version": "1.17.0",
  "schemaVersion": 8,
  "repo": "/path/to/repo",
  "languages": ["javascript"],
  "toolsRun": ["trivy", "gitleaks"],
  "toolStatus": [{ "name": "semgrep", "status": "skipped", "note": "not installed" }],
  "counts": { "findings": 8, "bySeverity": { "critical": 1, "high": 4, "medium": 3, "low": 0, "info": 0 } },
  "truncation": { "candidates": 0, "total": 8, "files": false },
  "scopes": ["src/api"],
  "extraction": { "tier": "cache", "ast": true },
  "passes": { "sinks": false, "logHygiene": true, "blame": false },
  "downgraded": [{ "reason": "encrypted-at-rest", "count": 41 }],
  "sbom": "sbom.cdx.json"
}
```

- **`extraction.ast: false`** ⇒ tree-sitter was unavailable and the regex extractors ran. On a
  69-file TypeScript repo that measured **27 taint candidates instead of 66, with every critical
  cross-file command-injection candidate missing**. A regex-tier run is a thinner audit and must
  be reported as one.
- **`truncation.candidates > 0`** or **`truncation.files: true`** ⇒ a cap was hit. Raise
  `--max-candidates` / narrow `--scope`, or say so in the report.
- **`toolStatus`** distinguishes `ran` (0 findings is a result) from `skipped` (not installed —
  a coverage hole) from `failed`.
- **`scopes[]`** accumulates every scope/diff that fed a merged run — this is what makes a
  map-first audit resumable across sessions.
- **`downgraded`** counts findings de-prioritized as noise BY CONSTRUCTION, one row per class
  (`{reason, count}`). The classes, and the ground each one proposes:

  | class | what it claims | ground |
  |---|---|---|
  | `encrypted-at-rest` | ciphertext in a file that is ciphertext by design (SealedSecret, SOPS, Ansible Vault, age, git-crypt) | `standard-behavior` |
  | `test-only-path` | EVERY node of the path is a test path, so the flow is not in the shipped artifact | `outside-usage` |
  | `vendored-artifact` | a vendored or minified upstream build artifact, not this repo's source | `no-threat-model` |
  | `pattern-declaration` | the cited line DECLARES the pattern — rule metadata, a bare regex, a comment — rather than performing it | `no-threat-model` |
  | `resource-identifier` | the value addresses a document (a spreadsheet/folder/project id), it is not a way in | `no-threat-model` |

  Demotion is **not adjudication**: it sets severity and confidence, never `status`, `verdict` or
  `brocard`. What it does is state the severity honestly, which is what makes the finding eligible
  for `triage` — the cheap lane that clears low/medium/info in one pass. Each class carries a
  caveat naming what to check before believing it (an encrypted file whose KEY is also committed
  is a real leak; a rule file that also configures the running system is both).

  The worklists carry `proposed: {class, ground, why}` on such an item and a `## Proposed noise
  classes` block naming each class once with its members — reading, never verdicts. `verdict` stays
  `null`: a pre-filled one would make copying the worklist to the apply file a passing adjudication.

  The
  engine's rule is that nothing disappears quietly: a secret finding inside a file that is
  ciphertext by design (SealedSecret, SOPS, Ansible Vault, age, git-crypt) is pushed to `info`
  rather than dropped, and the run still says how many and why. On a real k8s repo that is the
  dominant secret-finding class, and not one of them can be a leak. What IS worth checking on such
  a repo is whether the decryption key is committed too.
- **`passes`** records which opt-in passes ran (`--sinks`, `--log-hygiene`, `--blame`). Counts
  alone cannot say it: a run with `--log-hygiene` that found nothing and a run without the flag
  both report zero logging findings. `coverage` reads it so it never advises you to enable an
  option you already enabled. Absent on dossiers written before schema 8 — `undefined` means
  **unknown**, never "off".

## `TRIAGE.todo.json` → `TRIAGE.json`

`triage --run <dir>` emits one line per OPEN candidate — cited location, **no code excerpt**
(triage is a glance). You fill `verdict`; `triage --apply` folds it.

```json
[ { "id": "409b0c792964", "severity": "medium", "category": "taint",
    "title": "Cross-site scripting (reflected): untrusted input reaches send()",
    "at": "src/routes.js:26", "verdict": null } ]
```

You write (only `id` + `verdict` are read):

```json
[ { "id": "409b0c792964", "verdict": "keep" },
  { "id": "8104ef108b3e", "verdict": "noise" } ]
```

The Markdown brief groups repeated candidates under one heading with a `×N` count — 1342 rows
collapse to a few dozen groups on a large repo. **The grouping is for reading, never for deciding**:
`TRIAGE.todo.json` still carries one row per finding and your `TRIAGE.json` must still name every
id you mean. A group is not a verdict.

## `GUARDS.todo.json` → `GUARDS.json`

`guards --run <dir>` crosses every handler that reads request data against the auth/authorization
markers visible in its scope — the vulnerability that is an **absence**, which no taint path can
reach. One row per handler, not per request read.

```json
[ { "id": "2767aa999f18", "file": "src/pages/api/storage/index.ts", "line": 7,
    "handler": "endPoint", "kinds": ["http"], "reads": 5,
    "guards": [], "scope": "approx", "state": "unguarded", "verdict": null } ]
```

`scope` says how far the guard search reached, weakest last: `symbol` (the extractor gave an end
line), `approx` (bounded by the next symbol — the common case), `file` (nothing to bound against).

You write:

```json
[ { "id": "2767aa999f18", "verdict": "unguarded",
    "note": "No getServerSession, no middleware; POST writes to S3 with ACL public-read." } ]
```

`guarded` · `unguarded` · `intentionally-public` (a health check, a login route, a webhook with its
own signature check). An `unguarded` verdict becomes a cited `authz` finding through the same
citation gate as any discovery. **A marker in scope is a candidate, not a proof** — it may guard a
different branch, run after the object is read, or check authentication where the route needs
authorization; and a route protected by framework middleware this pass cannot see will show as
`unguarded` when it is fine.

## `VERIFY.todo.json` → `verdicts.json`

`verify --run <dir>` emits every finding still `open` **or `needs-human`** (a re-verify picks up
what an earlier pass escalated). `--shards n --shard i` writes `VERIFY.todo.<i>.json` instead;
the `.md` brief always describes the full worklist.

```json
[ { "id": "7e51071c4783", "severity": "high", "cwe": "CWE-89", "category": "taint",
    "title": "SQL injection: untrusted input reaches query()",
    "claim": "What must hold for this to be a real, exploitable issue…",
    "files": ["src/routes.js:12", "src/service.js:6", "src/db.js:7"],
    "verdict": null, "note": "", "priorSignal": "deepsec: true-positive (signal, not a verdict)" } ]
```

You write an array of `{id, verdict, note?, exploitPath?, brocard?}`. The emitted
`VERIFY.todo.json` carries `verdict: null`, `note: ""` **and `brocard: null`**, so every field you
are expected to fill is visible in the file you are filling:

```json
[ { "id": "7e51071c4783", "verdict": "supported",
    "note": "req.query.id concatenated at service.js:5, reaches conn.query() unparameterized.",
    "exploitPath": "GET /user?id=1%20OR%201=1 · unauthenticated → returns every row of `users`" },
  { "id": "8104ef108b3e", "verdict": "refuted", "brocard": "outside-usage",
    "note": "FP-9: scratch/ is gitignored developer debris, in no shipped artifact." } ]
```

`brocard` names the **ground** for a refutation — one of `no-threat-model` ·
`exploit-from-the-heavens` · `outside-usage` · `standard-behavior` · `documented-behavior` ·
`cure-worse-than-disease` · `report-not-dispositive`. It is ignored on any other verdict, and an
unrecognized name is dropped rather than failing the fold (a typo must not cost the batch).

`brocard` is the only field read as a ground. A refutation argued at length in `note` still
reports as unargued — on the first real-world audit that was 96 dismissals, 0 brocards, because
the worklist offered a `note` field and no `brocard` field at all. Both are now emitted.

Where the engine recognised a noise class it also emits `proposed: {class, ground, why}` on the
item — a suggestion to accept or refuse, never a filled-in verdict. A pre-filled `verdict` would
make copying the worklist to the apply file a passing adjudication.

It is optional and never blocks: `check --semantic` simply **lists** the high/critical dismissals
that name no ground, so a reviewer can see which refutations were argued. Making it a hard gate
would only teach adjudicators to pick a ground to get green — and the rule above it (never
auto-dismiss what you merely cannot confirm) already carries the weight.
[dismissal-brocards.md](dismissal-brocards.md) says when each one applies, and — more usefully —
when it does not.

`verify --apply` takes a file, a comma-list, or a **directory** — from a directory it picks up
every `*verdict*.json`, sorted, so fan-out fragments reassemble deterministically. Name your
fragments accordingly (`verdicts-1.json`, `verdicts-analyzer-a.json`). If every fragment is
stale (no id matches the dossier) it **exits 2** rather than silently folding nothing.

## `INVESTIGATE.todo.json` → `INVESTIGATE.json`

`investigate --run <dir>` groups the attack surface into regions:

```json
[ { "region": "src", "score": 41, "sinks": 5, "sources": 4,
    "files": ["src/routes.js", "src/db.js"],
    "neighbors": ["src/service.js", "src/fetcher.js"],
    "prompt": "What to hunt for here — the things the deterministic pass can't." } ]
```

You write a `Discovery[]` — this is how a bug the engine cannot enumerate (authz, business
logic, multi-hop) becomes a first-class candidate:

```json
[ { "title": "IDOR: any authenticated user can read another user's invoice",
    "category": "authz", "severity": "high", "cwe": "CWE-639",
    "message": "GET /invoice/:id loads by id with no ownership check; session user is never compared to invoice.ownerId.",
    "file": "src/invoice.js", "line": 42,
    "path": [ { "file": "src/routes.js", "line": 88, "why": "route: requireAuth only, no ownership guard" },
              { "file": "src/invoice.js", "line": 42, "why": "findById(req.params.id) returns any user's row" } ] } ]
```

Ingest rules: each becomes an `ultrasec-ai` finding, `status: open`, `confidence: low`, and is
adjudicated like any candidate. **Citations are checked first** — an unresolvable `file:line`
(primary or any path step) is rejected and reported, so `check` can never fail on an invented
line. A discovery at an existing finding's location folds into that finding's `sources` instead
of duplicating it.

## `REVALIDATE.todo.json` → `REVALIDATE.json`

`revalidate --run <dir>` emits git facts for every `confirmed`/`needs-human` finding. Run it
**after** `verify --apply` — before that, nothing is promoted and the worklist is empty.

```json
[ { "id": "7e51071c4783", "severity": "high", "title": "SQL injection: …",
    "at": "src/db.js:7", "fileExists": true,
    "currentLine": "  return conn.query(sql);",
    "commitsSinceFinding": 3,
    "lineLastChanged": { "commit": "a1b2c3d", "author": "dev", "date": "2026-05-02" },
    "renamedTo": null, "verdict": null, "note": "" } ]
```

You write `{id, verdict, fixedIn?, note?}`:

```json
[ { "id": "7e51071c4783", "verdict": "fixed", "fixedIn": "9f8e7d6",
    "note": "conn.query(sql) replaced by conn.query(text, params) in 9f8e7d6; the concatenation at service.js:5 is gone." } ]
```

`commitsSinceFinding` is `null` unless the dossier carries `--blame` provenance. Same
directory/comma-list apply, same fail-closed-on-all-stale behaviour as `verify`.

## `NARRATIVE.todo.json` → `NARRATIVE.json`

`narrative --run <dir>` emits the reportable findings plus a scaffold. You author the prose;
`render --narrative` and `implement` fold it in.

```json
{
  "executiveSummary": "Two confirmed injection flaws in a public API: untrusted query values reach a raw SQL statement and a shell command across files, both exploitable unauthenticated.",
  "positivePatterns": "Session handling is solid — tokens are rotated on privilege change and cookies carry HttpOnly/Secure/SameSite=Lax. Every write path outside these two goes through the parameterizing query builder.",
  "remediations": [
    { "id": "7e51071c4783", "fix": "Bind the id: conn.query('SELECT * FROM users WHERE id = ?', [id]).",
      "patch": "- const sql = \"SELECT * FROM users WHERE id = \" + id;\n+ return runQuery(\"SELECT * FROM users WHERE id = ?\", [id]);",
      "owner": "@platform" }
  ],
  "attackChains": [
    { "title": "Unauthenticated read of any user record", "findingIds": ["7e51071c4783"],
      "narrative": "No auth on /user, so the SQLi is reachable pre-authentication; the same DB user has read access to every table." }
  ],
  "rootCauses": [
    { "cause": "String-built queries and commands in the data layer", "findingIds": ["7e51071c4783", "22fb96504e71"],
      "note": "Both flow from handlers that pass raw request values into a helper that concatenates." }
  ],
  "hardeningNotes": [
    "Add a CSP to the report route — defense in depth; the current JSON content type already blocks the reflected-XSS variants."
  ]
}
```

Grounding: sections that cite finding ids (`remediations`, `attackChains`, `rootCauses`) are
checked and **dropped** if the id is unknown or not `confirmed`. The advisory prose
(`executiveSummary`, `positivePatterns`, `hardeningNotes`) cites no ids and is kept as written.
Nothing here ever changes a finding's status or severity.

> **Check each remediation against its CWE before you submit it.** The gate verifies the *id* is
> confirmed, not that the *fix matches the vulnerability* — a fix pasted onto the wrong finding
> passes every check and ships.

## `IMPLEMENT.todo.json` (emit-only)

`implement --run <dir>` — confirmed → `fixes`, needs-human → `investigations`. No `--apply`;
it never changes a status.

```json
{ "fixes": [ { "id": "7e51071c4783", "title": "SQL injection: …", "severity": "high",
               "category": "taint", "cwe": "CWE-89", "at": "src/db.js:7",
               "status": "confirmed", "kind": "fix",
               "fix": "Bind the id …", "patch": "…", "owner": "@platform" } ],
  "investigations": [], "rootCauses": [], "dismissed": 2 }
```

## `CONTEXT.scaffold.json` → `CONTEXT.md`

`context --repo <dir>` emits the scaffold; **you** author `CONTEXT.md` as prose (there is no
`--apply` — it is additive evidence, injected into every later dossier and worklist, and it
never gates a verdict).

```json
{ "frameworks": ["express"],
  "entryPoints": [{ "file": "src/routes.js", "line": 11, "kind": "http" }],
  "authMiddleware": [{ "file": "src/auth.js", "line": 8, "hint": "requireAuth" }],
  "sanitizers": [{ "file": "src/db.js", "line": 11, "kind": "sql-parameterized" }],
  "trustBoundaries": ["public HTTP → src/routes.js", "routes → data layer (src/db.js)"] }
```

## `attack-surface.json` (from `map`) and `LOGSTATS.json` (from `logs`)

`map --out <run>` writes `MAP.md` + `attack-surface.json`: `totals`, `entryPoints[]` grouped by
kind, `sinks[]` by CWE class, `byLanguage[]`, `byTopDir[]`, and `suggestedTargets[]` —
`{scope, sinks, sources, score, covered, reason}` ranked by severity-weighted sink density, with
`covered: true` on scopes a prior pass already scanned (read from `manifest.scopes`). Without
`--out`, `MAP.md` goes to stdout and nothing is written.

`logs` writes `LOGSTATS.json` alongside its dossier: per-file `{path, lines, format}`, `topIps`,
`topPaths`, `statusCounts`, `firstTs`/`lastTs`, `totalLines`, `authFailures`,
`authSuccessAfterFailure`, `distinctIpsSeen` and `distinctIpsOverflowed` (true ⇒
`distinctIpsSeen` is a floor, not a count). Top paths are redacted like finding evidence.

---

Related: [citation-format.md](citation-format.md) (the grounding contract in prose) ·
[commands.md](commands.md) (which command writes which file) ·
[adjudication.md](adjudication.md) (how to decide what goes in a verdict).

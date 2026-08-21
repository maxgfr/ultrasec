# Investigate playbook (agentic discovery)

The deterministic engine enumerates source→sink taint candidates, but it can't
reason about **authorization / IDOR, business logic, or subtle multi-hop flows**.
`investigate` closes that gap: the engine emits a worklist organized by
attack-surface **region** (the entry/sink files in a top-level dir plus their 1-hop
graph neighbours), you do the security reasoning, and the engine **ingests** your
grounded discoveries as first-class candidates that flow through `verify`/`check`
like everything else.

## 1. Emit the region worklist

```
ultrasec investigate --run .ultrasec
```

Writes `INVESTIGATE.todo.json` + `INVESTIGATE.md`. Each region lists its files,
graph neighbours, and a hunt prompt. Work the highest-attack-surface regions first.

A **region** is a workspace package when the repo is a workspace (npm/pnpm/lerna/nx/cargo/go/
maven/uv/composer/gradle are all detected), and a top-level directory otherwise — so a monorepo's
web app, CLI and batch pipelines get their own regions instead of sharing one. Region files are
chosen by ranked attack surface (severity-weighted sinks ⊕ entry points), not alphabetically, and
entry points carry weight in the rank: a package full of internet-reachable routes and no local
sink is a region worth opening, not one worth sorting last.

## 2. Hunt and emit grounded Discovery[]

Regions are ranked by attack-surface score, but **override that with judgment**: an
auth/payments module with three sinks outranks a logging directory with thirty. Weight toward
crown-jewel data, internet-exposed entry points, recent churn, and code with no CODEOWNER.

For each region, read the real code and look for what the engine can't. The mechanism-level
method per class — what to grep, how to prove it, how to rate it, what turns out to be nothing —
is [attack-classes.md](attack-classes.md); the lenses to apply before you know the class are in
[hunting-heuristics.md](hunting-heuristics.md); stack-specific hiding places are in
[frameworks.md](frameworks.md). The headline classes:

- **Broken access control / IDOR** — an endpoint that reads/writes another user's
  object with no ownership check; a parallel path that checks a weaker permission; a
  request-body field that overrides the intended restriction (mass assignment).
- **Missing authorization** — a privileged route with no auth guard.
- **Business-logic flaws** — price/quantity tampering, race conditions, replay,
  state-machine skips, rollback abuse.
- **Feature abuse & data leakage** — export-as-exfiltration, import-as-injection,
  search-as-oracle, enumeration via side effects, webhook-as-SSRF.
- **Multi-hop taint** the BFS missed (e.g. through a callback, a queue, or config).

Emit `INVESTIGATE.json` — an array of:

```json
{ "title": "...", "category": "authz", "severity": "high", "cwe": "CWE-862",
  "message": "what the exploit is", "file": "src/x.js", "line": 42,
  "path": [{ "file": "src/r.js", "line": 3, "why": "route, no auth" },
           { "file": "src/x.js", "line": 42, "why": "reads any user's record" }] }
```

`category` is one of `taint`/`sast`/`dep`/`secret`/`config`/`authz`/`crypto`/`logs`/`other`;
`severity` critical…info. Cite **resolvable `[file:line]`** for the primary location and every
path step. Full field reference: [schemas.md](schemas.md).

Choosing a `category` when it isn't obvious: anything about *who may* (IDOR, missing authz, mass
assignment, privilege escalation) is `authz`; key/hash/randomness/comparison misuse is `crypto`;
business logic, race conditions and feature abuse are `other`; a multi-hop data flow you traced
by hand is `taint`. The category groups the report — it never affects the gate, so don't
agonize.

## 3. Apply (ingest)

```
ultrasec investigate --apply INVESTIGATE.json --run .ultrasec
```

- Each discovery becomes an `ultrasec-ai` finding, `status: open`, `confidence: low`
  — recall-oriented; adjudicate it with `verify` like any candidate.
- **Citations are checked first.** An out-of-range or nonexistent `[file:line]`
  (primary or any path step) is **rejected** and reported — so `check` can never
  later fail on an AI-invented line. Don't guess line numbers: get them from `dossier`/`graph`,
  or with `rg -n '<pattern>' <file>`. Because bad citations bounce, over-reporting is cheap and
  under-reporting is not.
- A discovery at the **same `file:line` (and category+cwe|title)** as an existing
  finding folds into that finding's `sources` (no duplicate) — your independent hit
  corroborates it.

Then continue the normal loop: `dossier <id>` → `verify` → `check` → `render`.

## Citation discipline

`ultrasec-ai` findings are held to the **same grounding bar** as everything else
(see [citation-format.md](citation-format.md)). The whole point of ingesting them
through the engine is that ultrasec's conservative gate, not the model's
confidence, decides what ships.

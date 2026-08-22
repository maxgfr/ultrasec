# Command reference

Every command, its flags, what it writes, and how it exits. `--help` is the short form; this is
the full one. All paths below are relative to `--run`/`--out`.

**Exit codes are uniform:** `0` ok · `1` a gate failed (`check`) or nothing usable was ingested
(`import`) · `2` usage or runtime error (bad flag value, unreadable run, unresolvable git ref,
a `--repo` that isn't a directory).

Run the engine by its absolute path — see the `<skill-dir>` note in
[SKILL.md](../SKILL.md); the examples here write `ultrasec` for brevity.

**Global flags**, accepted by every command:

| flag | effect |
|---|---|
| `--json` | machine-readable output (all but `render`/`dossier`) |
| `--report <path>` | ALSO write this command's output to `<path>`. The extension picks the format — `.md`, `.html` (self-contained, no external assets), `.json` (the structured transcript), `.txt`/`.log`. **stdout is unchanged**; the archive is additive. An unsupported extension exits **2 before the command runs**, so a ten-minute scan never ends in an unwritable report. |
| `--no-journal` | skip the `JOURNAL.md` entry (see below). |

**`<run>/JOURNAL.md`** — every command that names a run directory (`--run`, or `--out` for
`scan`) appends one timestamped entry to it: the command line, its headline result, any refused
`--apply` rows, and the exit code. Append-only, created on first use, and kept by `clean`
alongside the other deliverables. It answers "what did this audit actually cover?" an hour later,
when the scrollback is gone. Best-effort: a journal write never fails a command.

The read-only commands — `dossier`, `graph`, `paths`, `check`, `tools` — never journal, so
`check` keeps writing nothing and a fan-out subagent running `dossier` stays a non-writer.
`--report` still works for them; it writes where you pointed, not into the run.

## Recon

### `map --repo <dir>`
Cheap attack-surface recon: entry points by kind, sinks by CWE class, per-directory density,
and a ranked `suggestedTargets` list. **No taint BFS, no tools, no network** — O(files), so it
stays fast on a repo too big to scan whole.

`--repo` (default `.`) · `--out` · `--scope` · `--include` · `--exclude` · `--max-files` ·
`--gitignore` · `--json`

Writes `MAP.md` + `attack-surface.json` **only when `--out` is given**; otherwise `MAP.md` goes
to stdout and nothing is persisted. With `--out` pointing at an existing run, targets already
covered by `manifest.scopes` are marked. Exit 0, or 2 if `--repo` isn't a directory.

### `context --repo <dir>`
The project-context primer, and the highest-leverage first step. Emits a deterministic scaffold;
**you** author `<run>/CONTEXT.md`, which is injected into every later dossier and every stage
worklist. Additive evidence only — it never gates a verdict, and there is no `--apply`.

`--repo` (default `.`) · `--out` (default `.ultrasec`) · `--scope` · `--include` · `--exclude` ·
`--max-files` · `--gitignore` · `--json`

Writes `CONTEXT.scaffold.json` + `CONTEXT.todo.md`. See
[context-playbook.md](context-playbook.md).

## Scan

### `scan --repo <dir>`
The mechanical pass: walk → link-graph → cross-file taint candidates → external scanners →
cross-tool correlation → EPSS/KEV/CVSS risk ranking → dossier.

**Output** `--out` (default `.ultrasec`) · `--json` · `--quiet`
**Tools** `--tools auto|none|<a,b>` (default `auto`) · `--no-tools` (= `--tools none`) ·
`--docker` · `--offline` / `--no-enrich`
**Focus** `--scope` · `--include` · `--exclude` · `--max-files` · `--gitignore` · `--include-vendored`
**Budget** `--budget quick|standard|thorough` · `--max-depth` · `--max-candidates`
**Incremental** `--diff <ref>` / `--since <commit>` · `--merge` · `--resume`
**Recall & provenance** `--sinks` · `--log-hygiene` · `--blame` (alias `--provenance`) ·
`--no-env-sources` · `--strict-scope` · `--include-tests`

`--sinks` enumerates **call** sinks and **assignment** sinks alike. The assignment family
(`dangerouslySetInnerHTML`, `innerHTML =`, `v-html`, `[innerHTML]`, `.src =`) used to surface only
when the taint pass could link a source, which is exactly the case a recall pass is for: on one
real audit, seven `dangerouslySetInnerHTML` were matched by the catalog and **zero** were reported.
Editorial HTML loaded from a database has no source the graph can see.

**A test file is not an entry point.** Its sources are ignored unless `--include-tests`, because
nobody sends a request to `__tests__/service.test.ts`. On one audit that harness accounted for
**46 of 63** taint candidates (73 %), none confirmed, including 37 SQL-injection candidates in a
repo with no SQL database. A test file is still a valid sink and a valid hop — the flag is about
whether the harness is something an attacker can *speak to*.

**Progress goes to stderr, and is on by default.** A line per stage, and per external scanner
started and finished, with its result and elapsed time. Adapters run serially and one of them can
spend twenty minutes walking git history, so without it a thorough scan is indistinguishable from
a hang. It never touches stdout — `--json` output and every line the command prints at the end are
byte-identical with or without it — and `--quiet` mutes it. If a scan seems stuck, the last line
printed names the tool that is blocking.

`--no-env-sources` drops candidates whose SOURCE is an environment read (`process.env`,
`os.getenv`). Those model configuration injection, which is real, but presume the operator of the
deployment is an attacker — on a repo whose trust model says otherwise they can dominate the
dossier. Opt-in: without it, enumeration is unchanged, and the source kind is on the finding
either way (`env input at …` in the dossier), so batch-refuting them stays equally available.

`--strict-scope` drops candidates whose source sits in a **different function of the same file**
(`sourceScope: "file"`). The BFS closes a path on any source at-or-above the frame's entry line in
that file, which is positional, not structural: on a router with twenty handlers, a `req.query` in
one and an `exec()` in another pair up although nothing connects them. Opt-in for the same reason
as above — a value *can* travel between two functions through module state — and every candidate
carries its `sourceScope` regardless, so you can triage the tail without re-scanning.

### The two intra-procedural signals on a taint candidate

Both sharpen a candidate without filtering it. **Reachability is not taint**: keep the vocabularies
apart when you write the finding.

| field | values | means |
|---|---|---|
| `sourceScope` | `symbol` | source and sink share one function — the flow a human would draw |
| | `module` | source is at file scope (middleware, top-level registration); legitimate |
| | `file` | source is in a *different* function of the same file — co-location only |
| `dataflow` | `linked` | a def-use walk still sees the source's bound value at the sink |
| | `unlinked` | it looked and the binding is never mentioned again |
| | *absent* | undecidable (used inline, threaded through an object or a template) — **not** "no" |

Ranking is severity → scope → `unlinked` last → proximity → cross-file. A `file`-scoped or
`unlinked` candidate is worth less of your attention, not zero: read the dossier before dropping it.

Writes `manifest.json`, `findings.json`, `graph.json`, `DOSSIER.md`; plus `sbom.cdx.json` when
`syft` is installed, and `cache/scan-cache.json` under `--resume`.

| budget | max depth | max candidates |
|---|---|---|
| `quick` | 3 | 200 |
| `standard` *(default)* | 6 | 1000 |
| `thorough` | 8 | 5000 |

Other fixed limits worth knowing: `--log-hygiene` caps at **40** findings per run (it inherits
an explicit `--max-candidates`, never the budget preset — logging call sites flood fast);
`--diff` expands changed files to their reverse-dependents **2 hops** deep, not configurable;
files above **1.5 MB** are skipped; `.git`, `node_modules`, `vendor`, `dist`, `build`, `target`,
`.next`, `coverage`, `.venv`, `__pycache__`, `.terraform` and ~20 more are always ignored;
`<repo>/.ultrasec` is always excluded so a scan never indexes its own dossier.

That ignore set now applies to **external scanner output too**, with or without `--gitignore`.
The walk had always skipped those trees while semgrep, bandit and gitleaks reported freely from
them: on one real monorepo that was 561 of 1366 findings (41 %), 559 of them refuted, and bandit
produced 519 findings of which 518 sat inside `.venv/` or `node_modules/`. `--gitignore` could not
have helped — `.next/` was not in that repo's `.gitignore`. Pass **`--include-vendored`** when you
genuinely mean to audit a vendored blob; the count of pruned results is always reported.

Candidates are **rank-then-cap**, and any cap lands in `manifest.truncation` — truncation is
never silent. External scanners are skipped by default in scoped/diff mode; pass `--tools auto`
to force them. `--offline` disables the EPSS/KEV fetch **and** every network-dependent adapter.
Exit 0, or 2 on a bad `--budget`, an unresolvable `--diff` ref, or a `--repo` that isn't a
directory.

### `import <findings.json> --run <dir>`
Ingest an upstream AI scanner's export (vercel-labs/**deepsec** today) into the dossier: map →
correlate → risk-rank → fold in, preserving prior verdicts. ultrasec never runs deepsec; this is
pure data ingest, and every imported finding lands `open` for you to adjudicate under the same
grounding gate.

`<findings.json>` (or `--file`) · `--run` (default `.ultrasec`) · `--repo` · `--format
deepsec-json` · `--offline` / `--no-enrich` · `--blame` · `--json`

Exit 0; **1** when nothing parses; 2 on a missing/unreadable file or an unknown `--format`.

### `logs <path…>`
Blue-team log forensics — a separate, read-only pipeline over existing log files, into its **own**
dossier. Never touches the code-scan pipeline. See
[log-forensics-playbook.md](log-forensics-playbook.md).

`<path…>` · `--out` (default `.ultrasec-logs`) · `--format
nginx-combined|common|json-lines|syslog|generic|raw|auto` · `--budget quick|standard|thorough` ·
`--max-lines` · `--window <sec>` (default 60) · `--no-redact` · `--json`

Writes a standard dossier (`graph.json` is intentionally empty) plus `LOGSTATS.json`. Budgets cap
total lines for the **whole run**, not per file: `quick` 200k · `standard` 2M · `thorough` 10M.
Each detector family caps at 50 findings per run (25 per file for secrets/PII) — fixed, and
truncation-reported. Directory arguments expand **non-recursively** to the `.log`/`.jsonl`/`.txt`
and extension-less text files directly inside them. Exit 2 on no inputs, an unreadable path, no
log-looking files, no common ancestor, or a bad `--format`/`--budget`/`--window`.

## Read

### `tools`
The external-scanner catalog: what's installed, what it covers, how to get the rest. Nothing is
required; ultrasec runs what's present.

`--upgrade` (drive each installed native tool's own package manager to latest — never `sudo`) ·
`--dry-run` (print the commands, run nothing) · `--json`. Always exits 0; per-tool upgrade
failures are printed, not fatal.

### `graph <file|symbol>`
The cross-file links into and out of a node. `--depth n` (default 1) · `--run` (read
`<run>/graph.json`) · `--repo` (live re-scan when no `--run`) · `--json`. Exit 2 on a missing
target, an ambiguous symbol, or an unknown node.

### `paths`
List the candidate source→sink **chains**. `--run` (default `.ultrasec`) · `--kind <k>` ·
`--severity <s>` · `--json`.

It lists chains and only chains, so an **orphan sink** — a dangerous callee the walk could not
connect to a source — never appears here. `--kind X` printing nothing therefore does not mean
there is no X, and some classes live almost entirely as orphans: the real CWE-407 finding this
catalog was built from is one `fuzz.extract` sink with no proven path to it. When a kind has
findings it could not list, `paths` now says how many rather than leaving the silence to be read
as absence — then go to `DOSSIER.md` or `findings.json`.

### `dossier <finding-id>`
The grounding packet for one finding: the real code at every hop, graph neighbours, and the four
verification questions. **The id may be a unique prefix** (`dossier 7e51071c`). `--run` ·
`--repo` (defaults to the manifest's repo). No `--json`. Read this before adjudicating anything.

## Adjudicate

Each of these emits a worklist, you fill it, `--apply` folds it back under a conservative rule.
The verdict→status table and every JSON shape live in [schemas.md](schemas.md).

| command | emits | you write | apply rule |
|---|---|---|---|
| `triage --run <d>` | `TRIAGE.todo.json` + `.md` | `noise\|keep` | `noise` clears only low/med/info; on high/critical it is **ignored** |
| `guards --run <d>` | `GUARDS.todo.json` + `.md` | `guarded\|unguarded\|intentionally-public` | `unguarded` becomes a cited `authz` finding (CWE-306); the matrix is re-derived from the code, so a stale row is refused |
| `guards --lens throttle --run <d>` | `THROTTLE.todo.json` + `.md` | `throttled\|unthrottled\|not-abusable` | `unthrottled` becomes a cited `other` finding — **CWE-307 + CWE-204** on an auth-shaped handler, CWE-770 otherwise |
| `verify --run <d>` | `VERIFY.todo.json` + `.md` | `supported\|partial\|unsupported\|refuted` | `partial` → needs-human at any severity; `unsupported` → needs-human on high/critical |
| `investigate --run <d>` | `INVESTIGATE.todo.json` + `.md` | `Discovery[]` | citations checked **before** ingest; a bad one is rejected, not folded |
| `revalidate --run <d>` | `REVALIDATE.todo.json` + `.md` | `still-valid\|fixed\|false-positive\|uncertain` | `fixed` → dismissed + `fixedIn`; high/critical `false-positive` → needs-human |

Shared `--apply` behaviour: the argument may be **a file, a comma-separated list, or a
directory**. From a directory each stage picks up its own pattern, sorted for determinism —
`*verdict*.json` (verify), `*triage*.json`, `*guard*.json`, `*throttle*.json`, `*revalidat*.json`, `*investigat*`/`*discover*.json`.
A directory with no match, or a fragment set where **no id matches the dossier**, exits 2 rather
than folding nothing and reporting success. `--apply -` reads the payload from **stdin**, so a
generated set of verdicts can be piped straight in.

**Refused rows are always reported.** A row whose schema is wrong — an unknown `verdict`, a
`category` outside the vocabulary, a missing `id` — is listed as `✗ dropped row N: <field> <value>
is not one of …`, counted in the summary line, and included in `--json` as `dropped[]`. The valid
rows still fold, because refusing a whole batch would waste the adjudication; `--strict` exits 1
when anything was refused, so CI can decline a partial fold. A file where **nothing** is usable
still exits 2, listing every rejection at once.

`verify` additionally takes `--shards n --shard i`, which writes `VERIFY.todo.<i>.json` (the
`.md` brief always covers the full worklist). Never let a subagent run `verify --shards` — each
shard invocation **writes** into the run dir, and the orchestrator must stay the only writer.
`verify` emits a **delta**: `open` findings, plus any `needs-human` one that carries no verdict
(escalated by another stage, never actually ruled on). A `needs-human` finding an earlier pass
*did* adjudicate is withheld until you pass `--all`, and comes back carrying its `priorVerdict` so
it cannot be mistaken for new work. The header names how many were withheld.

That default is a behaviour change with a body count: the worklist used to re-emit every
non-terminal finding, so a batch meant to cover 11 new discoveries arrived holding 171 rows, and
filling it in flipped 160 already-argued advisories to `supported` in a single apply. Re-visiting
an escalation is legitimate — it is why the re-emission exists — but it has to be asked for.

`--apply` lists every verdict that **changes** a finding already ruled on (`⚠ N verdict(s)
CHANGED an already-adjudicated finding`). Re-applying the same verdict is a silent no-op. Under
`--strict` a change fails the fold unless `--re-verdict` says it was intended. `investigate` accepts the focus flags (`--scope`/`--include`/
`--exclude`/`--max-files`/`--gitignore`); `investigate` and `revalidate` accept `--repo`.

## Report

### `narrative --run <dir>`
Emits `NARRATIVE.todo.json` + `NARRATIVE.md`; you author `NARRATIVE.json`. Emit-only.
See [narrative-playbook.md](narrative-playbook.md).

### `implement --run <dir>`
Emits `IMPLEMENT.md` (a remediation-PRD draft) + `IMPLEMENT.todo.json`. Confirmed → fix items,
needs-human → investigation items, grouped by root cause; folds `<run>/NARRATIVE.json` when
present, or an explicit `--narrative <file>`. **Emit-only — never changes a status, persists
nothing.** See [implement-playbook.md](implement-playbook.md).

### `render --run <dir>`
Writes `SUMMARY.md`, `REPORT.md` and a self-contained `index.html`. `--narrative <file>` folds in
the AI-authored sections, clearly marked; sections citing unknown or non-confirmed ids are
dropped. No `--json`. Without `--narrative` the output is byte-identical to a plain render.

### `check --run <dir>`
The exit gate. **Read-only — it writes nothing and changes no status.** Fails on any finding
whose cited `[file:line]` doesn't resolve (the anti-hallucination gate); `--semantic` *also*
fails when a candidate is still unadjudicated, or when **CONTEXT.md contradicts itself against the
code** (below).

`--run` (default `.ultrasec`) · `--repo` · `--semantic` ·
`--min-severity critical|high|medium|low|info` · `--json`. Exit **0** ok · **1** gate failed ·
**2** unreadable run.

**Negations in CONTEXT.md are checked against the tree.** That document is injected into every
dossier and every worklist, and a single confident sentence can close a whole family: a real
audit's CONTEXT.md said *"le dépôt ne contient aucun `dangerouslySetInnerHTML` en code de
production"*. There were eight, in production components — and the stored-XSS class went
unexamined, not because the engine missed the sinks, but because the auditor had written down that
there were none.

So `check` extracts every sentence that negates the PRESENCE of a backticked identifier, greps the
code for that identifier, and prints the sentence next to the `[file:line]`s that disagree with it.
It never parses the claim; putting the two side by side is the whole value. Always reported;
**only `--semantic` fails**, because reconciling is one edit to one sentence and prose should not
block a citation gate.

Deliberately narrow, or it would cry wolf. Only presence negations count (`aucun X`, `no X`,
`pas de X`, `never X`) — *"pas de protection CSRF sur les routes `pages/api`"* negates the
protection, not the route, and does not fire. The identifier must follow the negation immediately.
Only files a language recognises are searched, so a repo's own audit notes and README discussing a
token are not evidence that the token is there.

## Housekeeping

### `clean --run <dir>`
By default removes the intermediate artifacts and **preserves the deliverables** —
`SUMMARY.md`, `REPORT.md`, `index.html`, `findings.json`, `JOURNAL.md`. Everything else counts as an
intermediate ultrasec can regenerate, **including files you authored**: `CONTEXT.md`, `MAP.md`,
`NARRATIVE.json`, `IMPLEMENT.md`, `sbom.cdx.json`, `LOGSTATS.json`, `orchestration/`. Copy those
out first if you want them. A run that was never rendered has no deliverables, so it is removed
whole even without `--all`.

`--all` (wipe the run dir; it is no longer `check`-able afterwards) · `--keep-output` ·
`--docker` (also remove ultrasec's scanner images, the toolbox image, and the trivy cache
volume — nothing else of yours) · `--dry-run` · `--json`. Always exits 0.

## Orchestrate

### `run --repo <dir>`
Sequences the AI stages, then always `check` + `render`.

`--repo` (default `.`) · `--out` (default `.ultrasec`) · `--powered` · `--agent <name|tpl>`
(default `claude`) · `--cross-check <name|tpl>` · `--stages <a,b,c>` · `--no-scan` · the focus
flags · `--json`

The **default (no `--powered`)** scans, emits every worklist and prints the agent TODO, making
**zero external calls**. `--powered` drives your own agent CLI per worklist (the keys live in
that CLI). `--stages` selects a subset of the **seven** stage names —
`context, triage, investigate, verify, revalidate, narrative, implement` — kept in canonical
order. `check` and `render` are unconditional post-steps and are **not** valid `--stages` tokens
(`--stages check` exits 2). Exit 0; 1 when a powered stage errored; 2 on an unknown stage or
`--no-scan` without an existing dossier. See [powered-mode.md](powered-mode.md).

### `orchestrate --run <dir>`
Emits the run's multi-agent fan-out from its **current** worklists.

`--run` (**required**) · `--phase adjudicate|verify|revalidate|investigate` · `--eco` (RUNBOOK +
contracts only) · `--list` (phase readiness as JSON)

Writes into `<run>/orchestration/`: one `<phase>.workflow.mjs` per ready phase (real ids batched
**8 per agent**, absolute paths baked in), the dispatch contracts
`agents/{analyzer,skeptic,revalidator,hunter}.md`, a sequential `RUNBOOK.md` fallback, and empty
`out/{adjudicate,verify,revalidate,investigate}/` directories for subagent fragments. Emission is
deterministic and idempotent — re-run it whenever a worklist changes. `--phase <p>` before its
worklist exists exits 2 and names the command that produces it.

## Environment

| variable | effect |
|---|---|
| `ULTRASEC_CACHE_DIR` | where EPSS/KEV feeds and the package-checker script are cached (default `~/.cache/ultrasec`; feed TTL 24 h) |
| `ULTRASEC_PACKAGE_CHECKER_PINNED=1` | force the vendored, sha256-pinned package-checker instead of resolving upstream's latest |
| `CODEINDEX_NO_GRAMMARS_PULL=1` | skip the tree-sitter grammar download — the scan then runs on the **regex** extraction tier (thinner: `manifest.extraction.ast: false`) |
| `CODEINDEX_GRAMMARS_DIR` / `_URL` | point the grammar cache at a local directory or an internal mirror |

**First run on a cold machine downloads ~22 MB of tree-sitter grammars** for the commands that
walk the repo (`scan`, `run`, `graph`, `map`, `context`, `investigate`, `logs`). `--offline` does
**not** suppress it — it governs advisory feeds and scanner adapters, not the extractors. Offline
without a warm cache is still a successful run, on the regex tier, announced on stderr. Prewarm
with any `map` run, or point `CODEINDEX_GRAMMARS_DIR` at a shared cache.

Tool subprocesses are killed at **300 s**; the EPSS/KEV fetch times out at 20 s. The engine runs
adapters **serially** — parallelism comes from the agent fan-out, not from the engine.

---
name: ultrasec
description: "Use when the user wants a SECURITY AUDIT of a codebase — find real, exploitable bugs by tracing how untrusted data flows ACROSS functions and files, not file-by-file. A deterministic zero-dep engine (no keys, no install) scans the repo, builds a cross-file link-graph, enumerates source→sink paths (SQLi, command/code injection, path traversal, SSRF, XSS, SSTI, XXE, prototype pollution), runs scanners (Trivy, Semgrep, gitleaks…), correlates findings, ranks by EPSS/KEV/CVSS risk; YOU read the code along each path, judge reachability/exploitability (incl. authz/business-logic), and adversarially verify each into a cited report. Every finding cites resolvable [file:line] hops (`check` fails otherwise); an uncertain high-severity one stays needs-human, never dropped. Triggers: 'audit this repo for security', 'find vulnerabilities', 'security review of this codebase', 'is this vulnerable to SQL injection/XSS/SSRF', 'taint analysis', 'check my dependencies for CVEs', 'scan for secrets'."
license: MIT
metadata:
  version: 1.9.0
---

# ultrasec — cross-file security audit, grounded not guessed

`ultrasec` finds vulnerabilities by **reasoning over how untrusted data moves
between functions and files**, the way a human auditor does — then proves or
disproves each candidate against the real code. Like its `ultra*` siblings it is
a **division of labour**: the deterministic, zero-dependency engine
(`node scripts/ultrasec.mjs <command>` — no `npm install`, no API keys, run
`--help`) does the *mechanical* work — scanning, building the link-graph,
enumerating candidate source→sink paths, running external scanners, assembling
evidence packets; **you** do the *security reasoning* — decide which flows are
real and exploitable, find the subtle bugs the tools miss, and verify.

> **The core rules:**
> 1. **Reason from evidence, not memory.** Judge each finding from the real code
>    `dossier` shows you, and cite it `[file:line]` in the exact
>    [citation format](references/citation-format.md). `check` REJECTS any finding
>    whose cited location doesn't resolve — so don't invent line numbers.
> 2. **The engine finds *candidates*; you decide.** Enumerated taint paths are
>    deterministic and recall-oriented — many are false positives by design.
>    Confirm reachability + exploitability before calling something a bug.
> 3. **Be conservative.** Only `dismiss` a high/critical finding if you can
>    positively **refute** it. Uncertain ⇒ leave it `needs-human`. Aggressive
>    auto-suppression discards real bugs.
> 4. **Use the tools, then go beyond them.** Run the installed scanners (`tools`),
>    triage their output, and add what only cross-file/semantic reasoning can
>    find: authorization/IDOR, business-logic, multi-hop taint — hunt with the
>    attacker-mindset angles in [references/hunting-heuristics.md](references/hunting-heuristics.md).
> 5. **Only report what you can exploit.** Every finding needs a concrete attacker
>    scenario (who · what they send · what they get) — not "potentially". A
>    defense-in-depth gap another layer already prevents is a *hardening note*, not a
>    finding. Calibrate severity against a comparable baseline:
>    [references/severity-and-discipline.md](references/severity-and-discipline.md).

Most commands accept `--json` — prefer it when you branch on the result.

## The script

One committed, dependency-free bundle: `node scripts/ultrasec.mjs <command>`.

- `map --repo <dir> [--scope <glob>] [--out <run>] [--json]` — the **cheap recon
  pass**: enumerate the attack surface (entry points by kind, sinks by CWE class,
  per-dir density) with **no taint BFS, no tools, no network** — fast even on a
  billion-line repo. Emits `MAP.md`/`attack-surface.json` and a deterministic
  **suggested-target** list to drill into. Run this first on a huge repo.
- `context --repo <dir> [--out <run>] [--scope <glob>] [--json]` — the **project-context
  primer** (highest-leverage first step): emit a deterministic scaffold
  (`CONTEXT.scaffold.json`: frameworks, entry points, auth-middleware candidates,
  sanitizers, inferred trust boundaries) + a brief (`CONTEXT.todo.md`). **You** author
  `<run>/CONTEXT.md` (purpose, trust model, auth scheme, framework protections); ultrasec
  injects it into every `dossier` and the `verify`/`revalidate`/`triage`/`investigate`
  worklists. **Additive evidence only — it never gates a verdict.**
- `scan --repo <dir> [--out .ultrasec] [--tools auto|none|<list>] [--docker] [--no-enrich|--offline]`
  Scan → build the link-graph → enumerate cross-file taint candidates → run the
  installed external scanners → **correlate** their findings across tools (one
  issue, not three; `sources[]` records every producer) → **risk-rank** every
  finding by EPSS · CISA KEV · CVSS → write the **audit dossier** (`findings.json`,
  `graph.json`, `manifest.json`, `DOSSIER.md`, ordered by risk). `--tools`
  defaults to **auto** (every installed scanner); `none` for graph+taint only.
  `--no-enrich`/`--offline` skips the EPSS/KEV network fetch (ranks by severity).
  - **Focus (large repos):** `--scope <subdir|glob>` (prune the walk),
    `--include`/`--exclude <glob>`, `--max-files <n>`, `--gitignore`.
  - **Budget:** `--budget quick|standard|thorough` or `--max-candidates`/`--max-depth`
    — candidates are **rank-then-capped** (kept = the important ones), and any cap is
    reported in the dossier, **never silent**.
  - **Incremental:** `--diff <ref>`/`--since <commit>` (changed files + their
    reverse-dependents), `--merge` (fold into an existing run, preserving verdicts),
    `--resume` (content-hash scan cache). A scoped/diff pass skips external scanners
    unless you pass `--tools auto`.
  - **Recall & provenance (opt-in):** `--sinks` adds an **orphan-sink** pass — every
    dangerous sink the source-gated taint BFS can't connect to a source (single-file
    script, framework dispatch, config-fed sink) is emitted as a low-confidence
    `sast` candidate to adjudicate (capped + truncation-reported like taint).
    `--blame` attaches deterministic **provenance** (git-blame author/commit/author-date
    + CODEOWNERS owner) to each finding — a triage signal, **never** a suppression rule.
- `import <findings.json> --run <dir> [--format deepsec-json] [--no-enrich|--offline] [--blame]`
  Ingest an **upstream AI scanner's** exported findings (vercel-labs/**deepsec** today:
  `deepsec export --format json`) into the dossier — map each into the Finding model,
  **correlate** against engine/scanner findings (corroboration unions `sources[]`),
  **risk-rank**, and fold in **preserving prior verdicts**. ultrasec never runs deepsec
  (no keys, no Vercel) — pure data ingest; each imported finding lands `open` and is
  yours to adjudicate, gated by the same `[file:line]` grounding `check` as everything else.
- `tools [--json]` — the external-scanner catalog: which are installed, what they
  cover, how to install the rest. ultrasec runs what's present; none are required.
- `graph <file|symbol> [--depth n]` — the cross-file links into/out of a node.
- `paths [--kind sql] [--severity high]` — list the candidate source→sink chains.
- `dossier <finding-id>` — the **grounding packet** for one finding: the real code
  along the cross-file path + graph neighbours + how to verify. Read this to adjudicate.
- `triage --run <dir>` / `triage --apply TRIAGE.json --run <dir>` — a **cheap, code-free
  fast-lane** over OPEN candidates: emit one line per candidate, mark each `noise|keep`.
  Apply dismisses `noise` only on **low/medium/info**; on a high/critical finding a
  `noise` verdict is **ignored** (kept open for full `verify`). Use it to clear obvious
  noise before the expensive per-finding reads.
- `investigate --run <dir> [--repo <dir>]` / `investigate --apply INVESTIGATE.json` —
  **agentic discovery**: emit a worklist grouped by attack-surface region (entry/sink
  files + graph neighbours); you find what the deterministic engine can't (authz/IDOR,
  business logic, multi-hop) and emit grounded `Discovery[]`. Apply ingests them as
  `ultrasec-ai` **open** candidates — **citations are checked** (an unresolvable
  `[file:line]` is rejected) and a discovery at an existing finding's location folds
  into its `sources` (no duplicate). They then flow through `verify`/`check` like any candidate.
- `verify --run <dir> [--shards n --shard i]` — emit the adversarial worklist
  (`VERIFY.todo.json` / `VERIFY.md`); shard it to fan verification out.
- `verify --apply <verdicts.json | dir | a,b,c> --run <dir>` — fold your verdicts
  back in (`supported`→confirmed, `refuted`→dismissed, `unsupported`/`partial` on a
  high-severity ⇒ needs-human, never auto-dropped).
- `revalidate --run <dir> [--repo <dir>]` / `revalidate --apply REVALIDATE.json` — the
  **git-history false-positive cut** (deepsec's revalidate pass, ultrasec-style). For
  confirmed/needs-human findings, emit compact git facts (does the cited line still
  exist? what's there now? when did it last change? rename target?); you decide
  `still-valid|fixed|false-positive|uncertain`. Apply is conservative: `fixed`→dismissed
  + records the fixing commit (`fixedIn`); a high/critical `false-positive`→**needs-human**
  (never auto-dismissed); `uncertain`→needs-human; `still-valid` kept (flagged if the
  cited location drifted/removed).
- `check --run <dir> [--semantic] [--min-severity <s>]` — the exit gate. Fails on a
  dangling `[file:line]` (anti-hallucination); `--semantic` also fails if any
  candidate is still unadjudicated.
- `narrative --run <dir>` — emit the **report-narrative** worklist (reportable findings +
  a `Narrative` scaffold). You author `NARRATIVE.json` (executive summary, `positivePatterns`
  (what the codebase does well), per-confirmed remediations, attack chains, root-cause groups,
  and `hardeningNotes` (defense-in-depth, *not* findings)); it is folded in by
  `render --narrative`. Finding-citing sections are grounding-checked; the advisory prose
  (`executiveSummary`/`positivePatterns`/`hardeningNotes`) cites no ids and is kept as-is.
- `implement --run <dir> [--narrative NARRATIVE.json]` — emit a **remediation-PRD draft**
  (`IMPLEMENT.md`) + a structured worklist (`IMPLEMENT.todo.json`): confirmed findings → fix
  work items (each grounded in its `[file:line]` with an acceptance-criteria scaffold),
  needs-human → investigation items, grouped by root cause; folds in `NARRATIVE.json`
  (suggested fixes/patches/root causes) when present. **Emit-only — never changes a finding's
  status; persists nothing.** Feed `IMPLEMENT.md` to the local `to-prd` skill to author the
  PRD, or hand it to an implementer/AI.
- `render --run <dir> [--narrative NARRATIVE.json]` — `SUMMARY/REPORT.md` + a
  self-contained `index.html` (severity/status badges, the Mermaid taint-path, exploit
  paths). `--narrative` adds clearly-marked **AI-authored** sections (grounding-checked:
  sections citing unknown/non-confirmed ids are dropped; prose never changes status).
  **No `--narrative` ⇒ byte-identical to today.**
- `clean --run <dir> [--all] [--keep-output] [--docker] [--dry-run]` — tidy up. By
  **default** it removes only the intermediate scan artifacts and **PRESERVES the
  rendered deliverables** (`REPORT.md`/`SUMMARY.md`/`index.html` + `findings.json`) so
  a cleanup never destroys the report you just produced. `--all` wipes the whole run
  dir (after which it's no longer `check`-able — re-scan for a working run);
  `--keep-output` keeps everything; `--docker` also removes ultrasec's scanner images +
  toolbox image + trivy cache volume; `--dry-run` previews.
- `run --repo <dir> [--out <run>] [--powered] [--agent <name|tpl>] [--cross-check <name|tpl>]
  [--stages …] [--no-scan]` — **orchestrate the AI stages** (context → triage →
  investigate → verify → revalidate → narrative → implement → check → render). The **default
  (no `--powered`)** scans + emits every worklist + prints the agent TODO, making
  **ZERO external calls**. `--powered` drives an external agent CLI per worklist (the
  keys live in **that CLI**, not ultrasec); `--cross-check <cli>` runs a second agent
  whose high/critical verify/revalidate disagreement escalates a finding to needs-human.
  See [references/powered-mode.md](references/powered-mode.md).

## Route by situation

1. **No audit yet** — run `scan`, then work the dossier. For a standard audit read
   [references/audit-playbook.md](references/audit-playbook.md).
2. **High-assurance / "be thorough"** — decompose by vulnerability class and entry
   point, fan out analyzer + skeptic subagents, loop until dry:
   [references/deep-audit-playbook.md](references/deep-audit-playbook.md).
3. **Billion-line / monorepo / "audit the whole platform"** — too big to scan whole:
   `map` the attack surface, then drill in target-by-target under a budget, merging
   into one run: [references/scale-audit-playbook.md](references/scale-audit-playbook.md).
   Same loop for incremental `--diff` re-audits in CI.
4. **Tune coverage** — sink/source/sanitizer catalog + CWE map:
   [references/catalog.md](references/catalog.md); external tools:
   [references/tools.md](references/tools.md). For the bugs the engine *can't*
   enumerate (authz, business logic, feature abuse, chained attacks) hunt with
   [references/hunting-heuristics.md](references/hunting-heuristics.md); to calibrate
   severity and avoid false positives,
   [references/severity-and-discipline.md](references/severity-and-discipline.md).
5. **Drive it autonomously** — let an external agent CLI fill the worklists end-to-end
   (opt-in, keys live in that CLI): [references/powered-mode.md](references/powered-mode.md).
   Two deepsec-style accuracy passes worth their own playbooks:
   [references/revalidate-playbook.md](references/revalidate-playbook.md) (git-history
   FP cut) and [references/investigate-playbook.md](references/investigate-playbook.md)
   (agentic discovery of authz/business-logic bugs).

## Workflow (standard audit)

You are invoked to return a grounded, cited audit. Don't hand back control mid-run.
The full pipeline is `context → scan → triage → dossier → investigate → verify →
revalidate → check → narrative → implement → render` — every stage is additive and old runs
still work, so use the subset the task needs (a quick audit can skip triage/
investigate/narrative/implement). Each AI stage follows the same shape: the engine **emits**
a worklist → you **fill** it → `--apply` folds it back in under a conservative rule.

1. **Prime the context** *(highest leverage)*. `context --repo <dir> --out <run>`,
   then author `<run>/CONTEXT.md` from `CONTEXT.todo.md` — the project's purpose,
   trust model, auth/authorization scheme, framework protections, and a **comparable
   mainstream app to calibrate severity against**. Every later stage reasons WITH it.
   (Evidence only — it never gates a verdict.) The recon questions to answer and the
   baseline idea are in
   [references/severity-and-discipline.md](references/severity-and-discipline.md).

2. **Scan.** `scan --repo <dir> --out <run>`. Check `tools` first if you want to
   install scanners for richer coverage (Trivy for deps/secrets/IaC is highest-leverage).

3. **Read the dossier.** Open `<run>/DOSSIER.md` — the candidate list with each
   cross-file path. Don't bulk-load `graph.json`.

4. **Triage (optional fast-lane).** `triage --run <run>`, mark each open candidate
   `noise|keep`, `triage --apply`. `noise` clears only low/med/info; a high/critical
   `noise` is **ignored** (kept open) — serious findings always go through full verify.

5. **Investigate what the engine can't enumerate.** `investigate --run <run>` groups
   the attack surface by region; hunt **broken access control / IDOR, business-logic
   flaws, missing authz**, feature abuse, chained attacks, multi-hop taint, and emit
   grounded `Discovery[]` (`investigate --apply`). Bring the attacker-mindset angles
   and the non-taint attack-class taxonomy in
   [references/hunting-heuristics.md](references/hunting-heuristics.md). They land
   `ultrasec-ai` `open` and are adjudicated like any candidate; out-of-range citations
   are rejected, so don't fear over-reporting.

6. **Adjudicate each candidate from evidence.** For each, run `dossier <id>` and read
   the **real code along the path**. Decide: is the SOURCE attacker-controlled? does the
   value reach the SINK through every hop unchanged? is there a sanitizer/validator/authz
   guard on the path? is the SINK exploitable with the value that arrives (write the PoC)?

7. **Verify.** `verify --run <run>` → worklist; record a verdict per finding
   (`supported|partial|unsupported|refuted` + a note, and an `exploitPath` when
   supported), then `verify --apply`. Be a skeptic, but don't refute a high-severity
   finding you can't actually disprove (uncertain ⇒ leave it needs-human).

8. **Revalidate against git history (cuts false positives).** `revalidate --run <run>`
   gives compact git facts per confirmed/needs-human finding; decide
   `still-valid|fixed|false-positive|uncertain`, then `revalidate --apply`. `fixed`
   dismisses with the fixing commit; a high/critical `false-positive` escalates to
   needs-human (never auto-dismissed).

9. **Gate.** `check --run <run> --semantic`. Fix any dangling citation; adjudicate any
   remaining candidate until it passes.

10. **Narrate & render.** Optionally `narrative --run <run>`, author `NARRATIVE.json`
    (executive summary, **what the codebase does well** (`positivePatterns`),
    per-confirmed fixes, attack chains, root causes, and **`hardeningNotes`** —
    defense-in-depth suggestions that are *not* findings), then
    `render --run <run> --narrative NARRATIVE.json` (the AI sections are clearly marked;
    finding-citing sections are grounding-checked, the advisory prose isn't). Without a
    narrative, plain `render`. Present the SUMMARY, the confirmed findings with their
    cross-file + exploit paths, the needs-human list, and the dossier path. A single
    pass finds only part of the surface — recommend a `--merge` re-run for coverage
    ([references/severity-and-discipline.md](references/severity-and-discipline.md)).

11. **Plan the fixes (optional).** `implement --run <run>` emits a remediation-PRD draft
    (`IMPLEMENT.md`): confirmed → fix stories (each grounded in its `[file:line]` with an
    acceptance-criteria scaffold), needs-human → investigation items, grouped by root cause
    and folding the just-authored `NARRATIVE.json`. Feed `IMPLEMENT.md` to the local `to-prd`
    skill to author the PRD, or hand it to an implementer/AI. It never changes a finding's
    status. See [references/implement-playbook.md](references/implement-playbook.md).

**Autonomy (opt-in).** `run --repo <dir>` sequences all of the above; the default emits
every worklist and prints a TODO (zero external calls). With your own agent CLI,
`run --powered --agent <cli> [--cross-check <cli2>]` drives the loop end-to-end —
[references/powered-mode.md](references/powered-mode.md).

## Scope notes

- **Deterministic core, optional tools.** Two scans of an unchanged repo yield the
  same taint candidates; external-tool results depend on what's installed and may
  hit the network (Trivy/cargo-audit fetch advisory DBs). Nothing external is required.
- **Risk ranking & correlation are deterministic.** Findings from multiple tools are
  merged (dep: package + shared advisory id, collapsing per-version/per-lockfile
  instances into one finding whose `locations[]` keeps each `{file, line, version}`;
  else category+CWE+file:line — including a scanner finding that lands on a taint
  node, which corroborates rather than duplicates) and ranked by a composite
  EPSS/KEV/CVSS `risk`. EPSS/KEV feeds are cached under `~/.cache/ultrasec` (daily
  TTL); the scoring math is offline. `--no-enrich`/`--offline` makes it fully
  network-free (severity-only ranking).
- **~15 languages** for the link-graph (JS/TS, Python, Go, Java, Ruby, PHP, Rust,
  C/C++, C#, Kotlin, Swift, Scala, shell, Lua, Elixir); the sink/source catalog is
  deepest for the web stacks and grows over time.
- **Not a substitute for judgement.** ultrasec narrows a huge repo to a handful of
  evidence-backed candidates and proves the boring half mechanically; the security
  call is yours.

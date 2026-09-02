---
name: ultrasec
description: "Audit a codebase for exploitable security issues by tracing untrusted data across files and adjudicating scanner findings. Use for vulnerability, taint, dependency, secrets, auth, business-logic, or supply-chain audits."
license: MIT
metadata:
  version: 1.43.0
---

# ultrasec — cross-file security audit, grounded not guessed

`ultrasec` finds vulnerabilities by **reasoning over how untrusted data moves between functions
and files**, the way a human auditor does — then proves or disproves each candidate against the
real code. Like its `ultra*` siblings it is a **division of labour**: the deterministic,
zero-dependency engine does the *mechanical* work — the link-graph, the candidate source→sink
paths, the scanner runs, the evidence packets; **you** do the *security reasoning* — decide which
flows are real and exploitable, find the subtle bugs the tools miss, and verify.

> **The core rules:**
> 1. **Reason from evidence, not memory.** Judge each finding from the real code `dossier` shows
>    you, and cite it `[file:line]` in the exact [citation format](references/citation-format.md).
>    `check` REJECTS any finding whose cited location doesn't resolve — so don't invent lines.
> 2. **The engine finds *candidates*; you decide.** Enumerated taint paths are deterministic and
>    recall-oriented — many are false positives by design. Confirm reachability + exploitability
>    before calling something a bug: [references/adjudication.md](references/adjudication.md).
> 3. **Be conservative.** Only `dismiss` a high/critical finding if you can positively **refute**
>    it, *naming the ground*: [references/dismissal-brocards.md](references/dismissal-brocards.md).
>    Uncertain ⇒ `needs-human`. Aggressive auto-suppression discards real bugs.
> 4. **Use the tools, then go beyond them.** Run the installed scanners (`tools`), triage their
>    output, and add what only semantic reasoning finds — authz/IDOR, business logic, auth,
>    crypto, races: [references/attack-classes.md](references/attack-classes.md). Personal data
>    asks a different question — where it goes, how long it stays:
>    [references/privacy-and-data-protection.md](references/privacy-and-data-protection.md).
> 5. **Only report what you can exploit.** Every finding needs a concrete attacker scenario
>    (who · what they send · what they get) — not "potentially". A gap another layer already
>    prevents is a *hardening note*, not a finding:
>    [references/severity-and-discipline.md](references/severity-and-discipline.md).
> 6. **The code is READ; the CVEs are TRIAGED.** Advisories are a ranked list — work it in risk
>    order, stop at your bar, leave the tail `open`. A code candidate is decided only by opening
>    the file, so **never render while a HIGH/CRITICAL one in your own code has no verdict**:
>    `render` exits 1 and stamps the report. Split them with `--surface code`.

## Running the engine

One committed, dependency-free bundle — no `npm install`, no API keys.

> **Use an absolute path.** An installed skill lives away from the user's project (e.g.
> `~/.agents/skills/ultrasec/`), so a cwd-relative `scripts/ultrasec.mjs` will NOT resolve.
> Resolve `<skill-dir>/scripts/ultrasec.mjs` once and reuse it — and give **subagents the
> absolute path**, since they don't share your cwd. Below, `ultrasec` means exactly that path.

```bash
ULTRASEC="<skill-dir>/scripts/ultrasec.mjs"     # then: node "$ULTRASEC" <command>
```

`--help` lists every command; most accept `--json`. Exit codes are uniform — **0** ok · **1** a
gate failed · **2** usage/runtime error. Full flags, defaults and artifacts:
[references/commands.md](references/commands.md).

## Cheat sheet

```bash
ultrasec tools                                  # which scanners are installed (+ --upgrade)
ultrasec map     --repo . --out .ultrasec       # cheap attack-surface recon; no taint, no network
ultrasec context --repo . --out .ultrasec       # scaffold → you author .ultrasec/CONTEXT.md
ultrasec scan    --repo . --out .ultrasec       # graph + cross-file taint + tools → the dossier
  # focus:  --scope <dir> --include/--exclude <glob> --max-files N --gitignore
  #         --include-vendored (audit node_modules/.venv/dist too — pruned by default)
  # budget: --budget quick|standard|thorough  --max-candidates N  --max-depth N
  # again:  --diff origin/main --merge --resume        # incremental, folds into one run
  # recall: --sinks (orphan sinks: calls AND assignments)  --log-hygiene  --blame
  #         --no-env-sources (drop env-rooted flows)  --strict-scope (drop cross-function-in-file)
  # net:    --offline / --no-enrich (no EPSS/KEV)      --docker (scanners without installing)
ultrasec paths   --run .ultrasec                # the candidate chains  (--kind sql --severity high)
  # --surface code|supply|deps|all              # YOUR code · secrets+CI/IaC · advisories  (also on triage/orchestrate)
ultrasec dossier <id> --run .ultrasec           # ONE finding: enclosing function, callers, route, guards, sanitizers
  # --brief                                     # the compact packet, for batch fan-out
ultrasec graph   <file|symbol> --run .ultrasec  # cross-file links into/out of a node
ultrasec assumptions --run .ultrasec            # what each unit trusts that NOTHING enforces (--apply)
ultrasec triage  --run .ultrasec                # cheap noise|keep fast-lane  (--apply TRIAGE.json, --surface code)
ultrasec guards  --run .ultrasec                # entry point × auth guard — the MISSING check (--apply)
  # --lens throttle                             # …and the MISSING rate limit
ultrasec investigate --run .ultrasec            # hunt authz/logic  (--apply INVESTIGATE.json)
ultrasec verify  --run .ultrasec                # adversarial worklist → write verdicts.json
ultrasec verify  --apply verdicts.json --run .ultrasec       # a file, comma-list, DIRECTORY, or -
  # any --apply: refused rows are listed with their reason; --strict exits 1 on any
ultrasec revalidate --run .ultrasec             # git-history FP cut  (--apply REVALIDATE.json)
ultrasec variants   --run .ultrasec             # where ELSE this root cause appears (--apply)
ultrasec coverage --run .ultrasec               # standards matrix: what was NOT looked at (--write)
  # standard: --standard asvs|owasp-top10|owasp-api-top10|masvs|cwe-top25   (default asvs)
ultrasec check   --run .ultrasec --semantic     # THE GATE: grounded + adjudicated (--min-severity)
ultrasec narrative --run .ultrasec              # → you author NARRATIVE.json
ultrasec render  --run .ultrasec --narrative NARRATIVE.json  # SUMMARY/REPORT.md + index.html
  # exits 1 while a HIGH/CRITICAL CODE candidate is unread (files still written); --draft to accept it
ultrasec implement --run .ultrasec              # remediation-PRD draft → the `to-prd` skill
ultrasec run     --repo . --out .ultrasec       # sequence every stage (ZERO external calls)
ultrasec orchestrate --run .ultrasec --phase verify   # emit the multi-agent fan-out (--surface code)
ultrasec logs    ./var/log --out .ultrasec-logs # blue team: forensics over EXISTING log files
  # detections: --sigma → ultrasec-logs.sigma.yml (SIEM pack, like variants→semgrep)
  # anywhere: --report out.md|html|json (archive this output)  --no-journal (skip JOURNAL.md)
ultrasec import  findings.json --run .ultrasec  # ingest a deepsec export as candidates
ultrasec clean   --run .ultrasec                # keeps REPORT/SUMMARY/index.html/findings/JOURNAL
ultrasec probe   https://you-own-this --i-own-this   # DYNAMIC live-site posture → PROBE.json (isolated)
  # probe: --allow-private (localhost)  --graphql  --deep (exposed files)  --timeout ms  --strict
ultrasec route   app.apk | ./bin/x.so | https://host # OUT-OF-SCOPE triage → methodology + tools (advisory)
  # route: URL → probe · source/dir → scan · else → jadx/radare2/wireshark/… (--write ROUTE.md)
```

## Route by situation

1. **"Audit this repo"** — the standard single pass: `context` → `scan` → adjudicate → `verify` →
   `check` → report. [references/audit-playbook.md](references/audit-playbook.md).
2. **"Be thorough" / high-assurance** — decompose by class and entry point, fan out analyzer +
   skeptic subagents, loop until dry:
   [references/deep-audit-playbook.md](references/deep-audit-playbook.md).
3. **"Audit the whole platform" / a repo too big to scan** — `map` first, then drill in
   target-by-target under a budget, merging into one run; same loop for incremental `--diff`
   re-audits in CI: [references/scale-audit-playbook.md](references/scale-audit-playbook.md).
4. **"Is this real?" / "looks like a false positive"** — the FP taxonomy, the refutation bar, how
   to write an exploit proof, worked examples:
   [references/adjudication.md](references/adjudication.md).
5. **"What else should I look for?"** — the classes taint can't reach, at mechanism level:
   [references/attack-classes.md](references/attack-classes.md); where they hide in your stack:
   [references/frameworks.md](references/frameworks.md); the lenses to apply first:
   [references/hunting-heuristics.md](references/hunting-heuristics.md).
6. **"Check my dependencies / secrets / CI"** — triage ladder, secret response, GitHub Actions,
   IaC: [references/supply-chain.md](references/supply-chain.md); the scanner belt:
   [references/tools.md](references/tools.md). A workflow that hands a coding agent your repo's
   own event data is its own class, audited by `scan`:
   [references/agentic-ci.md](references/agentic-ci.md).
6b. **"Audit this library / SDK / API"** — the question changes: not *is this vulnerable* but
   *does this design make the insecure use easier than the secure one*.
   `investigate --lens sharp-edges` · [references/sharp-edges.md](references/sharp-edges.md).
7. **"How bad is this?"** — severity rubric with worked calibration pairs:
   [references/severity-and-discipline.md](references/severity-and-discipline.md).
8. **"Analyze my access/auth logs" / "did anyone attack us"** — blue team, read-only, own
   dossier: [references/log-forensics-playbook.md](references/log-forensics-playbook.md).
9. **"Run it autonomously"** — let an external agent CLI fill the worklists (opt-in, keys live in
   that CLI): [references/powered-mode.md](references/powered-mode.md).

## Workflow (standard audit)

You are invoked to return a grounded, cited audit — don't hand back control mid-run. Every stage
is additive; use the subset the task needs. Each has the same shape: the engine **emits** a
worklist → you **fill** it → `--apply` folds it back under a conservative rule. Exact JSON for
each: [references/schemas.md](references/schemas.md).

1. **Prime the context** *(highest leverage)*. `context --repo <dir> --out <run>`, then author
   `<run>/CONTEXT.md` — purpose, trust model, auth scheme, framework protections, and a
   comparable app to calibrate severity against. Add `Exposure:` and `Criticality:` (the risk
   score reads them) and a STRIDE/LINDDUN pass per trust boundary — that is what decides *what
   you hunt* instead of letting the tooling decide:
   [references/threat-modeling.md](references/threat-modeling.md).
   [references/context-playbook.md](references/context-playbook.md).

2. **Scan.** `scan --repo <dir> --out <run>`. Run `tools` first for richer coverage (Trivy is
   highest-leverage); with the user's consent, `tools --upgrade` (`--dry-run` previews).

3. **Check the run is real** — before reading a single finding, open `<run>/manifest.json`:
   - `extraction.ast: false` ⇒ tree-sitter was unavailable and the **regex** extractors ran. On a
     69-file TypeScript repo that is 27 taint candidates instead of 66, with every critical
     cross-file command-injection candidate missing. Re-run with the grammars, or say so.
   - `truncation` non-zero ⇒ a cap was hit; raise `--max-candidates` or narrow `--scope`.
   - `toolStatus` ⇒ which scanners ran, which were skipped (a coverage hole), which failed.

   A degraded run must never be reported as a complete one.

4. **Read the dossier.** Open `<run>/DOSSIER.md` — candidates ordered by risk, each with its
   cross-file path. Don't bulk-load `graph.json`.

5. **Triage (optional).** `triage --run <run>`, mark `noise|keep`, `triage --apply`. Clears only
   low/medium/info; a high/critical `noise` is **ignored** and goes to full verify.

6. **Adjudicate from evidence — the CODE first.** Work `paths --surface code`, not the whole open
   tier; the dependency half is triaged as a list, never a dossier per CVE
   ([references/supply-chain.md](references/supply-chain.md)). `dossier <id>` gives you the whole
   enclosing function at both ends plus **Who can reach this** — route file, callers, auth and
   rate-limit markers in scope, sanitizers near the path. Answer: is the SOURCE
   attacker-controlled? does the value reach the SINK through every hop unchanged? is there a
   sanitizer/authz guard? is the SINK exploitable with what arrives — can you write the PoC?
   Budget **by family, not by finding**: one read decides a whole fold (242 candidates were 62 on
   the run this came from). [references/adjudication.md](references/adjudication.md).

6b. **Map the assumptions** *(before hunting)*. `assumptions --run <run>` — per unit, what it
   guarantees (cited) and what it depends on that nothing enforces. A `nothing-found` marks code
   trusting something nobody wrote down: no dangerous call, nothing wrong on any single screen,
   invisible to the engine. `--apply` feeds the leads to `investigate`.
   [references/assumptions-playbook.md](references/assumptions-playbook.md).

6c. **Enumerate the MISSING guard.** `guards --run <run>` lists every handler reading request data
   with no auth marker in scope — the class taint cannot reach, since an absent check has no line
   to trace. A marker is a *candidate*: read the handler, confirm it guards authorization before
   the object is touched. `--apply` turns `unguarded` into a cited finding. Run it again with
   `--lens throttle` for the other absence — handlers nothing rate-limits, auth routes flagged
   apart. Under either lens, **no marker anywhere is one architectural fact, not N findings**:
   answer it once in `CONTEXT.md`. [references/hunting-heuristics.md](references/hunting-heuristics.md).

7. **Hunt what the engine can't enumerate.** `investigate --run <run>` groups the attack surface
   by region; find broken access control/IDOR, business logic, auth/session/JWT, crypto, races,
   feature abuse, chained attacks, and emit grounded `Discovery[]` — citations are checked before
   ingest, so over-reporting is cheap.
   [references/investigate-playbook.md](references/investigate-playbook.md).

8. **Verify.** `verify --run <run>` → worklist; record `supported|partial|unsupported|refuted`
   with a note, plus an `exploitPath` when supported; `verify --apply`. Be a skeptic, but don't
   refute a high-severity finding you can't actually disprove.

9. **Revalidate against git history.** After `verify --apply` (its scope is confirmed/needs-human,
   so earlier the worklist is empty): decide `still-valid|fixed|false-positive|uncertain`.
   [references/revalidate-playbook.md](references/revalidate-playbook.md).

9b. **Hunt the variants.** `variants --run <run>` — a root cause almost never produced exactly one
   instance. State the *why*, generalize one dimension at a time, and emit a Semgrep rule so the
   family cannot come back: [references/variant-analysis.md](references/variant-analysis.md).

10. **Gate.** `check --run <run> --semantic`. Fix any dangling citation, adjudicate anything left,
   and reconcile any negation in `CONTEXT.md` the code contradicts — a sentence saying a class
   isn't there is how a class goes unexamined.

10b. **State the coverage.** `coverage --run <run>` — an ASVS matrix of what this audit looked at
   and what it did not. A short report reads as "nothing there" when it means "nothing there, in
   what I looked at"; the matrix separates the two. Folded into REPORT.md automatically.

11. **Narrate & render.** `narrative --run <run>`, author `NARRATIVE.json` (executive summary,
    `positivePatterns`, fixes, attack chains, root causes, `hardeningNotes`), then `render --run
    <run> --narrative NARRATIVE.json`. The report is organised by surface: your code first with
    its entry-point table, then secrets/CI/IaC, then advisories folded one row per package.
    **It exits 1 while a HIGH/CRITICAL code candidate is unread** — files still written, reason
    stamped in them — so go back to step 6, or pass `--draft` and say so. Present the SUMMARY, the
    confirmed findings with their exploit paths, the needs-human list and the run folder.
    [references/narrative-playbook.md](references/narrative-playbook.md).

12. **Plan the fixes (optional).** `implement --run <run>` → `IMPLEMENT.md`, a remediation-PRD
    draft grouped by root cause. Feed it to the `to-prd` skill or an implementer.
    [references/implement-playbook.md](references/implement-playbook.md).

## Orchestration — route by harness

The judgment stages fan out: the open candidates in `findings.json` (adjudicate),
`VERIFY.todo.json`, `REVALIDATE.todo.json` and `INVESTIGATE.todo.json` are independent per-item
worklists. `orchestrate` emits the fan-out from the CURRENT worklists, with absolute paths and
the real item ids baked in:

```
ultrasec orchestrate --run <dir> [--phase adjudicate|verify|revalidate|investigate] [--eco] [--list]
```

| Your harness | How to run each judgment phase |
|---|---|
| Claude Code exposes Workflow | `orchestrate --run <RUN> --phase <p>`, then `Workflow({ scriptPath: "<RUN>/orchestration/<p>.workflow.mjs" })`. Subagents RETURN verdict/discovery fragments; merge them into one apply file yourself, then run the `--apply` fold shown at the end of the workflow. |
| Codex/other host has subagents | Same `orchestrate`; dispatch one subagent per batch following `<RUN>/orchestration/agents/<role>.md` (the workflow script shows batches + prompts). One writer: you merge and fold. |
| Eco mode, or no subagents | `orchestrate --run <RUN> --eco` → follow `<RUN>/orchestration/RUNBOOK.md` sequentially, playing each role yourself. Correctness-identical; only wall-clock differs. |

Fan-out is an optimization, never a requirement — every phase has a sequential fallback with
identical artifacts. Subagents never write: the contracts end with the one-writer rule (read-only
commands only), and `--apply` stays with you, so an uncertain high-severity finding still lands
needs-human whoever adjudicated it. Re-run `orchestrate` whenever a worklist changes (emission is
idempotent); `--phase <p>` before its worklist exists fails and names the command that produces it.

## When the run looks wrong

| symptom | what to do |
|---|---|
| `scan` found 0 candidates | Check `manifest.extraction.ast` (regex tier?) and `languages` — an unsupported stack yields no graph. Try `--sinks`, and hunt manually with `investigate`. |
| Far fewer candidates than expected | Same, plus `truncation` (a cap was hit) and `--scope`/`--gitignore` pruning more than you meant. |
| `toolStatus` shows everything skipped | No scanners installed — `tools` for install hints, or `scan --docker`. The taint core is unaffected. |
| `check` keeps failing | A cited `[file:line]` doesn't resolve: the file moved, the line is out of range, or it was invented. Reopen `dossier <id>`, fix the citation, or drop the finding. |
| `check --semantic` fails | Candidates are still `open`. Adjudicate them, or clear the obvious ones with `triage`. |
| `--apply` exits 2 | Fail-closed: malformed file, or no id in it matches the dossier (stale fragments). Re-emit the worklist and refill. |
| `--apply` from a directory folded nothing | Fragment names must match the stage's pattern — [commands.md](references/commands.md) lists them. |
| `investigate --apply` rejected a discovery | Either its `[file:line]` doesn't resolve — the anti-hallucination gate working; get the real line and resubmit — or a field is outside its vocabulary. The reason names the field and the value. Class names (`xss`, `dos`, `disclosure`…) are folded onto `category`, not refused. |
| First run is slow / hits the network | A cold machine downloads ~22 MB of tree-sitter grammars once (`--offline` does not suppress it). Prewarm, or set `CODEINDEX_GRAMMARS_DIR`. |
| A scoped re-scan seems to lose findings | Use `--merge` — it preserves prior verdicts and keeps out-of-scope findings. |

## Common mistakes

1. **Running the engine by a relative path.** It fails from any cwd but the skill dir. Use the
   absolute `<skill-dir>/scripts/ultrasec.mjs`, and give subagents the same.
2. **Reporting a degraded run as complete.** Check `extraction`/`truncation`/`toolStatus` first.
3. **Promoting candidates without reading the code.** They are recall-oriented by design; a
   `dossier` read is the unit of work.
4. **Refuting what you merely can't confirm.** Not proving it is not disproving it — that's
   `needs-human`.
5. **Rating defense-in-depth as HIGH.** If another layer prevents it, it's a hardening note.
6. **Padding with LOWs.** Three real MEDIUMs beat ten theoretical LOWs.
7. **Stopping at the scanners.** They cover known patterns; authz, business logic and races are
   where a manual pass earns its keep.
8. **Skipping `context`.** Without a trust model you are rating in the abstract.
9. **Hunting only what the engine listed.** It finds PATTERNS, not ABSENCES — run `guards`, both
   lenses. A FAILED scanner is the same trap: a hole that reads like an empty result.
10. **Rendering a dump, or spending the audit on the CVE list.** One run went `scan` → `guards`
   → `render` and shipped 882 candidates, none adjudicated, every *why* cell a dash, under "No
   confirmed issues" — which reads as a clean bill of health and meant nobody had looked. The
   advisories were most of that count and the least of its value: they come ranked, the flows do
   not. Read the code first; don't reach for `--draft` to silence the gate.

## Do not

- **Never hand-edit `findings.json`.** It bypasses the citation gate and breaks the
  content-derived `id` that makes re-scans and `--merge` idempotent — use `investigate --apply`.
- **Never let a subagent run `--apply` or `verify --shards`.** Both write into the run dir; the
  orchestrator is the sole writer.
- **Never auto-dismiss a high/critical finding you can't positively refute.**
- **Never invent a `[file:line]`.** Get it from `dossier`, `graph`, or `rg -n`.
- **Never run an exploit that damages or exfiltrates.** Prove control with a benign marker:
  `sleep(5)`, a `<b>` tag, a canary string.

## Scope notes

- **Deterministic core, optional tools.** Two scans of an unchanged repo yield the same taint
  candidates *on the same extraction tier*; external-tool results depend on what's installed and
  may hit the network (advisory DBs). Nothing external is required.
- **Risk ranking & correlation are deterministic.** One issue seen by several tools becomes one
  finding whose `sources[]` names each producer, ranked by a composite EPSS/KEV/CVSS `risk`. Feeds
  are cached (daily TTL); the math is offline. `--offline` ranks by severity alone.
- **~15 languages** for the link-graph (JS/TS, Python, Go, Java, Ruby, PHP, Rust, C/C++, C#,
  Kotlin, Swift, Scala, shell, Lua, Elixir); the catalog is deepest for the web stacks —
  [references/catalog.md](references/catalog.md).
- **What it does not do:** no DAST, no fuzzing, no authenticated crawling, no runtime testing.
  Every class in [references/attack-classes.md](references/attack-classes.md) is manual, and one
  pass reads only the paths you dug into — recommend a `--merge` re-run.
- **Measured.** Per-CWE scores on OWASP Benchmark:
  [references/BENCHMARK.md](references/BENCHMARK.md), gaps
  included — strong on injection, **zero** on what is not a source→sink shape. `coverage` says which.
- **Not a substitute for judgement.** ultrasec narrows a huge repo to a handful of evidence-backed
  candidates and proves the boring half mechanically; the security call is yours.

## References

**Method** — [adjudication.md](references/adjudication.md) (FP taxonomy, PoC rubric, worked
examples) · [severity-and-discipline.md](references/severity-and-discipline.md) (rubric +
calibration pairs) · [citation-format.md](references/citation-format.md) (the grounding contract)
· [schemas.md](references/schemas.md) (every worklist JSON).

**Security knowledge** — [attack-classes.md](references/attack-classes.md) (the classes taint
can't reach) · [access-control.md](references/access-control.md) (IDOR/BOLA/BFLA, `--lens access-control`) ·
[privacy-and-data-protection.md](references/privacy-and-data-protection.md) (transfers,
retention, pseudonymisation) ·
[frameworks.md](references/frameworks.md) (per-stack hiding places) ·
[hunting-heuristics.md](references/hunting-heuristics.md) (attacker lenses + recon commands) ·
[supply-chain.md](references/supply-chain.md) (deps, secrets, CI, IaC) ·
[catalog.md](references/catalog.md) (what the engine enumerates).

**Playbooks** — [audit-playbook.md](references/audit-playbook.md) (standard) ·
[deep-audit-playbook.md](references/deep-audit-playbook.md) (thorough) ·
[scale-audit-playbook.md](references/scale-audit-playbook.md) (huge repos, CI) ·
[context-playbook.md](references/context-playbook.md) ·
[investigate-playbook.md](references/investigate-playbook.md) ·
[revalidate-playbook.md](references/revalidate-playbook.md) ·
[narrative-playbook.md](references/narrative-playbook.md) ·
[implement-playbook.md](references/implement-playbook.md) ·
[log-forensics-playbook.md](references/log-forensics-playbook.md) (blue team) ·
[probe-playbook.md](references/probe-playbook.md) (dynamic live-site posture, isolated) ·
[route-playbook.md](references/route-playbook.md) (triage out-of-scope targets → tools) ·
[powered-mode.md](references/powered-mode.md) (autonomy).

**Engine** — [commands.md](references/commands.md) (full CLI) ·
[tools.md](references/tools.md) (scanner belt) ·
[tooling-internals.md](references/tooling-internals.md).

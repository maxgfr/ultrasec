---
name: ultrasec
description: "Use when the user wants a SECURITY AUDIT of a codebase — to find real, exploitable vulnerabilities by reasoning about how untrusted data flows ACROSS functions and files, not just linting one file at a time. A deterministic zero-dependency engine (no API keys, no npm install) scans the whole repo, builds a cross-file/function link-graph, enumerates candidate source→sink taint paths (SQLi, NoSQL injection, command/code injection, path traversal & zip-slip, SSRF, XSS, SSTI, XXE, LDAP injection, header/CRLF injection, prototype pollution, insecure deserialization, weak crypto, open redirect), and orchestrates whatever best-in-class OSS scanners are installed (Trivy, OpenGrep/Semgrep, gitleaks, osv-scanner, cargo-audit, govulncheck, bandit, gosec, checkov, hadolint, kingfisher…), correlating their findings across tools and ranking everything by composite EPSS/CISA-KEV/CVSS risk; YOU then read the real code along each path, judge whether the flow is genuinely reachable and exploitable (incl. authz/business-logic bugs the tools miss), and adversarially verify every finding into a cited, tiered report. Anti-hallucination: every finding must cite resolvable [file:line] hops (`check` fails otherwise). Conservative: an uncertain high-severity finding is flagged needs-human, never silently dropped. Triggers: 'audit this repo for security', 'find vulnerabilities', 'security review of this codebase', 'is this code vulnerable to SQL injection/XSS/SSRF/command injection', 'taint analysis', 'where does user input reach a dangerous sink', 'check my dependencies for CVEs', 'scan for secrets'. The code-facing security sibling of ultraindex/ultrasearch."
license: MIT
metadata:
  version: 1.5.0
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
>    `dossier` shows you, and cite it `[file:line]`. `check` REJECTS any finding
>    whose cited location doesn't resolve — so don't invent line numbers.
> 2. **The engine finds *candidates*; you decide.** Enumerated taint paths are
>    deterministic and recall-oriented — many are false positives by design.
>    Confirm reachability + exploitability before calling something a bug.
> 3. **Be conservative.** Only `dismiss` a high/critical finding if you can
>    positively **refute** it. Uncertain ⇒ leave it `needs-human`. Aggressive
>    auto-suppression discards real bugs.
> 4. **Use the tools, then go beyond them.** Run the installed scanners (`tools`),
>    triage their output, and add what only cross-file/semantic reasoning can
>    find: authorization/IDOR, business-logic, multi-hop taint.

Most commands accept `--json` — prefer it when you branch on the result.

## The script

One committed, dependency-free bundle: `node scripts/ultrasec.mjs <command>`.

- `map --repo <dir> [--scope <glob>] [--out <run>] [--json]` — the **cheap recon
  pass**: enumerate the attack surface (entry points by kind, sinks by CWE class,
  per-dir density) with **no taint BFS, no tools, no network** — fast even on a
  billion-line repo. Emits `MAP.md`/`attack-surface.json` and a deterministic
  **suggested-target** list to drill into. Run this first on a huge repo.
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
- `verify --run <dir> [--shards n --shard i]` — emit the adversarial worklist
  (`VERIFY.todo.json` / `VERIFY.md`); shard it to fan verification out.
- `verify --apply <verdicts.json | dir | a,b,c> --run <dir>` — fold your verdicts
  back in (`supported`→confirmed, `refuted`→dismissed, `unsupported`/`partial` on a
  high-severity ⇒ needs-human, never auto-dropped).
- `check --run <dir> [--semantic] [--min-severity <s>]` — the exit gate. Fails on a
  dangling `[file:line]` (anti-hallucination); `--semantic` also fails if any
  candidate is still unadjudicated.
- `render --run <dir>` — `SUMMARY/REPORT/FULL.md` + a self-contained `index.html`
  (severity/status badges, the Mermaid taint-path, exploit paths).

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
   [references/tools.md](references/tools.md).

## Workflow (standard audit)

You are invoked to return a grounded, cited audit. Don't hand back control mid-run.

1. **Scan.** `node scripts/ultrasec.mjs scan --repo <dir>`. Note the dossier path
   (default `.ultrasec`). Check `tools` first if you want to install scanners for
   richer coverage (Trivy for deps/secrets/IaC is the highest-leverage one).

2. **Read the dossier.** Open `<out>/DOSSIER.md` — the candidate list with each
   cross-file path. Don't bulk-load `graph.json`. Triage obvious noise mentally,
   but keep anything plausible.

3. **Adjudicate each candidate from evidence.** For each, run
   `dossier <id>` and read the **real code along the path**. Decide:
   - Is the SOURCE truly attacker-controlled?
   - Does the tainted value actually reach the SINK through every hop, unchanged?
   - Is there a sanitizer/validator/authz guard anywhere on the path?
   - Is the SINK exploitable with the value that arrives? Write the trigger/PoC.
   Also hunt for what the engine can't enumerate: **broken access control / IDOR,
   business-logic flaws, missing authz**, unsafe config — these need whole-repo
   reasoning. Add them with `[file:line]` citations.

4. **Verify.** `verify --run <out>` to get the worklist; record a verdict per
   finding (`supported|partial|unsupported|refuted` + a note, and an `exploitPath`
   when supported) in a `verdicts.json`, then `verify --apply verdicts.json`. Be a
   skeptic, but don't refute a high-severity finding you can't actually disprove.

5. **Gate.** `check --run <out> --semantic`. Fix any dangling citation; adjudicate
   any remaining candidate until it passes.

6. **Render & present.** `render --run <out>`. Give the user the SUMMARY, the
   confirmed findings with their cross-file paths + exploit paths, the
   needs-human list, and the dossier path.

## Scope notes

- **Deterministic core, optional tools.** Two scans of an unchanged repo yield the
  same taint candidates; external-tool results depend on what's installed and may
  hit the network (Trivy/cargo-audit fetch advisory DBs). Nothing external is required.
- **Risk ranking & correlation are deterministic.** Findings from multiple tools are
  merged (dep: package@version + shared advisory id; else category+CWE+file:line)
  and ranked by a composite EPSS/KEV/CVSS `risk`. EPSS/KEV feeds are cached under
  `~/.cache/ultrasec` (daily TTL); the scoring math is offline. `--no-enrich`/
  `--offline` makes it fully network-free (severity-only ranking).
- **~15 languages** for the link-graph (JS/TS, Python, Go, Java, Ruby, PHP, Rust,
  C/C++, C#, Kotlin, Swift, Scala, shell, Lua, Elixir); the sink/source catalog is
  deepest for the web stacks and grows over time.
- **Not a substitute for judgement.** ultrasec narrows a huge repo to a handful of
  evidence-backed candidates and proves the boring half mechanically; the security
  call is yours.

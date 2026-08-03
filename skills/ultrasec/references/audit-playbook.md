# Audit playbook (standard single pass)

The everyday workflow: narrow the repo to a handful of evidence-backed candidates, adjudicate
each from the real code, gate, and report. Commands are shown as `ultrasec …`; run the engine by
its absolute path (see [SKILL.md](../SKILL.md)).

> **What did this run cover?** Every command that names a run directory appends to
> `<run>/JOURNAL.md` — command, headline result, refused `--apply` rows, exit code. Read it
> before you trust a run you didn't watch, and pass `--report <file>` to archive any single
> command's output. Both are additive; `--no-journal` opts out.

> **Optional stages, all additive.** `context` (trust model), `triage` (cheap noise cut),
> `investigate` (the classes the engine can't enumerate), `revalidate` (git-history FP cut),
> `narrative` + `implement` (report and remediation plan). A quick audit can skip all of them;
> `run` sequences them all. For a thorough one, escalate to
> [deep-audit-playbook.md](deep-audit-playbook.md); for a repo too big to scan whole, start at
> [scale-audit-playbook.md](scale-audit-playbook.md).

## 1. Prime the context (highest leverage)

```
ultrasec context --repo . --out .ultrasec     # → CONTEXT.scaffold.json + CONTEXT.todo.md
# author .ultrasec/CONTEXT.md
```

Every later dossier and worklist is injected with it. The questions to answer are in
[context-playbook.md](context-playbook.md). Skipping this means adjudicating each candidate
without knowing what the app considers trusted.

## 2. (Optional) install scanners

```
ultrasec tools
```

**Trivy** covers the most ground (deps + secrets + IaC); add `gitleaks`, `osv-scanner`,
`opengrep`/`semgrep`, and the language-native ones as relevant. Everything works without them.
See [tools.md](tools.md).

## 3. Scan

```
ultrasec scan --repo . --out .ultrasec              # auto-runs installed tools
ultrasec scan --repo . --out .ultrasec --tools none # graph + taint only
```

Then **read `manifest.json` before reading the findings** — `extraction.ast: false` means the
scan ran on the regex tier and is materially thinner; `truncation` means a cap was hit;
`toolStatus` shows which scanners were skipped. A degraded run must never be reported as a
complete one. Scope a big repo with `--scope`/`--include`/`--exclude`.

## 4. (Optional) triage the obvious noise

```
ultrasec triage --run .ultrasec                       # → TRIAGE.todo.json (no code excerpts)
ultrasec triage --apply TRIAGE.json --run .ultrasec
```

A glance, not a read: mark `noise|keep` per candidate. `noise` clears only low/medium/info — on a
high/critical it is **ignored by design** and the finding goes to full verify. Decision rules are
in [adjudication.md](adjudication.md#triage-noise-vs-keep). If deciding needs the code, it isn't
triage — leave it `keep`.

## 5. Read the dossier, then adjudicate each candidate

```
ultrasec paths --run .ultrasec                 # the candidate chains
ultrasec dossier <id> --run .ultrasec          # the grounding packet (id may be a prefix)
```

For each candidate, answer the four questions from the code in the packet:

1. **Source** — is it genuinely attacker-controlled (request, CLI, env, file, queue)?
2. **Propagation** — does the tainted value reach the sink through every hop, unchanged?
3. **Sanitizer/guard** — is it parameterized / escaped / validated / authz-checked on the path?
4. **Sink** — is it exploitable with the value that arrives? Write the concrete trigger.

The false-positive taxonomy, the refutation bar, how to write an `exploitPath`, and three worked
examples are in [adjudication.md](adjudication.md).

## 6. Hunt what taint enumeration can't reach

```
ultrasec investigate --run .ultrasec                          # → region worklist
ultrasec investigate --apply INVESTIGATE.json --run .ultrasec  # citation-checked ingest
```

Broken access control / IDOR, missing authorization, business logic, auth/session/JWT, crypto
misuse, race conditions, feature abuse, chained attacks. Method per class:
[attack-classes.md](attack-classes.md); where each hides in your stack:
[frameworks.md](frameworks.md); the lenses to apply first:
[hunting-heuristics.md](hunting-heuristics.md).

If the app is built around personal data, this is also where you ask where that data goes and how
long it stays — file those as `category: "privacy"`. Method:
[privacy-and-data-protection.md](privacy-and-data-protection.md).

**Ingest discoveries through `investigate --apply`, never by editing `findings.json`.** Hand
editing bypasses the citation gate and breaks the content-derived `id` that makes re-scans and
`--merge` idempotent. Citations are checked before ingest, so over-reporting costs nothing.

## 7. Verify and gate

```
ultrasec verify --run .ultrasec                        # → VERIFY.todo.json + VERIFY.md
# write verdicts.json — shape in references/schemas.md
ultrasec verify --apply verdicts.json --run .ultrasec
```

`supported`→confirmed, `refuted`→dismissed. `partial` → **needs-human at every severity**;
`unsupported` → needs-human on high/critical, dismissed below. Don't refute a high-severity
finding you can't actually disprove — not proving it is not disproving it.

## 8. Revalidate against git history

Run this **after** `verify --apply`: its scope is `status ∈ {confirmed, needs-human}`, so before
promotion the worklist is empty.

```
ultrasec revalidate --run .ultrasec                          # git facts per promoted finding
ultrasec revalidate --apply REVALIDATE.json --run .ultrasec
```

`fixed`→dismissed (+ the fixing commit); a high/critical `false-positive`→needs-human, never
auto-dismissed. See [revalidate-playbook.md](revalidate-playbook.md).

## 9. Gate

```
ultrasec check --run .ultrasec --semantic   # exit 0 only when grounded + adjudicated
```

Read-only. A dangling `[file:line]` means a hallucinated or stale citation — reopen the dossier
and fix it, or drop the finding.

## 10. Narrate, render and present

```
ultrasec narrative --run .ultrasec                                # → author NARRATIVE.json
ultrasec render --run .ultrasec --narrative NARRATIVE.json        # SUMMARY/REPORT.md + index.html
```

Present the SUMMARY counts, each confirmed finding with its cross-file and exploit path, the
needs-human list, the coverage caveats from step 3, and the run folder. Writing guidance:
[narrative-playbook.md](narrative-playbook.md); citation contract:
[citation-format.md](citation-format.md).

> **Coverage improves with more runs.** One pass reads only the paths you dug into. Re-run and
> fold with `--merge` (verdicts preserved), weighting the next pass toward what this one
> under-covered — see [severity-and-discipline.md](severity-and-discipline.md).

## 11. Plan the fixes (optional)

```
ultrasec implement --run .ultrasec    # → IMPLEMENT.md + IMPLEMENT.todo.json
```

Confirmed findings become fix stories grounded in their `[file:line]`, grouped by root cause;
feed `IMPLEMENT.md` to the `to-prd` skill or an implementer. Per-class fix patterns:
[implement-playbook.md](implement-playbook.md).

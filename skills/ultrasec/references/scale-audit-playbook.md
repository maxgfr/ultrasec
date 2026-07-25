# Scale-audit playbook (billion-line repos, map-first)

For a repo too big to scan whole — a giant monorepo, a vendored tree, "audit our
whole platform". The standard pass (`scan` the whole repo → adjudicate → `check`)
assumes you can hold the repo at once. Here you **don't**: you map the attack
surface cheaply, then **drill in target-by-target under a budget**, folding every
pass into one shared dossier. The engine stays deterministic and keyless — it
gives you a cheap map, scoped scans, an incremental cache, and a budget-bounded
candidate ranking; **you** decide where to look and when to stop.

> Why not just `scan` everything? On a 10M+ LOC repo a whole-repo scan reads every
> file, holds the full graph in memory, and enumerates candidates everywhere — most
> of it code you'll never read. Map-first spends the budget where the attack surface
> actually is.

> The AI stages scope cleanly too: `context --scope <dir>` and `investigate --scope
> <dir>` accept the same focus knobs, and `triage` is a cheap way to clear noise from
> a large candidate set before the per-finding reads. `revalidate` is especially
> valuable here — git history tells you which findings in a huge tree were already
> fixed. See [investigate-playbook.md](investigate-playbook.md) ·
> [revalidate-playbook.md](revalidate-playbook.md).

## The loop

1. **Map the attack surface (cheap, no taint, no tools, no network).**
   ```
   ultrasec map --repo . --out .ultrasec
   ```
   Reads `MAP.md` / `attack-surface.json`: entry points by kind (http/cli/env/ws…),
   sinks by CWE class, and **suggested targets** — top-level dirs ranked by
   severity-weighted sink density. This is O(files): fast even on a billion lines.
   `--scope`/`--include`/`--exclude`/`--max-files` narrow it further; `--gitignore`
   honours the repo's ignore file.

2. **Prioritise (engine suggests, you override).** The `suggestedTargets` list is a
   deterministic default — highest attack-surface density first, with already-scanned
   dirs marked. **Sink density is a proxy, not the answer**: it over-ranks noisy utility code and
   under-ranks the auth module with three careful sinks. Re-rank by:

   - **Crown jewels** — what holds credentials, money, PII, or the keys to everything else
     (auth, payments, tenancy, admin, key management, migrations).
   - **Exposure** — internet-facing before internal, unauthenticated before authenticated.
     Cross-reference `attack-surface.json`'s `entryPoints` with the guard list from `CONTEXT.md`.
   - **Churn** — `git log --since=6.months --name-only | sort | uniq -c | sort -rn` — recently
     and heavily changed code has had the least review time.
   - **Ownership gaps** — files with no CODEOWNER, or an owner who left. `--blame` surfaces both.
   - **Test coverage** — what the suite doesn't exercise, nobody has reasoned about either.
   - **Provenance** — vendored, generated, acquired or "temporary" code, and anything whose
     comments say experimental.

   Pick the next target and say why in the report; the ordering *is* the audit's thesis.

3. **Drill in — scoped scan, merged into the same run.**
   ```
   ultrasec scan --repo . --scope <target-dir> --merge --resume --out .ultrasec
   ```
   - `--scope` prunes the walk to that subtree (the load-bearing scale knob).
   - `--merge` folds the pass into the existing dossier — prior verdicts are
     preserved, new candidates appended, **out-of-scope findings kept** (a scoped
     re-scan never deletes what it didn't look at).
   - `--resume` reuses the content-hashed scan cache, so unchanged files aren't
     re-parsed across passes.
   - External scanners are skipped by default in scoped mode (don't re-run Trivy on a
     drill-down) — pass `--tools auto` when you want them on a target.
   - Bound the cost with `--budget quick|standard|thorough` (depth × candidates), or
     `--max-candidates`/`--max-depth` directly. If candidates are capped you get an
     explicit banner — **truncation is never silent**; raise the cap or narrow scope.

4. **Adjudicate + verify this target** (same as the standard/deep playbooks):
   `dossier <id>` → reason from the real code → `verify` (shard across skeptic
   subagents for a thorough audit) → `verify --apply` → `check --run .ultrasec --semantic`.

5. **Loop until the budget or the targets are dry.** Re-run `map --out .ultrasec`:
   already-scanned targets are marked ✅ and the next un-covered one is suggested.
   Move to it. Coverage is tracked in `manifest.scopes`, so the audit is **resumable
   across sessions** — pick up exactly where you left off.

   **Define the risk bar before you start, and write it in the report.** On a repo you can't
   finish, "where we stopped" is a finding in itself. A workable default: keep going while the
   next target is internet-reachable, or touches credentials/money/PII, or has changed in the
   last quarter; stop when the remaining targets are internal-only, non-sensitive and stable.
   Then say exactly that, and name the scopes left uncovered — a report that doesn't state its
   boundary reads as complete.

**Monorepo specifics.** Workspace boundaries are usually trust boundaries — check whether one
package's API assumes another validated. Shared internal libraries are blast-radius multipliers:
a bug there is every consumer's bug, so weight them up even at low sink density. And note that
npm/pnpm/yarn-audit only see the **root** lockfile; per-workspace sub-lockfiles need
trivy/osv-scanner, which walk the tree ([tools.md](tools.md)).

## Incremental re-audit (CI / "what changed?")

After a first full or map-driven pass, re-audit only what moved:
```
ultrasec scan --repo . --diff origin/main --merge --resume --out .ultrasec
```
`--diff <ref>`/`--since <commit>` scans only files changed since the ref **plus their
reverse-dependents** (the call sites that reach a changed sink, via the cached graph, 2 hops
deep), and merges into the dossier. Diff-based scanning helps most on large repos,
where each change touches little code. (`--diff` reflects git state, so it is not
reproducible across machines the way a full scan is — the resolved ref is recorded
in the manifest.)

In CI, gate on `check` rather than on the finding count:

```
ultrasec scan  --repo . --diff origin/main --merge --resume --out .ultrasec --offline
ultrasec check --run .ultrasec --min-severity high     # exit 1 fails the job
```

`--min-severity` limits the gate to the tier you want to block on; `--offline` keeps CI off the
advisory feeds (rank by severity, no EPSS/KEV). Cache `~/.cache/ultrasec` and the tree-sitter
grammar cache between runs, or every job pays the cold-start download — and a job that downloads
nothing silently runs on the thinner **regex** extraction tier (`manifest.extraction.ast: false`).
Note that `--diff` is not a substitute for a periodic full pass: it cannot see a bug in code
nobody touched.

## Fan-out (optional, same as deep-audit)

With a subagent harness, run step 3–4 per target in parallel: one analyzer subagent
per scoped target. Subagents stay READ-ONLY (`dossier`, `graph`, `paths`, `tools`)
and return verdict fragments — YOU, the orchestrator, are the sole writer and run
every `--apply` fold yourself. For the verify pass, `orchestrate --run <run>
--phase verify` batches the ids of the ONE emitted `VERIFY.todo.json` into skeptic
subagents (never have a subagent run `verify --shards` — each shard invocation
WRITES into the run dir). Without subagents, the identical commands run in a
sequential loop — same artifacts, only wall-clock differs.

> Per-run emission: `ultrasec orchestrate --run <run>` EMITS the adjudicate/verify/
> revalidate/investigate fan-out (workflows + the dispatch contracts + a sequential
> RUNBOOK) from the run's CURRENT worklists — re-run it after each merged pass so the
> batched ids stay in sync with the dossier.

## What stays the AI's job

The engine narrows the repo and proves the boring half mechanically. Reachability,
exploitability, **which targets matter**, and the non-taint classes
(authorization/IDOR, business logic, auth/session) are yours — see
[catalog.md](catalog.md) for the engine/AI split and
[deep-audit-playbook.md](deep-audit-playbook.md) for the per-target verification loop.

# Deep audit playbook (the agentic tier)

The standard workflow is one `scan` + adjudicate + `check` — fast and
reproducible, a single pass. The **deep tier** grafts a hypothesis-validation
harness onto the same engine: decompose the audit → fan out one analyzer per
facet → merge findings → adversarially verify each → loop until nothing new
surfaces. Slower, but far more thorough and far fewer false positives — this is
the technique that drives SAST false-positive rates down dramatically, *as long
as verification stays conservative* (it also suppresses real bugs if you let it).

The engine stays deterministic and keyless — you supply the judgement
(decomposition, reachability, exploitability, verdicts, completeness); the CLI
supplies determinism (graph, candidate enumeration, tool runs, the worklist, the
gate). No LLM calls and no API keys are added by the engine.

> Compose the deep tier with the dedicated AI stages: `context` to prime the trust
> model, `investigate` to systematically hunt authz/business-logic bugs per
> attack-surface region ([investigate-playbook.md](investigate-playbook.md)), and
> `revalidate` to cut false positives against git history
> ([revalidate-playbook.md](revalidate-playbook.md)). To run the whole loop under an
> external agent CLI, see [powered-mode.md](powered-mode.md) — note `run --powered
> --cross-check <cli>` adds a second adjudicator whose high/critical disagreement
> escalates a finding to needs-human.

## Portability contract

Every step is a plain `ultrasec …` call. Parallel subagents are
an **optimization, not a requirement**:

- **Harness with subagents** (for example Codex or Claude Code): one analyzer subagent per facet,
  and one skeptic subagent per `verify` shard.
- **No subagents**: run the same commands in a sequential loop. Identical
  artifacts; only wall-clock differs.

> `ultrasec orchestrate --run <run>` now EMITS this fan-out ready to launch — the
> analyzer/skeptic contracts below (as `<run>/orchestration/agents/analyzer.md` /
> `skeptic.md`, plus revalidator + hunter), one `<phase>.workflow.mjs` per ready
> worklist with the real item ids batched in, and a sequential `RUNBOOK.md` fallback
> (`--eco`). Subagents return fragments; every `--apply` fold stays with you.

## The loop

0. **(Huge repo?) Map first.** If the repo is too big to scan whole, run
   `map --repo <dir> --out <run>` for a cheap attack-surface recon and drill in
   target-by-target with `scan --scope <dir> --merge` — see
   [scale-audit-playbook.md](scale-audit-playbook.md). Otherwise continue:

1. **Scan once.** `scan --repo <dir> --out <run> --tools auto`. This builds the
   shared link-graph + the candidate dossier + the tool findings everyone reuses.
   `map` first (even when scanning whole) is a fast way to see the entry-point and
   sink clusters before decomposing.

2. **Decompose** into facets — two complementary axes:
   - **By vulnerability class**: the taint classes the engine enumerates (SQLi, command/code
     injection, path traversal, SSRF, deserialization, XSS), the tool output (secrets, deps,
     IaC), and the classes only reasoning finds — **authorization/IDOR, business logic,
     auth/session/JWT, crypto, race conditions, feature abuse, chained attacks** — plus a
     **wildcard** facet and an **obvious-things** sweep. Method per class:
     [attack-classes.md](attack-classes.md); lenses: [hunting-heuristics.md](hunting-heuristics.md).
   - **By entry point / module**: each HTTP route group, CLI, queue consumer,
     webhook — the places untrusted input enters. Use `graph` and `paths` to see
     which files each touches.

3. **Fan out — one analyzer per facet.** `orchestrate --run <run> --phase adjudicate` emits the
   analyzer contract (`<run>/orchestration/agents/analyzer.md`) with the real ids batched and
   absolute paths baked in — **dispatch that**, don't hand-write a prompt. The emitted contract
   is generated from the same source as the apply parser, so its response schema can't drift out
   of sync with what `--apply` accepts; a hand-written one silently can.

4. **Merge.** Collect the facets' fragments. New findings (not in the dossier) go in through
   `investigate --apply` so their citations are checked; for enumerated candidates, collect the
   verdicts for `verify --apply`.

5. **Verify adversarially.** `verify --run <run>` emits the ONE
   `VERIFY.todo.json`; `orchestrate --run <run> --phase verify` batches its ids
   into read-only skeptic subagents (contract + workflow, emitted). Each skeptic
   opens the cited code, tries to **refute** the claim, and RETURNS its verdicts — subagents
   never write. You, the sole writer, merge the fragments and reassemble:
   `verify --apply <fragments> --run <run>` (a directory picks up every
   `*verdict*.json`, sorted).

   **When you run several skeptics over the same finding**, the merge rule is
   *escalate-only*, matching `--cross-check`: take the **least harsh** verdict any skeptic
   returned. One credible `supported` beats two `refuted`s, because a refutation has to be
   positive and cited to count, and disagreement on a high/critical finding is itself a reason to
   leave it for a human. Don't hold a vote — the conservative policy already resolves ties toward
   needs-human.

6. **Gate.** `check --run <run> --semantic`. Fix dangling citations; adjudicate
   leftovers. Re-run until it passes.

7. **Loop until dry.** Did a facet surface a new entry point, a new sink, or a new
   sub-question? If so and you're under budget, fan those out and merge into the
   **same** run, then re-verify only the new claims. Stop when a round surfaces
   nothing new.

8. **Render & present.** `render --run <run>` → `index.html` + tiered Markdown.
   Present the SUMMARY, confirmed findings with exploit paths, and the needs-human
   list.

## Mapping to a workflow primitive

If your harness has an orchestration primitive, the shape is a `pipeline` over the
facets (each: analyze → propose verdicts) feeding a `verify` fan-out (the read-only
skeptic batches `orchestrate --phase verify` emits) into the reassembling
`--apply`, then `check --semantic`. The CLI calls are identical; the primitive
only schedules them.

## Signals to act on

- **Dangling citation** (`check`) — a finding cites code that doesn't resolve:
  hallucinated or stale. Re-open the dossier and fix the location, or drop it.
- **needs-human after apply** — you couldn't confirm or refute a high-severity
  flow. Surface it prominently; do not bury it.
- **A sink with no source** vs **a source with no sink** — the engine only emits a
  candidate when both connect across the graph. If you suspect a flow it missed
  (e.g. taint through a framework callback it can't resolve), add it by hand with
  citations — that's exactly the cross-file reasoning the engine defers to you.

## Budget

Scale to the ask. Cost is dominated by how many candidates you *open* — the engine has already
narrowed the repo, and reading a `dossier` packet is the unit of spend.

| ask | facets | verify | loop |
|---|---|---|---|
| "any obvious bugs" | 3–4 classes, top-`risk` candidates only | one skeptic pass | none |
| standard audit | every enumerated class + the 3–4 non-taint classes the app's trust model makes serious | one skeptic pass over the full worklist | one round |
| "thorough" / "be exhaustive" | every class × every entry-point group | 3 shards, independent skeptics per finding | until dry |

`orchestrate` batches **8 ids per subagent**; that is the granularity to plan around. "Under
budget" at step 7 means you can still afford a full round — a fan-out plus the merge and re-verify
of whatever it surfaces. **"Nothing new"** means a round produced no candidate at a location you
hadn't already adjudicated; a round that only re-derives known findings is dry even if it is
loud. Two consecutive dry rounds is a reasonable stopping rule for an exhaustive audit.

## Second opinion from other models

Another model family misses different things, and the cheapest way to find what your own pass
missed is to ask one that did not watch you look. On one Next.js audit, three external reviewers
(through `kilo`, `vibe` and `opencode`) plus two read-only subagents produced the run's only HIGH
that neither the engine nor the first manual pass had seen — a module-level `debounce` shared
across server-rendered requests — and four confident claims that were false. Both outcomes are
the reason for the protocol below.

`ultrasec council` runs this protocol; the steps below are what it does and why
([commands.md](commands.md) has every flag, [schemas.md](schemas.md) every file).

```bash
ultrasec council --run .ultrasec                    # the plan: which CLIs are installed — ZERO calls
ultrasec council --run .ultrasec --models "kilo:<model>,opencode:<provider/model>,vibe:<model>" --focus "kilo=src/api;opencode=src/web"
ultrasec council --run .ultrasec --apply decisions.json          # after YOU verified each candidate
ultrasec council --run .ultrasec --phase devil --models "vibe:<model>"   # after verify
```

1. **A snapshot, not the repo.** Reviewers work on `git archive HEAD` under `<run>/council/`:
   same line numbers, no untracked `.env`, nothing they can write back into the working tree. Each
   CLI starts with an emptied environment (`HOME`, `PATH`, `TERM=dumb`) — agent allow-lists often
   include `printenv`, and your shell holds tokens — on its read-only agent (`plan` / `--sandbox
   read-only`). opencode always gets `--pure`: a user plugin once replaced its default agent with
   one that delegated to a model that did not exist, and the run stalled without an error.
2. **Blind pass first.** The same brief to every model — the trust model from `CONTEXT.md`, the
   area to cover, and an output contract of one block per finding with `path:line`, attacker
   scenario (who · sends what · gets what), quoted evidence and fix, then what to verify and what
   was not reviewed. The brief is a file in the snapshot and argv only points at it (a 60 KB argv
   prompt hung opencode for eleven minutes). Your findings are **not** shown: a model that has
   read them returns them.
3. **Cap the spend, and plan for the cap.** A budget stop before the final answer loses the whole
   run — one reviewer was cut at its cap with nothing but progress notes. `--max-cost` and
   `--timeout-min` stop a reviewer from its own JSON events, then `council` **resumes the same
   session for one turn**: "stop exploring, no tools, write the report now". The context is already
   paid for; the report costs cents. A quota or credit stop goes to `--fallback` instead (kilo's
   free models — one of which answered 504 "Upstream idle timeout", so the next one gets the turn),
   and `--resume <reviewer>` finishes it after the printed reset time. Do not rely on a CLI's own
   price cap (`vibe --max-price`) until you have seen it stop a run.
4. **Parse, don't read raw.** Every `path:line` is resolved against the snapshot — `ok` or
   `unresolved` with the reason — claims are grouped across reviewers by location and CWE family,
   and a claim landing on a finding the run already holds is reported against that id. Secrets in
   reports and event logs are redacted before anything is written.
5. **Nothing enters the run unverified.** Open every cited line in `COUNCIL.md` yourself, reproduce
   what can be reproduced locally, then `council --apply` your decisions: an accepted candidate goes
   in through the `investigate` citation gate as an `open` `ultrasec-ai` candidate, a rejected one
   is recorded with its reason. Corroboration across families is signal, not proof.
6. **Devil's advocate second.** `--phase devil` hands a model (the one with budget to spare) the
   run's confirmed and needs-human findings — id, severity, status, title, first citations; never a
   message or an evidence line — plus what was rejected and why. Its contestations come back as a
   worklist for `verify`, never applied. Pair it with one fresh read-only subagent: the subagent can
   read `node_modules` and run a library in isolation; the external CLIs on the snapshot cannot, so
   they reason about library behaviour from memory.

What the external reviewers got wrong on that audit, so you know where to look first:

- **Framework behaviour from memory.** "React forwards a lowercase `onclick`/`onerror` to the
  DOM": it drops unknown `on*` props (checked with React's own SSR). Treat any claim about what a
  library or framework does as unverified until you run it.
- **Advisory status offline.** Without network access, "no known-vulnerable pins in the lockfile"
  is a guess; the run's own `pnpm audit` / osv results decide.
- **Deployment facts.** "Source maps are shipped publicly" — the deployed chunk's `.map` was a
  404. Probe the deployed artifact (passively) before asserting what it serves.
- **Severity drift.** External reviewers rate by class name; recalibrate against the trust model
  in `CONTEXT.md` (a CSP without `'unsafe-inline'` turns several "stored XSS" into defense in
  depth).

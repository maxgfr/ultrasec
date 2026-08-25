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

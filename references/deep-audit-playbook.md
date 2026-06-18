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

Every step is a plain `node scripts/ultrasec.mjs …` call. Parallel subagents are
an **optimization, not a requirement**:

- **Harness with subagents** (e.g. Claude Code): one analyzer subagent per facet,
  and one skeptic subagent per `verify` shard.
- **No subagents**: run the same commands in a sequential loop. Identical
  artifacts; only wall-clock differs.

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
   - **By vulnerability class**: SQLi, command/code injection, path traversal,
     SSRF, deserialization, XSS, secrets/deps (tool triage), and the non-taint
     classes only reasoning finds — **authorization/IDOR, business logic, weak
     crypto, SSO/session**.
   - **By entry point / module**: each HTTP route group, CLI, queue consumer,
     webhook — the places untrusted input enters. Use `graph` and `paths` to see
     which files each touches.

3. **Fan out — one analyzer per facet.** Give each subagent a self-contained task
   (it shares none of your context):

   > You are auditing ONE facet of a security review. Run, from the repo root:
   > `node scripts/ultrasec.mjs paths --kind <class> --run <run>` (and `graph`
   > `dossier <id>` as needed). For each relevant candidate, open the cited code,
   > decide if untrusted data really reaches the sink unsanitized and is
   > exploitable, and ALSO look for <class> bugs the engine didn't enumerate.
   > Reply with a JSON array of `{id?, title, severity, cwe, file, line, path,
   > exploitPath, verdict}` — `verdict` ∈ supported|partial|unsupported|refuted.
   > Cite real `[file:line]`. Default to the harsher verdict ONLY when you can
   > disprove it; otherwise mark `partial`/leave for a human.

4. **Merge.** Collect the facets' findings. New findings you discovered (not in
   the dossier) get appended; for enumerated candidates, collect the verdicts.

5. **Verify adversarially.** `verify --run <run> --shards N --shard i` gives each
   skeptic subagent a disjoint slice. Each opens the cited code and tries to
   **refute** the claim; needs ≥ majority to kill. Reassemble:
   `verify --apply <run> --run <run>` (a directory picks up every
   `*verdict*.json`). The conservative policy keeps uncertain high-severity items
   as needs-human.

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
facets (each: analyze → propose verdicts) feeding a `verify` fan-out (skeptic
shards) into the reassembling `--apply`, then `check --semantic`. The CLI calls
are identical; the primitive only schedules them.

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

Scale to the ask. "any obvious bugs" → a few class facets, single-vote verify.
"thorough audit" / "be exhaustive" → every class + every entry point, 3-shard
adversarial verify, a completeness loop. Cost is dominated by how many candidates
you open — the engine has already narrowed the repo for you.

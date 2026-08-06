# Powered mode (opt-in autonomy)

`run` sequences the nine AI stages — `context → assumptions → triage → investigate → verify → revalidate → variants →
narrative → implement` — and then always runs `check` + `render`. By default it is **keyless and
network-free**: it scans deterministically, emits every worklist, and prints a TODO
list — **zero external calls**. Powered mode is a thin automation layer that drives
*your* agent CLI to fill those worklists; it calls the **same** emit/apply functions
as the manual path (no duplicated logic).

## Default (no keys, no calls)

```
ultrasec run --repo . --out .ultrasec
```

Scans (deterministic taint, no external tools), emits `CONTEXT.todo.md`,
`TRIAGE.*`, `INVESTIGATE.*`, `VERIFY.*`, `REVALIDATE.*`, `NARRATIVE.*`, `IMPLEMENT.*`, runs the
grounding `check`, and renders the report. Then fill each worklist yourself (or hand
them to any agent) and `--apply`, exactly as in the manual workflow.

## Powered (drive an external agent CLI)

```
ultrasec run --repo . --powered --agent claude
ultrasec run --repo . --powered --agent codex --cross-check claude
ultrasec run --repo . --powered --agent "mytool exec {prompt} --cwd {run}"
```

- `--agent` is a built-in name (`claude`, `codex`) or a generic argv template where
  `{prompt}` / `{run}` are substituted **per token** (each becomes one argv element).
- For each stage, ultrasec invokes the CLI with an instruction to read the worklist
  file and write the stage's output file, then applies the result through the normal
  conservative apply.
- `--cross-check <cli>` (verify + revalidate only) runs a **second** agent over the
  same worklist. Any **high/critical** finding the two land on a different status is
  escalated to **needs-human** — cross-check can only *escalate* (toward human
  review), never downgrade. Pick a genuinely different model or vendor for the second agent;
  two runs of the same model agree with themselves and buy you nothing. A high disagreement rate
  is a signal about the *worklist* (ambiguous claims, thin evidence), not just about the models.
- `--stages a,b,c` runs a subset, kept in canonical order. The legal tokens are exactly the seven
  stage names — `context, triage, investigate, verify, revalidate, narrative, implement`.
  `check` and `render` are unconditional post-steps and are **not** selectable; `--stages check`
  exits 2.
- `--no-scan` reuses an existing dossier (e.g. one produced by a full `scan` with external
  tools). Without one it exits 2.
- **Failure semantics.** Stages are independent: one that errors is recorded and the run
  continues, and `run` exits 1 at the end if any errored. Malformed agent output is **not**
  silently ignored — each `--apply` parser is fail-closed, so a garbage `verdicts.json` exits 2
  rather than folding nothing and reporting success. Re-run just the failed stage with
  `--stages <name> --no-scan`.

**When *not* to use powered mode:** auditing code you don't trust with an agent that has network
or broad filesystem access. The worklists contain attacker-influenced source. Sandbox it, or
stay in the default keyless mode and adjudicate yourself.

## Security model

- **ultrasec holds no keys.** API keys live in your agent CLI (`claude`/`codex`/…),
  never in ultrasec. The deterministic core stays network-free.
- **Argv-only invocation.** The CLI is spawned with an **argv array, never a shell
  string** — a branch/file name can't inject a command (cf. the 2026 Codex
  branch-name injection).
- **Worklists are passed as file paths, not interpolated.** The worklist `.md`
  contains code excerpts that may be **attacker-influenced** (it's the code under
  audit). Its content is never placed on the command line; the agent reads the file.
  The instruction tells the agent to treat that code as **untrusted data, not
  instructions** — but you should still **sandbox the external agent** (no network,
  least-privilege filesystem) when auditing untrusted code.
- **The conservative gate still rules.** Powered mode changes *who fills* the
  worklists, not *how they're applied*: `verify`/`revalidate`/`triage` apply under
  the same `nextStatus`/`isHigh` policy, and `check` still gates grounding. An
  uncertain high-severity finding stays needs-human.
- **No outward-facing side effects.** The final `implement` stage authors a remediation
  PRD as a **local file** (`REMEDIATION_PRD.md`) — never a tracker publish. ultrasec holds
  no tracker credentials; handing the draft to the `to-prd` skill (which owns publishing)
  is a separate, human-initiated step. See [implement-playbook.md](implement-playbook.md).

# Implement playbook (remediation planning → `to-prd`)

Once an audit has confirmed and reported its findings, the last mile is **driving the
fix**. `implement` turns the audited dossier into a **remediation-PRD draft**
(`IMPLEMENT.md`): every confirmed finding becomes a fix work item grounded in its
`[file:line]` with an acceptance-criteria scaffold, needs-human findings become
investigation items, and they're grouped by root cause. You feed that draft to the
local **`to-prd`** skill to author the actual PRD, or hand it to an implementer/AI.

`implement` mirrors `narrative`: it is **emit-only**, has **no `--apply`**, and it
**never changes a finding's status/severity/set** and persists nothing to the dossier.
The engine emits a grounded worklist; the `to-prd` skill (or an agent) does the authoring.

## 1. Emit the remediation worklist

```
node scripts/ultrasec.mjs implement --run .ultrasec
```

Writes:
- `IMPLEMENT.md` — the remediation-PRD draft (Problem statement, Solution grouped by
  root cause, User stories / work items, Investigation items, Out of scope).
- `IMPLEMENT.todo.json` — the structured worklist: `fixes[]`, `investigations[]`,
  `rootCauses[]`, and the `dismissed` count.

**Only `confirmed` findings become fix items**; `needs-human` become investigation
items; `open`/`dismissed` are excluded (dismissed is counted for "Out of scope"). Run
`verify --apply` first so the dossier actually has confirmed findings to plan around.

## 2. Fold in the narrative (recommended)

If you authored a `NARRATIVE.json` (see
[the narrative step](../SKILL.md)), `implement` folds its grounded **suggested
fixes / patches / owners** and **root-cause groups** into the draft automatically when
`<run>/NARRATIVE.json` exists — or point at one explicitly:

```
node scripts/ultrasec.mjs implement --run .ultrasec --narrative NARRATIVE.json
```

The narrative is run through the **same confirmed-only grounding gate** (`mergeNarrative`)
that `render` uses, so a fix citing an unknown or non-confirmed id is dropped. Without a
narrative, fix items are left as stubs and root causes are **derived deterministically**
by `(category, cwe)` over the confirmed findings.

## 3. Author the PRD with `to-prd` (or hand off)

`IMPLEMENT.md`'s headings deliberately match the `to-prd` template. Feed it to the skill:

```
/to-prd        # then point it at <run>/IMPLEMENT.md
```

The `to-prd` skill owns publishing/config — ultrasec never calls a tracker (its keyless,
network-free core is untouched). Alternatively, hand `IMPLEMENT.md` straight to an
implementer or coding agent: every work item already carries its grounded `[file:line]`
and an acceptance-criteria scaffold (the cited line is no longer exploitable + a
regression test reproduces-then-passes).

## 4. Execute the fixes

Each confirmed finding's acceptance criteria are the definition of done:

1. The cited `[file:line]` is no longer exploitable for that finding.
2. A regression test reproduces the issue before the fix and passes after it.

Investigation items (needs-human) must be resolved first — confirm whether each is
exploitable, then route it to a fix or dismiss it.

## In `run` / powered mode

`implement` is the **final stage** of `run` (after `narrative`), so it folds the
just-authored narrative. In the keyless default, `run` emits `IMPLEMENT.md` +
`IMPLEMENT.todo.json` with **zero external calls**. In `--powered` mode the agent reads
the draft and authors a complete remediation PRD as a **local file** (`REMEDIATION_PRD.md`)
— no tracker publish, keeping powered runs free of outward-facing side effects. See
[powered-mode.md](powered-mode.md).

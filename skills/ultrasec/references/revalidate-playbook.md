# Revalidate playbook (git-history false-positive cut)

A finding can be real *and* already fixed — the code moved, the line was patched, the file was
deleted. Re-checking each promoted finding against git history is a cheap, high-yield
false-positive cut, and it is the pass most audits skip. The engine emits compact, deterministic
**git facts** about each cited location and you decide whether it's still live. The facts come
from the hardened argv `git()` path and degrade gracefully (a non-git repo just yields
`fileExists:false` / `null`).

**Scope:** findings the pipeline already promoted — `status ∈ {confirmed, needs-human}`.
Run it *after* `verify --apply`, before the final `render`.

## 1. Emit the worklist

```
ultrasec revalidate --run .ultrasec
```

Writes `REVALIDATE.todo.json` + `REVALIDATE.md`. Per finding you get:

- `at` — the cited `file:line`.
- `fileExists` — does the file still exist at HEAD?
- `currentLine` — the content of the cited line *now* (or a "drifted/removed" note).
- `commitsSinceFinding` — commits to the file since the finding's provenance commit
  (only when the dossier carries `--blame` provenance; else `null`).
- `lineLastChanged` — the commit/author/date that last touched the cited line.
- `renamedTo` — if the file was deleted, its likely rename target (best-effort).

## 2. Decide a verdict per finding

Set `verdict` to one of:

- `still-valid` — the issue is still present. (If the cited line drifted/removed at
  HEAD, apply keeps it but **flags it for re-confirmation** in the note.)
- `fixed` — the code was patched. Optionally set `fixedIn` to the fixing commit
  (else ultrasec infers it from `lineLastChanged`).
- `false-positive` — it was never a real issue.
- `uncertain` — you can't tell from the facts.

Save as `REVALIDATE.json` (array of `{id, verdict, fixedIn?, note?}` — filled example in
[schemas.md](schemas.md)).

**`fixed` is the verdict that gets over-used.** The facts tell you the line *changed*; only the
code tells you the bug is gone. Before you write `fixed`, rule out all five:

| what you might be seeing | how to tell | verdict |
|---|---|---|
| The line moved, and the bug moved with it | read the current function, not the line — is the sink still fed by the same source? | `still-valid` |
| A reformat, rename or lint pass touched it | the diff changes whitespace/identifiers, not data flow | `still-valid` |
| Fixed on one path, not the others | the finding's route is patched; a sibling route still reaches the same sink | `still-valid`, and note the surviving path |
| The file was deleted | `renamedTo` is best-effort — if it resolves, re-check there; if the code genuinely went away | `fixed` |
| A real fix | you can point at the commit and say what it changed (parameterized, argv-array, guard added) | `fixed` + `fixedIn` |

If you can't tell from the facts alone, that is exactly what `uncertain` is for — it lands
`needs-human`, which is cheaper than a wrong `fixed`.

**Where git facts mislead.** A shallow clone, a squash-merged history or a submodule boundary
makes `lineLastChanged` meaningless or absent; `commitsSinceFinding` is `null` without `--blame`
provenance. Absent facts are not evidence of a fix — default to `still-valid`/`uncertain`.

## 3. Apply (conservative)

```
ultrasec revalidate --apply REVALIDATE.json --run .ultrasec
```

- `still-valid` → kept as-is (flagged if its location drifted).
- `fixed` → **dismissed**, recording `fixedIn = <sha>` and a note.
- `false-positive` → **dismissed** on low/medium/info; on **high/critical** it is
  escalated to **needs-human** (never auto-dismissed — the conservative `isHigh`
  policy, shared with `verify`).
- `uncertain` / unknown → **needs-human**.

Apply never touches `path`/`source`/`sink`/`title`/`severity`. Re-run `check` after.

## Notes

- `revalidate` is most powerful with `--blame` provenance (gives `commitsSinceFinding`)
  and on a real git repo; without git it still surfaces `fileExists`/`currentLine`.
- It's idempotent: a finding already dismissed/escalated is out of scope on re-emit.

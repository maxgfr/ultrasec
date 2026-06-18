# Revalidate playbook (git-history false-positive cut)

deepsec's revalidate pass cuts false positives 50%+ by re-checking each candidate
against git history. ultrasec does the same in its own idiom: the engine emits
compact, deterministic **git facts** about each promoted finding's cited location,
and you decide whether it's still a live issue. The git facts come from the
hardened argv `git()` path and degrade gracefully (a non-git repo just yields
`fileExists:false` / `null`).

**Scope:** findings the pipeline already promoted — `status ∈ {confirmed, needs-human}`.
Run it *after* `verify --apply`, before the final `render`.

## 1. Emit the worklist

```
node scripts/ultrasec.mjs revalidate --run .ultrasec
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

Save as `REVALIDATE.json` (array of `{id, verdict, fixedIn?, note?}`).

## 3. Apply (conservative)

```
node scripts/ultrasec.mjs revalidate --apply REVALIDATE.json --run .ultrasec
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

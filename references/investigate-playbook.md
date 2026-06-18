# Investigate playbook (agentic discovery)

The deterministic engine enumerates source→sink taint candidates, but it can't
reason about **authorization / IDOR, business logic, or subtle multi-hop flows**.
`investigate` closes that gap: the engine emits a worklist organized by
attack-surface **region** (the entry/sink files in a top-level dir plus their 1-hop
graph neighbours), you do the security reasoning, and the engine **ingests** your
grounded discoveries as first-class candidates that flow through `verify`/`check`
like everything else.

## 1. Emit the region worklist

```
node scripts/ultrasec.mjs investigate --run .ultrasec
```

Writes `INVESTIGATE.todo.json` + `INVESTIGATE.md`. Each region lists its files,
graph neighbours, and a hunt prompt. Work the highest-attack-surface regions first.

## 2. Hunt and emit grounded Discovery[]

For each region, read the real code and look for what the engine can't:

- **Broken access control / IDOR** — an endpoint that reads/writes another user's
  object with no ownership check.
- **Missing authorization** — a privileged route with no auth guard.
- **Business-logic flaws** — price/quantity tampering, race conditions, replay.
- **Multi-hop taint** the BFS missed (e.g. through a callback, a queue, or config).

Emit `INVESTIGATE.json` — an array of:

```json
{ "title": "...", "category": "authz", "severity": "high", "cwe": "CWE-862",
  "message": "what the exploit is", "file": "src/x.js", "line": 42,
  "path": [{ "file": "src/r.js", "line": 3, "why": "route, no auth" },
           { "file": "src/x.js", "line": 42, "why": "reads any user's record" }] }
```

`category` is one of taint/sast/dep/secret/config/authz/crypto/other; `severity`
critical…info. Cite **resolvable `[file:line]`** for the primary location and every
path step.

## 3. Apply (ingest)

```
node scripts/ultrasec.mjs investigate --apply INVESTIGATE.json --run .ultrasec
```

- Each discovery becomes an `ultrasec-ai` finding, `status: open`, `confidence: low`
  — recall-oriented; adjudicate it with `verify` like any candidate.
- **Citations are checked first.** An out-of-range or nonexistent `[file:line]`
  (primary or any path step) is **rejected** and reported — so `check` can never
  later fail on an AI-invented line. Don't guess line numbers.
- A discovery at the **same `file:line` (and category+cwe|title)** as an existing
  finding folds into that finding's `sources` (no duplicate) — your independent hit
  corroborates it.

Then continue the normal loop: `dossier <id>` → `verify` → `check` → `render`.

## Citation discipline

`ultrasec-ai` findings are held to the **same grounding bar** as everything else
(see [citation-format.md](citation-format.md)). The whole point of ingesting them
through the engine is that ultrasec's conservative gate, not the model's
confidence, decides what ships.

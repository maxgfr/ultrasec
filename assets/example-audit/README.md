# Example audit dossier

A complete `ultrasec` run over a deliberately vulnerable cross-file Express app
(`tests/fixtures/vuln-express`), committed so you can see the artifacts without
running anything. Paths are sanitized to `examples/vuln-express`.

Pipeline that produced it (the full AI-stage flow):

```
ultrasec context    --repo examples/vuln-express --out .   # → CONTEXT scaffold; author CONTEXT.md
ultrasec scan       --repo examples/vuln-express --out . --tools none
ultrasec verify     --run .                 # → VERIFY.todo.json + VERIFY.md
# (the AI adjudicates each candidate, writing verdicts.json)
ultrasec verify     --apply verdicts.json --run .
ultrasec revalidate --run .                 # → REVALIDATE.* (git-history false-positive cut)
ultrasec revalidate --apply REVALIDATE.json --run .
ultrasec check      --run . --semantic      # exit gate: grounded + adjudicated
ultrasec narrative  --run .                 # → author NARRATIVE.json (exec summary, fixes, chains)
ultrasec render     --run . --narrative NARRATIVE.json   # → SUMMARY/REPORT/FULL.md + index.html
ultrasec implement  --run . --narrative NARRATIVE.json   # → IMPLEMENT.md (remediation-PRD draft) + IMPLEMENT.todo.json
```

Files:

| file | what |
|------|------|
| `CONTEXT.md` | the project-context primer the agent authored (trust model, framework protections) — injected into every dossier + worklist |
| `DOSSIER.md` | the always-loadable index of candidates the AI reads first |
| `findings.json` | every finding (after verdicts applied) |
| `graph.json` | the cross-file link-graph |
| `manifest.json` | run metadata + severity counts |
| `VERIFY.todo.json` / `VERIFY.md` | the adversarial worklist |
| `verdicts.json` | the adjudication the AI produced |
| `REVALIDATE.todo.json` / `REVALIDATE.md` | per-finding git facts for the false-positive cut |
| `REVALIDATE.json` | the revalidation verdicts the AI produced |
| `NARRATIVE.json` | the AI-authored report narrative (exec summary, per-fix, attack chains, root causes) |
| `SUMMARY.md` / `REPORT.md` / `FULL.md` | the tiered report (with clearly-marked AI sections) |
| `index.html` | self-contained report (open in a browser) |
| `IMPLEMENT.md` | the remediation-PRD draft (fix story per confirmed finding, grouped by root cause) — feed to the `to-prd` skill |
| `IMPLEMENT.todo.json` | the structured remediation worklist (fixes, investigations, root causes) |

Three cross-file flows were **confirmed** (OS command injection, SQL injection,
reflected XSS), all judged **still-valid** by the git-history revalidation pass —
and the report carries an AI-authored executive summary, per-finding fixes, an
attack chain, and a root-cause grouping (each marked "AI-authored", grounding-
checked against the confirmed findings).

`IMPLEMENT.md` then turns those three confirmed flows into a remediation-PRD draft —
one fix story each (grounded in its `[file:line]`, with the suggested fix folded from
the narrative and an acceptance-criteria scaffold), grouped under their shared root
cause — ready to feed to the `to-prd` skill.

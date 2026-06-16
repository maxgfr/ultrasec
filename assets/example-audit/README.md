# Example audit dossier

A complete `ultrasec` run over a deliberately vulnerable cross-file Express app
(`tests/fixtures/vuln-express`), committed so you can see the artifacts without
running anything. Paths are sanitized to `examples/vuln-express`.

Pipeline that produced it:

```
ultrasec scan   --repo examples/vuln-express --out . --tools none
ultrasec verify --run .                 # → VERIFY.todo.json + VERIFY.md
# (the AI adjudicates each candidate, writing verdicts.json)
ultrasec verify --apply verdicts.json --run .
ultrasec check  --run . --semantic      # exit gate: grounded + adjudicated
ultrasec render --run .                 # → SUMMARY/REPORT/FULL.md + index.html
```

Files:

| file | what |
|------|------|
| `DOSSIER.md` | the always-loadable index of candidates the AI reads first |
| `findings.json` | every finding (after verdicts applied) |
| `graph.json` | the cross-file link-graph |
| `manifest.json` | run metadata + severity counts |
| `VERIFY.todo.json` / `VERIFY.md` | the adversarial worklist |
| `verdicts.json` | the adjudication the AI produced |
| `SUMMARY.md` / `REPORT.md` / `FULL.md` | the tiered report |
| `index.html` | self-contained report (open in a browser) |

Two cross-file flows were **confirmed** (SQL injection, OS command injection)
and one candidate **dismissed** after review (reflected-XSS false positive) —
demonstrating the conservative verify gate.

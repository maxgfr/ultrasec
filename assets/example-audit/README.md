# Example audit dossier

A complete `ultrasec` run over a deliberately vulnerable cross-file Express app
(`tests/fixtures/vuln-express`), committed so you can see the artifacts without
running anything. Paths are sanitized to `examples/vuln-express` and the version is
pinned, so a release bump doesn't churn the example.

**Generated, not hand-maintained:**

```bash
node scripts/build-example-audit.mjs           # regenerate
node scripts/build-example-audit.mjs --check   # CI gate: fails if stale
```

The script copies the fixture into a throwaway git repo, runs the pipeline, and folds
in the four **authored** inputs kept under version control here — `CONTEXT.md`,
`verdicts.json`, `REVALIDATE.json`, `NARRATIVE.json`. Those are the parts a human or an
AI writes; everything else is engine output.

Pipeline:

```
ultrasec scan       --repo examples/vuln-express --out run --tools none --offline
ultrasec verify     --run run                      # → VERIFY.todo.json + VERIFY.md
#   (the AI adjudicates each candidate → verdicts.json)
ultrasec verify     --apply verdicts.json --run run
ultrasec revalidate --run run                      # git facts per promoted finding
ultrasec revalidate --apply REVALIDATE.json --run run
ultrasec check      --run run --semantic           # exit gate: grounded + adjudicated
ultrasec narrative  --run run                      # → author NARRATIVE.json
ultrasec render     --run run --narrative NARRATIVE.json
ultrasec implement  --run run --narrative NARRATIVE.json
```

| file | what |
|------|------|
| `CONTEXT.md` | **authored** — the project-context primer (trust model, framework protections), injected into every dossier + worklist |
| `manifest.json` | run metadata, severity counts, and the extraction tier the scan actually used |
| `DOSSIER.md` | the always-loadable index of candidates the AI reads first |
| `findings.json` | every finding, after verdicts applied |
| `graph.json` | the cross-file link-graph |
| `VERIFY.todo.json` / `VERIFY.md` | the adversarial worklist |
| `verdicts.json` | **authored** — the adjudication |
| `REVALIDATE.todo.json` / `REVALIDATE.md` | per-finding git facts for the false-positive cut |
| `REVALIDATE.json` | **authored** — the revalidation verdicts |
| `NARRATIVE.todo.json` / `NARRATIVE.md` | the report-narrative worklist |
| `NARRATIVE.json` | **authored** — exec summary, positive patterns, fixes, attack chain, root causes, hardening notes |
| `SUMMARY.md` / `REPORT.md` | the tiered report (AI sections clearly marked) |
| `index.html` | self-contained report (open in a browser) |
| `IMPLEMENT.md` | the remediation-PRD draft — feed to the `to-prd` skill |
| `IMPLEMENT.todo.json` | the structured remediation worklist |

## What the example demonstrates

Three candidates, **two confirmed** — and the third is the point.

- **CRITICAL** OS command injection, `server.js:18 → server.js:19 → report.js:5`.
- **HIGH** SQL injection, `server.js:10 → server.js:11 → db.js:6`. Its parameterized
  sibling `getUserSafe` (`db.js:11`) is correctly never enumerated.
- **MEDIUM** reflected XSS — **`unsupported`**. The engine linked `req.query.name` on
  `server.js:18` to `res.send()` on `server.js:20`, but the argument to `res.send` is
  `out`, the *return value* of `runReport()`, not the query parameter. The attacker does
  control that output — by way of the command injection, whose RCE impact subsumes it.
  Reporting a separate XSS would double-count one bug.

That third verdict is the false-positive shape `references/adjudication.md` calls FP-6,
and working it through — rather than refuting it and moving on, or confirming it because
the path looks plausible — is what the adjudication step is for.

Both confirmed findings were judged **still-valid** by the git-history revalidation
pass, and `IMPLEMENT.md` turns them into two fix stories grouped under their shared root
cause, each with the acceptance criteria and the suggested patch from the narrative.

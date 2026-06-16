# Audit playbook (standard single pass)

The everyday workflow: narrow the repo to a handful of evidence-backed
candidates, adjudicate each from the real code, gate, and report.

## 1. (Optional) install scanners

```
node scripts/ultrasec.mjs tools
```

Install the highest-leverage ones for the stack — **Trivy** (deps + secrets +
IaC across ecosystems) covers the most ground; add `gitleaks` for secrets,
`osv-scanner` for lockfile CVEs, `opengrep`/`semgrep` for rule-based SAST, and the
language-native ones (`cargo-audit`, `govulncheck`, `pip-audit`) as relevant.
Everything works without them — they're an automatic bonus.

## 2. Scan

```
node scripts/ultrasec.mjs scan --repo . --out .ultrasec        # auto-runs installed tools
node scripts/ultrasec.mjs scan --repo . --out .ultrasec --tools none   # graph + taint only
```

Writes the audit dossier. Scope with `--include`/`--exclude` globs on a big repo.

## 3. Read the dossier, then adjudicate each candidate

```
node scripts/ultrasec.mjs paths --run .ultrasec               # the candidate chains
node scripts/ultrasec.mjs dossier <id> --run .ultrasec        # the grounding packet
```

For each candidate, the four questions (answer from the code in the packet):

1. **Source** — is it genuinely attacker-controlled (request, CLI, env, file, queue)?
2. **Propagation** — does the tainted value reach the sink through every hop, unchanged?
3. **Sanitizer/guard** — is it parameterized / escaped / validated / authz-checked anywhere on the path?
4. **Sink** — is it exploitable with the value that arrives? Write the concrete trigger.

Then look for what taint enumeration can't: **broken access control / IDOR,
missing authorization, business-logic abuse, weak crypto, unsafe config**. Add
them as findings with `[file:line]` citations (edit `findings.json`, or note them
for the report).

## 4. Verify and gate

```
node scripts/ultrasec.mjs verify --run .ultrasec              # → VERIFY.todo.json + VERIFY.md
# write verdicts.json: [{ "id": "...", "verdict": "supported", "note": "...", "exploitPath": "..." }, ...]
node scripts/ultrasec.mjs verify --apply verdicts.json --run .ultrasec
node scripts/ultrasec.mjs check --run .ultrasec --semantic    # exit 0 only when grounded + adjudicated
```

`supported`→confirmed, `refuted`→dismissed. `unsupported`/`partial` on a
high/critical finding becomes **needs-human** — not dropped. Don't refute a
high-severity finding you can't actually disprove.

## 5. Render and present

```
node scripts/ultrasec.mjs render --run .ultrasec              # SUMMARY/REPORT/FULL.md + index.html
```

Present: the SUMMARY counts, each confirmed finding with its cross-file path and
exploit path, the needs-human list, and the run folder. See
[citation-format.md](citation-format.md) for how findings are cited.

For a thorough/high-assurance audit, escalate to
[deep-audit-playbook.md](deep-audit-playbook.md).

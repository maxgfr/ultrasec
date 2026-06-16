# ultrasec

> Cross-file security audit for whole repos — trace untrusted data across
> functions and files, orchestrate best-in-class OSS scanners, and adversarially
> verify every finding into a cited, tiered report.

`ultrasec` is an [agent skill](https://skills.sh) in the `ultra*` family
(sibling of [ultraindex](https://github.com/maxgfr/ultraindex) and
[ultrasearch](https://github.com/maxgfr/ultrasearch)). It follows the same
division of labour:

- a **deterministic, zero-dependency engine** (`scripts/ultrasec.mjs`, run with
  `node`, no `npm install`, no API keys) does the mechanical work — scan the
  repo, build a **cross-file/function link-graph**, enumerate candidate
  **source→sink taint paths**, run + normalize whatever external scanners are
  installed, and assemble per-finding **evidence packets**;
- the **AI** does the security reasoning — judge which candidate flows are real
  and exploitable across files, find the subtle authz/business-logic bugs the
  tools miss, and **adversarially verify** each finding (conservatively — an
  uncertain high-severity stays `needs-human`, never auto-dismissed).

Why it exists: deterministic engines that do cross-file taint (CodeQL global
flow, Semgrep Pro, Joern) are precise but gate it behind paywalls and miss
business-logic flaws; pure-LLM scanners hallucinate and are diff-scoped.
`ultrasec` occupies the middle ground — an **explicit cross-file link-graph**
plus **adversarial AI verification** — and stays whole-repo and anti-hallucinating
(every finding must cite resolvable `[file:line]` hops).

## Quick start

```bash
node scripts/ultrasec.mjs tools                       # installed scanners + how to get the rest
node scripts/ultrasec.mjs scan --repo . --out .ultrasec   # graph + cross-file taint + tools → dossier
node scripts/ultrasec.mjs paths --run .ultrasec       # the candidate source→sink chains
node scripts/ultrasec.mjs dossier <id> --run .ultrasec    # one finding's real code + path (adjudicate)
node scripts/ultrasec.mjs verify --run .ultrasec      # adversarial worklist → write verdicts.json
node scripts/ultrasec.mjs verify --apply verdicts.json --run .ultrasec
node scripts/ultrasec.mjs check --run .ultrasec --semantic   # exit gate: grounded + adjudicated
node scripts/ultrasec.mjs render --run .ultrasec      # SUMMARY/REPORT/FULL.md + index.html
```

Nothing external is required — the link-graph and taint reasoning are the
always-on core. Installed scanners (Trivy, OpenGrep/Semgrep, gitleaks,
osv-scanner, cargo-audit, govulncheck, …) are an automatic bonus, normalized into
one finding model.

See [`assets/example-audit/`](assets/example-audit/) for a complete run, and
[`SKILL.md`](SKILL.md) + [`references/`](references/) for the agent workflow
(including the [deep-audit playbook](references/deep-audit-playbook.md)).

## How it works

| stage | who | what |
|-------|-----|------|
| scan | engine | walk repo → cross-file/function link-graph (~15 langs) → enumerate candidate source→sink taint paths → run installed scanners → evidence packets |
| adjudicate | **AI** | read the real code along each path; confirm reachability + exploitability; find authz/business-logic bugs the tools miss |
| verify | **AI** + engine | adversarial worklist, conservative gate (uncertain high-severity → `needs-human`, never auto-dropped) |
| report | engine | grounded, cited, tiered Markdown + self-contained HTML |

## Development

```bash
pnpm install
pnpm typecheck && pnpm test && pnpm run check:build   # the CI gate
```

Releases are automatic: Conventional Commits on `main` drive semantic-release
(GitHub release + tarball).

## License

MIT


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
node scripts/ultrasec.mjs tools          # what scanners are installed + how to get the rest
node scripts/ultrasec.mjs scan --repo .  # build the audit dossier
node scripts/ultrasec.mjs check --run .ultrasec --semantic   # the grounding gate
```

Nothing external is required — the link-graph and AI taint reasoning are the
always-on core. Installed scanners (Trivy, OpenGrep/Semgrep, gitleaks,
osv-scanner, cargo-audit, govulncheck, …) are an automatic bonus.

## Status

Under active construction. See the milestones in the repo's plan.

## License

MIT

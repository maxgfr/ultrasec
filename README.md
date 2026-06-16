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

## Install

**As an agent skill** (Claude Code, Cursor, … via [skills.sh](https://skills.sh)):

```bash
npx skills add maxgfr/ultrasec
```

This drops `SKILL.md` + the `references/` + the committed `scripts/ultrasec.mjs`
bundle into your agent's skills directory. Your agent then triggers it on
"audit this repo for security", "find vulnerabilities", etc.

**Standalone** (just the CLI — no agent needed):

```bash
git clone https://github.com/maxgfr/ultrasec && cd ultrasec
node scripts/ultrasec.mjs --help          # the committed bundle runs as-is (zero deps, Node >= 18)
```

**From the release tarball:** grab `ultrasec-<version>.tgz` from the
[latest release](https://github.com/maxgfr/ultrasec/releases), `tar xf` it, and
run `node package/scripts/ultrasec.mjs`.

No `npm install`, no API keys — the engine is a single dependency-free bundle.
External scanners are optional and auto-detected (see [Docker](#analysis-tools-via-docker) below).

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

## Analysis tools via Docker

ultrasec orchestrates best-in-class OSS scanners and normalizes their output into
one finding model. You don't have to install any of them — two Docker paths:

**1. `--docker` (zero install).** ultrasec runs each scanner from its official,
version-pinned image on demand, with your repo bind-mounted at `/work`:

```bash
node scripts/ultrasec.mjs scan --repo . --out .ultrasec --docker
# runs, via docker: trivy, gitleaks, osv-scanner, semgrep — whatever has an image
node scripts/ultrasec.mjs scan --repo . --docker --tools trivy,gitleaks   # pick a subset
```

Only Docker is required. Reported paths are rewritten from `/work` back to
repo-relative automatically. Pinned images: `ghcr.io/aquasecurity/trivy:0.71.1`,
`ghcr.io/gitleaks/gitleaks:v8.30.1`, `ghcr.io/google/osv-scanner:v2.3.8`,
`semgrep/semgrep:1.166.0`.

**2. Toolbox image (everything baked in).** Build one image with the engine + all
bundled scanners and run the whole audit inside it:

```bash
docker compose build
TARGET=/path/to/repo docker compose run --rm ultrasec scan --repo /work --out /work/.ultrasec
TARGET=/path/to/repo docker compose run --rm ultrasec tools     # all show ✓ installed
```

See [`references/tools.md`](references/tools.md) for the full scanner matrix and
recommended additions (trufflehog, checkov, syft, bandit, brakeman).

## Tested on real projects

ultrasec's cross-file taint engine was run on real, intentionally-vulnerable repos
(graph + taint only, `--tools none`):

| repo | lang | what it surfaced |
|------|------|------------------|
| [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat) | JS | 13 candidates incl. the signature **server-side `eval()` injection** (`eval(req.body.…)`, CWE-94), **command injection** in the Gruntfile (CWE-78), **open redirects** in `session.js` (CWE-601), reflected **XSS** in `research.js` (CWE-79) |
| [we45/Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App) | Python | **SQLi** (CWE-89), **insecure deserialization** (CWE-502), **path traversal** (CWE-22), **SSTI/XSS** via `render_template_string` (CWE-79), **weak crypto** `md5` (CWE-327) |

And the external-tool path, validated live via `--docker`: a planted GitHub PAT +
API key were found by dockerized **gitleaks** and normalized to `CWE-798` findings
with repo-relative locations. Each candidate is then adjudicated by the AI and the
grounding gate (`check --semantic`) before it counts.

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


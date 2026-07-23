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
  installed, **correlate** their findings across tools (one issue, not three),
  **rank** every finding by composite **EPSS · CISA KEV · CVSS risk**, and
  assemble per-finding **evidence packets**;
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
node scripts/ultrasec.mjs context --repo . --out .ultrasec   # project-context primer → author CONTEXT.md
node scripts/ultrasec.mjs scan --repo . --out .ultrasec   # graph + cross-file taint + tools → dossier
node scripts/ultrasec.mjs triage --run .ultrasec      # cheap noise/keep fast-lane (apply: --apply TRIAGE.json)
node scripts/ultrasec.mjs dossier <id> --run .ultrasec    # one finding's real code + path (adjudicate)
node scripts/ultrasec.mjs investigate --run .ultrasec     # hunt authz/business-logic; ingest grounded Discovery[]
node scripts/ultrasec.mjs verify --run .ultrasec      # adversarial worklist → write verdicts.json
node scripts/ultrasec.mjs verify --apply verdicts.json --run .ultrasec
node scripts/ultrasec.mjs revalidate --run .ultrasec  # git-history false-positive cut (apply: REVALIDATE.json)
node scripts/ultrasec.mjs check --run .ultrasec --semantic   # exit gate: grounded + adjudicated
node scripts/ultrasec.mjs narrative --run .ultrasec   # author NARRATIVE.json (exec summary, fixes, chains)
node scripts/ultrasec.mjs render --run .ultrasec --narrative NARRATIVE.json   # SUMMARY/REPORT/FULL.md + index.html
node scripts/ultrasec.mjs implement --run .ultrasec   # remediation-PRD draft (IMPLEMENT.md) → feed to the to-prd skill
```

`context`, `triage`, `investigate`, `revalidate`, `narrative`, `implement` are additive — a quick
audit can skip them. To sequence the whole pipeline (and, opt-in, drive your own agent
CLI to fill the worklists), use `run`:

```bash
node scripts/ultrasec.mjs run --repo . --out .ultrasec    # emits every worklist + a TODO; ZERO external calls
node scripts/ultrasec.mjs run --repo . --powered --agent claude --cross-check codex   # autonomous (keys live in the CLI)
```

Nothing external is required — the link-graph and taint reasoning are the
always-on core. Installed scanners (Trivy, OpenGrep/Semgrep, gitleaks,
osv-scanner, cargo-audit, govulncheck, **grype, pip-audit, npm/pnpm/yarn audit,
package-checker, bandit, gosec, checkov, hadolint, kingfisher**, …) are an
automatic bonus, normalized into one finding model, **de-duplicated across
tools**, and **risk-ranked** (EPSS exploit-probability + CISA KEV + CVSS). Risk
scoring uses cached, offline-friendly feeds — add `--no-enrich`/`--offline` to
skip the network and rank by severity alone. When `syft` is installed, `scan`
also emits a CycloneDX SBOM (`sbom.cdx.json`) as a dossier deliverable, fed
straight into grype (`sbom:` mode) and package-checker (`--source`).

See [`assets/example-audit/`](assets/example-audit/) for a complete run, and
[`SKILL.md`](skills/ultrasec/SKILL.md) + [`references/`](skills/ultrasec/references/) for the agent workflow
(including the [deep-audit playbook](skills/ultrasec/references/deep-audit-playbook.md)).

### Large repos (millions–billions of LOC)

Don't scan the whole tree — **map the attack surface, then drill in under a budget**:

```bash
node scripts/ultrasec.mjs map  --repo . --out .ultrasec                       # rank targets by sink density
node scripts/ultrasec.mjs scan --repo . --scope <dir> --merge --resume --out .ultrasec   # drill one target into the same run
node scripts/ultrasec.mjs scan --repo . --diff origin/main --merge --resume --out .ultrasec  # incremental: only changed files + reverse-deps
```

`--scope`/`--include`/`--exclude`/`--max-files`/`--gitignore` prune the walk;
`--budget quick|standard|thorough` (and `--max-candidates`/`--max-depth`)
rank-then-cap candidates (truncation is reported, never silent); `--merge` folds a
scoped pass into one dossier (preserving prior verdicts); `--resume` reuses a
content-hashed scan cache. Full loop: [scale-audit playbook](skills/ultrasec/references/scale-audit-playbook.md).

## Extra recall, provenance & deepsec interop

Three opt-in additions, all keeping the zero-dependency / no-API-key core intact:

```bash
node scripts/ultrasec.mjs scan --repo . --sinks --out .ultrasec   # orphan-sink recall
node scripts/ultrasec.mjs scan --repo . --blame --out .ultrasec   # git-blame + CODEOWNERS provenance
node scripts/ultrasec.mjs import findings.json --run .ultrasec    # ingest a deepsec export
```

- **`--sinks` (orphan-sink recall).** The taint pass only emits a finding when it can
  connect a dangerous sink *back* to an untrusted source. `--sinks` adds every sink it
  **can't** connect (single-file scripts, framework dispatch the summary-graph misses,
  config-fed sinks) as a low-confidence `sast` candidate — capped and truncation-reported
  like taint, adjudicated the same way.
- **`--blame` (provenance).** Attaches deterministic git-blame author/commit/author-date +
  CODEOWNERS owner to each finding — a triage signal ("introduced last week by X, owned by
  team Y"). Reproducible (author-date, not wall-clock) and **evidence only**: it never culls
  a finding by age.
- **`import` (deepsec interop).** [vercel-labs/deepsec](https://github.com/vercel-labs/deepsec)
  is an agent-powered scanner that drives its *own* LLM. Rather than vendor it (it needs API
  keys + an Apache-2.0 dependency, against ultrasec's grain), ultrasec **ingests its output**:
  run `deepsec export --format json` yourself, then `ultrasec import` maps each finding into
  the unified model, correlates it against the engine/scanner findings, risk-ranks it, and
  runs it through the same `[file:line]` grounding gate and conservative verify flow — making
  ultrasec the deterministic referee over deepsec's non-deterministic agent output. No keys,
  no Vercel, no deepsec process spawned by ultrasec. Correlation goes deeper than dedup: a
  deepsec hit whose `file:line` lands on a node of an engine **taint path** corroborates that
  flow in place (its `sources` gains `deepsec`, confidence bumps, the path is untouched), and
  deepsec's revalidation reasoning/verdict is carried as a clearly-labelled **`priorAnalysis`
  signal** (shown in the dossier + verify worklist, but it never changes a status — your
  verify gate does).

## Log forensics (blue team)

`logs <path…>` is a separate, read-only pipeline over *existing* log files
(nginx/access, JSON-lines, syslog/auth, raw) — deterministic attack-signature
and behavioral detection (SQLi/XSS/traversal/brute-force/request-burst/scan
behavior…) plus redacted secret/PII leak findings, into its own dossier:

```bash
node scripts/ultrasec.mjs logs ./var/log --out .ultrasec-logs
```

See [references/log-forensics-playbook.md](skills/ultrasec/references/log-forensics-playbook.md).

## The tool belt

Every scanner ultrasec knows how to drive, normalized into one finding model and
correlated (the same advisory seen by three tools becomes one multi-source
finding). Everything degrades gracefully: not installed ⇒ skipped with a note,
`scan --offline` skips the network-dependent audits, and `ultrasec tools` shows
the live status of each.

| Tool | Covers | Needs |
|---|---|---|
| `package-checker` | dependencies — 12 ecosystems (npm/yarn/pnpm/bun/deno, PyPI, Go, Cargo, RubyGems, Composer, Maven/Gradle, NuGet, Pub, Hex, Swift, GitHub Actions) against GHSA/OSV feeds | **nothing** — fetches upstream's latest [release](https://github.com/maxgfr/package-checker.sh) at scan time (sha-cached); falls back to a vendored, sha256-pinned copy offline/on any resolution failure, auto-bumped by a scheduled PR (`ULTRASEC_PACKAGE_CHECKER_PINNED=1` forces the pinned copy); just bash+awk+curl |
| `trivy` | dependencies/CVE + secrets + misconfig | install or `--docker` |
| `osv-scanner` | dependencies (Google OSV, lockfile-driven) | install or `--docker` |
| `grype` | dependencies (Anchore; consumes the Syft SBOM when present) | install |
| `npm-audit` / `pnpm-audit` / `yarn-audit` | dependencies — the package manager's own registry audit of the detected lockfile | npm/pnpm/yarn on PATH; network (skipped `--offline`) |
| `pip-audit` | Python dependencies (`requirements.txt`) | install; network |
| `cargo-audit` | Rust dependencies (`Cargo.lock`, RustSec) | install |
| `govulncheck` | Go dependencies, reachability-aware | install |
| `syft` | SBOM generator — CycloneDX deliverable (`sbom.cdx.json`), cross-fed to grype and package-checker | install |
| `semgrep` / `opengrep` | SAST rules | install (semgrep also `--docker`) |
| `bandit` / `gosec` | SAST (Python / Go) | install or `--docker` |
| `gitleaks` / `kingfisher` | secrets | install (gitleaks also `--docker`) |
| `checkov` / `hadolint` | IaC / Dockerfile misconfig | install or `--docker` |

**Latest-first, everywhere.** ultrasec never asks you to manually chase a scanner
version: `--docker` runs always pull each image's rolling `latest` tag
(`--pull always`, so a stale cache is never silently reused), `package-checker`
resolves upstream's latest release at every scan (vendored, sha256-pinned
fallback), and `node scripts/ultrasec.mjs tools --upgrade [--dry-run]` completes
the story for natively-installed binaries — it infers which package manager
(brew/pipx/go/cargo/corepack/npm) put each installed tool there from its own
binary path and drives that manager's real upgrade command (apt-owned or
unrecognized origins print a hint instead; ultrasec never runs `sudo`). See
[`references/tools.md`](skills/ultrasec/references/tools.md#keeping-native-tools-fresh-tools---upgrade)
for the full origin-inference table.

## Analysis tools via Docker

ultrasec orchestrates best-in-class OSS scanners and normalizes their output into
one finding model. You don't have to install any of them — two Docker paths:

**1. `--docker` (zero install).** ultrasec runs each scanner from its official
image's rolling `latest` tag on demand (`--pull always`, so a stale cached
`latest` is never silently reused — this trades reproducibility for always-current
CVE/rule coverage), with your repo bind-mounted at `/work`:

```bash
node scripts/ultrasec.mjs scan --repo . --out .ultrasec --docker
# runs, via docker: trivy, gitleaks, osv-scanner, semgrep, bandit, gosec,
# checkov, hadolint — whatever has an official image
node scripts/ultrasec.mjs scan --repo . --docker --tools trivy,gitleaks   # pick a subset
```

Only Docker is required. Reported paths are rewritten from `/work` back to
repo-relative automatically. Images (all track `:latest`):
`ghcr.io/aquasecurity/trivy`, `ghcr.io/gitleaks/gitleaks`,
`ghcr.io/google/osv-scanner`, `semgrep/semgrep`, `ghcr.io/pycqa/bandit/bandit`,
`ghcr.io/securego/gosec`, `bridgecrew/checkov`, `hadolint/hadolint`.

**2. Toolbox image (everything baked in).** Build one image with the engine + the
bundled scanners and run the whole audit inside it — trivy, gitleaks, osv-scanner,
semgrep, gosec, hadolint, bandit, checkov, **grype, syft, pip-audit**. Every tool
installs its latest release by default (each has an optional `--build-arg
<TOOL>_VERSION=x.y.z` to pin it instead — see `docker/Dockerfile`); image
freshness is therefore the freshness of the last build:

```bash
docker compose build
docker compose build --no-cache   # refresh: re-resolve every tool's latest release
TARGET=/path/to/repo docker compose run --rm ultrasec scan --repo /work --out /work/.ultrasec
TARGET=/path/to/repo docker compose run --rm ultrasec tools     # the baked-in tools show ✓ installed
```

See [`references/tools.md`](skills/ultrasec/references/tools.md) for the full scanner matrix,
the correlation/risk-scoring layers, and recommended additions (GuardDog for
malicious packages, TruffleHog for live secret verification, cppcheck for C/C++).

## Cleanup

ultrasec never installs anything globally, and you can remove everything it
created — straight from the script — when you're done:

```bash
node scripts/ultrasec.mjs clean --run .ultrasec            # remove the audit dossier
node scripts/ultrasec.mjs clean --run .ultrasec --docker   # + pulled scanner images, toolbox image, trivy cache volume
node scripts/ultrasec.mjs clean --docker --dry-run         # preview what would be removed
```

`clean --docker` removes only the artifacts ultrasec is responsible for (the
scanner images, `ultrasec-toolbox`, and the `*trivy-cache*` volume) — your
other Docker images are untouched. The compose stack tears down the same way with
`docker compose down -v`.

## Tested on real projects

Validated **end-to-end inside the Docker toolbox** (engine + trivy + osv-scanner +
semgrep + gitleaks, all four scanners) on real, intentionally-vulnerable repos:

| repo | lang | findings (taint + tools) | highlights |
|------|------|--------------------------|------------|
| [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat) | JS | **275** — 13 taint · 262 tool (trivy 67, osv 163, semgrep 29, gitleaks 3) | the signature server-side **`eval()` SSJI** (`eval(req.body.…)`, CWE-94), **command injection**, **open redirects**, reflected **XSS** — plus dependency CVEs, hardcoded secrets (incl. a private key), and SAST findings |
| [we45/Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App) | Python | **206** — 6 taint · 200 tool (trivy 69, osv 110, semgrep 21) | **SQLi**, **insecure deserialization**, **path traversal**, **SSTI**, **weak crypto** (CWE-89/502/22/79/327) — plus Python dep CVEs and SAST |

Every finding's path is repo-relative and the grounding gate (`check`) passes over
all of them; each is then adjudicated by the AI before it counts as confirmed.
Reproduce:

```bash
TARGET=/path/to/repo docker compose run --rm ultrasec scan --repo /work --out /work/.ultrasec
```

## How it works

| stage | who | what |
|-------|-----|------|
| scan | engine | walk repo → cross-file/function link-graph (~15 langs) → enumerate candidate source→sink taint paths → run installed scanners → correlate across tools → EPSS/KEV/CVSS risk-rank → evidence packets |
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


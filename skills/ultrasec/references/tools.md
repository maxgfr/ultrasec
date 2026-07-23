# External scanner orchestration

ultrasec runs whatever scanners are installed and normalizes their JSON into the
unified `Finding` model (category · cwe · severity · file:line · message ·
references). Nothing is required — the link-graph + taint reasoning is the
always-on core. `node scripts/ultrasec.mjs tools` shows status + install hints.

| tool | category | what it adds | install |
|------|----------|--------------|---------|
| **trivy** | dep + secret + config | CVEs (SCA), hardcoded secrets, IaC/misconfig across most ecosystems — highest leverage | `brew install trivy` |
| **opengrep** | sast | free Semgrep fork with cross-function taint | see opengrep.dev |
| semgrep | sast | rule + dataflow SAST (cross-file taint is Pro) | `brew install semgrep` |
| gitleaks | secret | hardcoded secrets (git history when present, else working tree) | `brew install gitleaks` |
| osv-scanner | dep | OSV.dev lockfile CVEs | `brew install osv-scanner` |
| grype | dep | Anchore SBOM-based CVEs (pairs with the SBOM a run already generates) | `brew install grype` |
| cargo-audit | dep | RustSec advisories (Cargo.lock) | `cargo install cargo-audit` |
| govulncheck | dep | reachability-aware Go vulns | `go install golang.org/x/vuln/cmd/govulncheck@latest` |
| pip-audit | dep | PyPI/OSV advisories for `requirements.txt` (network on every run) | `pipx install pip-audit` |
| npm-audit | dep | registry audit of the detected lockfile; needs network (skipped under `--offline`) | ships with Node |
| pnpm-audit | dep | registry audit of the detected lockfile; needs network (skipped under `--offline`) | `corepack enable pnpm` |
| yarn-audit | dep | registry audit of the detected lockfile, classic or berry; needs network (skipped under `--offline`) | `corepack enable yarn` |
| **bandit** | sast | Python idioms a taint engine can't see (shell=True, eval, weak crypto, pickle) | `pipx install bandit` |
| **gosec** | sast | Go stdlib-aware (math/rand, InsecureSkipVerify, exec w/ tainted args) | `brew install gosec` |
| **checkov** | config | IaC misconfig with a cross-resource graph (deeper than per-block) | `pipx install checkov` |
| **hadolint** | config | Dockerfile lint + ShellCheck on the bash inside `RUN` | `brew install hadolint` |
| **kingfisher** | secret | offline checksum/entropy/lang-aware secret pre-filter, git history, SARIF | `brew install kingfisher` |

## How it runs

`scan --tools auto` (default) runs every installed adapter; `--tools a,b` selects;
`--tools none`/`--no-tools` disables. Each adapter is detected on PATH, executed
in the repo dir (timeout-bounded), and its output parsed — even when the tool exits
non-zero (scanners exit non-zero *when they find issues*). A missing or failing
tool is skipped gracefully and recorded, never fatal.

Severity is normalized to critical/high/medium/low/info: label vocabularies are
aliased; tools that emit only a CVSS vector or score (cargo-audit, osv-scanner)
are bucketed via the CVSS v3 base-score calculator in `src/tools/cvss.ts`.

npm-audit/pnpm-audit/yarn-audit each gate on their own root lockfile
(`package-lock.json`/`npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`) and
audit it via the package manager's real registry query — no local vuln DB, so
they're `network: true` and skipped under `--offline`. **v1 limitation**: only
the root lockfile is audited, not per-workspace sub-lockfiles in a monorepo;
trivy/osv-scanner already walk the tree recursively and cover that gap.

## Correlation, risk scoring & SARIF

Three deterministic layers turn raw scanner output into a ranked, de-duplicated
worklist (all keyless, no LLM calls):

- **Cross-tool correlation** (`src/tools/correlate.ts`). The same issue reported
  by several scanners collapses into one finding whose `sources[]` lists every
  producer — and "N scanners agree" bumps confidence to `high`. dep findings
  merge on *package@version + a shared advisory id* (CVE/GHSA/RUSTSEC, one alias
  hop, so distinct vulns never merge); everything else merges on
  *category + CWE/title + file:line*. Taint candidates are left untouched.
- **EPSS + KEV + CVSS risk** (`src/tools/scoring.ts`). Every CVE-bearing finding
  is enriched with FIRST.org **EPSS** (exploit probability) and CISA **KEV**
  (exploited in the wild → floored to risk 95). A composite `risk` 0–100
  (severity ⊕ EPSS ⊕ KEV) is computed on *every* finding and is the report's
  primary sort key. Feeds are cached under `~/.cache/ultrasec` (daily TTL,
  `ULTRASEC_CACHE_DIR` to override); the math is 100% offline. `--no-enrich` /
  `--offline` skips the network and ranks by severity alone. Network failure
  degrades gracefully (stale cache, then severity-only) — never fatal, no keys.
- **Generic SARIF parser** (`src/tools/sarif.ts`). Any SARIF-emitting scanner
  becomes a thin adapter (argv + a CWE default): severity from
  `security-severity` or `level`, CWE from rule tags, location from the first
  result region. Used by the kingfisher adapter and ready for the next ones.

## Via Docker (no native install)

Two ways to get the scanners without installing them on the host:

- **`scan --docker`** runs each scanner from its official, version-pinned image on
  demand (repo bind-mounted at `/work`, paths rewritten back to repo-relative).
  Only Docker is needed. Adapters with images: trivy, gitleaks, osv-scanner,
  semgrep. Pinned: `ghcr.io/aquasecurity/trivy:0.71.1`,
  `ghcr.io/gitleaks/gitleaks:v8.30.1`, `ghcr.io/google/osv-scanner:v2.3.8`,
  `semgrep/semgrep:1.166.0` (its entrypoint isn't the tool, so the runner prepends
  `semgrep`). OpenGrep has no official image yet → native-only.
- **Toolbox image** (`docker/Dockerfile` + `docker-compose.yml`) bakes the engine +
  the scanners into one image (`docker compose build`), so the whole audit runs
  in-container with everything on PATH. Baked in: trivy, gitleaks, osv-scanner,
  semgrep, gosec, hadolint, bandit, checkov. Versions are pinned build-args; arch
  (amd64/arm64) is auto-detected.

Adapters with an official image for on-demand `--docker`: trivy, gitleaks,
osv-scanner, semgrep, bandit (`ghcr.io/pycqa/bandit`), gosec
(`ghcr.io/securego/gosec`), checkov (`bridgecrew/checkov`), hadolint
(`hadolint/hadolint`). opengrep, kingfisher → native-only for now.

## Recommended additions (researched, not yet adapters)

Net-new coverage worth adding next (none overlap trivy): **GuardDog**
(`ghcr.io/datadog/guarddog`) — malicious-package / typosquat detection, a class
no CVE scanner sees (opt-in network); **TruffleHog** — *live* secret verification
(verified/unverified) to feed the `verified` field; **cppcheck** — C/C++
memory-safety via SARIF (needs stderr capture). Brakeman and CodeQL were screened
out (non-commercial / private-repo licence); **osv-scalibr** was screened out too
— it's an inventory extractor already embedded in osv-scanner v2, not a
standalone advisory source. Add one by following "Adding an adapter" below.

## Triaging tool findings

Tool findings arrive `open` like taint candidates — adjudicate them too. Scanners
are noisy (especially SAST): confirm reachability and exploitability before
promoting, and use the same conservative verify gate. Dependency CVEs are usually
high-confidence (a known-vulnerable version is installed) but still check whether
the vulnerable code path is actually used (`govulncheck` does this for Go).

## Adding an adapter

Implement `ToolAdapter` (`{ name, category, argv(repo), parse(raw) }`) in
`src/tools/<tool>.ts`, register it in `src/tools/index.ts`, add it to the registry
in `src/tools/registry.ts`, and add a parse test against a frozen sample of the
tool's real JSON under `tests/fixtures/tool-output/`.

Notes:
- **SARIF output?** Skip a bespoke parser — delegate to
  `parseSarif(raw, { tool, category, defaultCwe })` (see `kingfisher.ts`).
- **dep/SCA adapter?** Pass `pkg`, `version`, and `aliases` (every advisory id —
  the CVE is auto-picked) so cross-tool correlation and EPSS/KEV scoring work.
- **Scans files, not a directory** (e.g. hadolint)? Add `enumerate(repo)`
  returning the repo-relative paths to scan; the runner appends them to argv and
  skips the run cleanly when none are found.
- `makeToolFinding` sets `sources: [tool]`; the correlator unions them — don't set
  `sources` by hand.

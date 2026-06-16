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
| gitleaks | secret | hardcoded secrets (working tree) | `brew install gitleaks` |
| osv-scanner | dep | OSV.dev lockfile CVEs | `brew install osv-scanner` |
| cargo-audit | dep | RustSec advisories (Cargo.lock) | `cargo install cargo-audit` |
| govulncheck | dep | reachability-aware Go vulns | `go install golang.org/x/vuln/cmd/govulncheck@latest` |

## How it runs

`scan --tools auto` (default) runs every installed adapter; `--tools a,b` selects;
`--tools none`/`--no-tools` disables. Each adapter is detected on PATH, executed
in the repo dir (timeout-bounded), and its output parsed — even when the tool exits
non-zero (scanners exit non-zero *when they find issues*). A missing or failing
tool is skipped gracefully and recorded, never fatal.

Severity is normalized to critical/high/medium/low/info: label vocabularies are
aliased; tools that emit only a CVSS vector or score (cargo-audit, osv-scanner)
are bucketed via the CVSS v3 base-score calculator in `src/tools/cvss.ts`.

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
  all four scanners into one image (`docker compose build`), so the whole audit
  runs in-container with everything on PATH. Versions are pinned build-args; arch
  (amd64/arm64) is auto-detected.

## Recommended additions (researched, not yet adapters)

High-value, non-overlapping scanners worth adding next (official image / install):
**trufflehog** — secret *verification* (authenticates candidates, cuts FP noise)
`ghcr.io/trufflesecurity/trufflehog`; **checkov** — deep IaC/misconfig
`bridgecrew/checkov` / `pip install checkov`; **syft** — SBOM (SPDX/CycloneDX)
`anchore/syft`; **bandit** — Python AST security `pip install bandit`; **brakeman**
— Rails-aware taint `gem install brakeman`. Add one by following "Adding an
adapter" below.

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

# External scanner orchestration

ultrasec runs whatever scanners are installed and normalizes their JSON into the
unified `Finding` model (category · cwe · severity · file:line · message ·
references). Nothing is required — the link-graph + taint reasoning is the
always-on core. `ultrasec tools` shows status + install hints.

**What to *do* with what they produce** — dependency-CVE triage, secrets response, per-tool
false-positive profiles, and the CI/IaC classes none of them cover — is
[supply-chain.md](supply-chain.md). This file is what each tool is and how the belt runs.

| tool | category | what it adds | install |
|------|----------|--------------|---------|
| **trivy** | dep + secret + config | CVEs (SCA), hardcoded secrets, IaC/misconfig across most ecosystems — highest leverage | `brew install trivy` |
| **opengrep** | sast | free Semgrep fork with cross-function taint | see opengrep.dev |
| semgrep | sast | rule + dataflow SAST (cross-file taint is Pro) | `brew install semgrep` |
| gitleaks | secret | hardcoded secrets (git history when present, else working tree) | `brew install gitleaks` |
| osv-scanner | dep | OSV.dev lockfile CVEs | `brew install osv-scanner` |
| grype | dep | Anchore SBOM-based CVEs (pairs with the SBOM a run already generates) | `brew install grype` |
| syft | dep | Anchore CycloneDX SBOM generator — a dossier deliverable AND grype/package-checker input | `brew install syft` |
| cargo-audit | dep | RustSec advisories (Cargo.lock) | `cargo install cargo-audit` |
| govulncheck | dep | reachability-aware Go vulns | `go install golang.org/x/vuln/cmd/govulncheck@latest` |
| pip-audit | dep | PyPI/OSV advisories for `requirements.txt` (network on every run) | `pipx install pip-audit` |
| npm-audit | dep | registry audit of the detected lockfile; needs network (skipped under `--offline`) | ships with Node |
| pnpm-audit | dep | registry audit of the detected lockfile; needs network (skipped under `--offline`) | `corepack enable pnpm` |
| yarn-audit | dep | registry audit of the detected lockfile, classic or berry; needs network (skipped under `--offline`) | `corepack enable yarn` |
| **package-checker** | dep | 12-ecosystem GHSA/OSV lockfile scanner; runs upstream's latest release by default, vendored sha256-pinned copy as offline/failure fallback; needs network to fetch feeds (skipped under `--offline`) unless pre-warmed | nothing to install (bash+awk+curl) |
| **bandit** | sast | Python idioms a taint engine can't see (shell=True, eval, weak crypto, pickle) | `pipx install bandit` |
| **gosec** | sast | Go stdlib-aware (math/rand, InsecureSkipVerify, exec w/ tainted args) | `brew install gosec` |
| **checkov** | config | IaC misconfig with a cross-resource graph (deeper than per-block) | `pipx install checkov` |
| **hadolint** | config | Dockerfile lint + ShellCheck on the bash inside `RUN` | `brew install hadolint` |
| **kingfisher** | secret | offline checksum/entropy/lang-aware secret pre-filter, git history, SARIF | `brew install kingfisher` |

Highest-leverage first if you're installing anything: **trivy** (deps + secrets + IaC in one),
then `gitleaks`, then the language-native one for the stack (`govulncheck`, `cargo-audit`,
`pip-audit`), then a SAST engine.

## Secrets: what the scanners systematically get wrong

Two failures, in opposite directions, both measured on one public k8s repo.

**Encrypted-at-rest files are the dominant noise class.** gitleaks emitted 41 "Generic API Key"
hits on Bitnami SealedSecret ciphertext — files whose entire content is encrypted *by design*,
which is the point of committing them. ultrasec de-prioritizes these to `info` (SealedSecret,
SOPS, Ansible Vault, age, git-crypt, PGP, Jasypt) and records the count in `manifest.downgraded`,
so the class is quiet without being invisible. What actually deserves attention on such a repo is
whether the DECRYPTION KEY is committed alongside, which no filename rule can tell you.

**A credential can hide in plain sight by looking like configuration.** The same repo carried a
literal production Postgres password in
`postgresql://$(username):<literal>@$(host):$(port)/db` — username, host and port are environment
references, the password is not. Both gitleaks and trufflehog missed it: entropy and format
heuristics skip a string whose surroundings are plainly a template. ultrasec's own
credential-URI pass fires on `scheme://user:secret@host` for any scheme even when neighbouring
components are templated, and stays quiet only when the PASSWORD segment itself is a template or a
placeholder. Partial templating is exactly how these survive review.


## How it runs

`scan --tools auto` (default) runs every installed adapter; `--tools a,b` selects;
`--tools none`/`--no-tools` disables. Each adapter is detected on PATH, executed
in the repo dir (300 s timeout), and its output parsed — even when the tool exits
non-zero (scanners exit non-zero *when they find issues*). A missing or failing
tool is skipped gracefully and recorded in `manifest.toolStatus`, never fatal.

**Read `manifest.toolStatus` before trusting a clean result.** It distinguishes `ran` (0 findings
is a real result) from `skipped` (not installed — a coverage hole you should name in the report)
from `failed`. Adapters run **serially**; parallelism in an ultrasec audit comes from the agent
fan-out, not the engine.

Severity is normalized to critical/high/medium/low/info: label vocabularies are
aliased; tools that emit only a CVSS vector or score (cargo-audit, osv-scanner)
are bucketed via the CVSS v3 base-score calculator in `src/tools/cvss.ts`.

npm-audit/pnpm-audit/yarn-audit each gate on their own root lockfile
(`package-lock.json`/`npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`) and
audit it via the package manager's real registry query — no local vuln DB, so
they're `network: true` and skipped under `--offline`. In a monorepo each
per-workspace sub-lockfile is audited too, not just the root one; trivy and
osv-scanner walk the tree recursively and corroborate.

When `syft` is installed, `scan` generates a CycloneDX SBOM (`sbom.cdx.json`) before running the
adapters — a dossier deliverable in its own right, and faster input for grype (`sbom:` mode) and
package-checker (`--source`). Absence is the normal path; without it each adapter scans the repo
directory directly.

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

The ordering the composite `risk` encodes — KEV, then EPSS, then CVSS — and how to work a ranked
list are in [supply-chain.md](supply-chain.md).

## Keeping the toolchain fresh

ultrasec is latest-first everywhere and never asks you to chase a version by hand:

- `scan --docker` runs each scanner from its official image's rolling `latest` tag with
  `--pull always`, so a stale cached `latest` is never silently reused. Only Docker is required;
  reported paths are rewritten from `/work` back to repo-relative automatically.
- `package-checker` resolves upstream's latest release at every scan, with a vendored,
  sha256-pinned fallback for offline/air-gapped hosts (`ULTRASEC_PACKAGE_CHECKER_PINNED=1`).
- `tools --upgrade [--dry-run]` completes the story for natively-installed binaries: it infers
  which package manager (brew/pipx/go/cargo/corepack/npm) put each tool there from its own
  resolved binary path and drives that manager's real upgrade command. apt-owned and unrecognized
  origins print a hint instead — **ultrasec never runs `sudo`**. Per-tool failures are recorded,
  never fatal.

Run `tools` at audit start; with the user's consent (or a standing preference), `tools --upgrade`
— `--dry-run` first to see the exact commands.

The origin-inference table, the package-checker vendoring/feed-poisoning guard, the Docker image
list and toolbox build, the researched-but-not-yet-built adapters, and the `ToolAdapter` contract
for adding one are all in [`docs/tooling-internals.md`](../../../docs/tooling-internals.md)
(maintainer reference, not shipped with the skill).

## Triaging tool findings

Tool findings arrive `open` like taint candidates and are adjudicated the same way, under the
same `[file:line]` gate and the same conservative verify policy. Two rules to start from:

- **SAST findings are pattern matches**, not proofs. Confirm reachability and exploitability
  before promoting. Each engine has a characteristic noise profile — Bandit's `B101`/`B404`,
  gosec's `G104`/`G304`, Semgrep's `generic.secrets` — catalogued in
  [supply-chain.md](supply-chain.md).
- **Dependency CVEs are high-confidence on *presence* and low-confidence on *relevance*.** The
  vulnerable version really is installed; whether the vulnerable path is reachable, shipped, or
  matters in your deployment is the judgment. `govulncheck` answers reachability mechanically for
  Go, which is why its findings carry more weight than a plain lockfile match.

Corroboration (`sources[]` longer than one) is a confidence prior for verify, never a verdict.

## Three that cover what the others cannot

| tool | the gap it fills |
|---|---|
| **trufflehog** (`--only-verified`) | whether a secret is still LIVE. Sets `verified` on the finding — the difference between an incident and a hygiene note. Network-dependent, so `--offline` skips it. |
| **guarddog** | malicious packages and typosquats: a package hostile from its first publish has no advisory and never will. Heuristic, so findings arrive at low confidence for you to confirm. |
| **cppcheck** | C/C++ memory safety — use-after-free, out-of-bounds, uninitialized reads, leaks. The catalog's `buffer` rule is a best-effort scaffold; this is the real analysis. Reads its diagnostics from **stderr**, which the runner now captures. |

## What the belt does not cover

No DAST, no fuzzing, no authenticated crawling, no runtime testing — and no coverage of
authorization or business logic. Everything in [attack-classes.md](attack-classes.md) is manual
by construction. A clean scanner run means the known-pattern layer is clean, nothing more, and
the report should say so.

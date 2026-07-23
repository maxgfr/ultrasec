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

## Supply-chain audit: SBOM (syft) + package-checker

When `syft` is installed, `scan` generates a CycloneDX SBOM (`sbom.cdx.json`)
before running the adapters — a dossier deliverable in its own right (linked
from `DOSSIER.md`), and faster input for the two adapters that can consume it
instead of re-walking the tree themselves: grype switches its `argv` to
`sbom:<path>` mode, and package-checker appends it as an extra `--source`
alongside its default GHSA/OSV feed. Absence is the normal path — most hosts
don't ship `syft` — so a scan without it just falls back to each adapter
scanning the repo directory directly; nothing is fatal either way.

package-checker ([maxgfr/package-checker.sh](https://github.com/maxgfr/package-checker.sh),
same author as ultrasec) runs **upstream's latest release by default** —
executing it at scan time is first-party trust, not a third-party
supply-chain hole. `command()` (`src/tools/package-checker.ts`) resolves the
latest tag + downloads `script.sh` via a short-timeout `curl` (the
`ToolAdapter.command()` contract is synchronous, so this can't use `fetch`),
caches it content-addressed under `<cache dir>/package-checker/script-<tag>-<hash12>.sh`,
and runs that. Any failure in that chain — offline, DNS, rate-limited, a
malformed API response, a full disk — falls straight back to the vendored,
sha256-pinned copy (`src/vendor/package-checker.sh` +
`src/vendor/package-checker.meta.json`, synced by
`scripts/sync-package-checker.mjs`, drift-gated by
`pnpm run check:package-checker` folded into `check:build`, and kept fresh by
the scheduled `.github/workflows/update-package-checker.yml` auto-bump PR).
Set `ULTRASEC_PACKAGE_CHECKER_PINNED=1` to force the vendored copy
unconditionally (hardened/air-gapped hosts) — this is also what the test
suite sets by default so it never hits the network. The vendored copy ships
embedded as a generated TS string constant in the bundle
(`src/vendor/package-checker-script.ts`) so it survives any packaging path
that only copies `scripts/ultrasec.mjs`. Either way it needs `bash`, `awk`
and `curl` — nothing to `npm install`.

Coverage — 12 ecosystems, one script, detect-then-load: npm, yarn, pnpm, bun,
deno, PyPI, Go, Cargo, RubyGems, Composer, Maven/Gradle, NuGet, Pub, Hex,
Swift, and GitHub Actions workflow files, matched against GHSA + OSV advisory
feeds.

**Network stance**: the script resolves its default feeds via
`find_default_source()` (Homebrew share → `./data/` → `/app/data/` → a remote
GitHub raw URL) with no env var or flag to redirect that search to an
arbitrary directory, and `./data/` resolves against the scanned repo's cwd,
not ultrasec's cache dir — so this adapter cannot be made offline-safe by
pointing it at a cache dir. It is `network: true` and skipped under
`--offline`. For air-gapped use, warm the feeds once and point the script at
them explicitly:

```sh
bash <vendored script.sh> --fetch-all <dir>
bash <vendored script.sh> <repo> --source <dir>/*.purl --export-json <file>
```

**Feed-poisoning guard**: precisely because `./data/` resolves against the
*scanned repo's own cwd* and is preferred over Homebrew/`/app/data`/the real
upstream feed, a repo that commits its own `data/ghsa.purl` (or `data/osv.purl`,
or a per-ecosystem `data/{ghsa,osv}-<eco>.purl`) makes `find_default_source()`
silently substitute it for the real advisory feed — suppressing real findings
or injecting fake ones. `package-checker.ts`'s `applicable(repo)` detects any
`<repo>/data/*.purl` file (the exact shape probed) and SKIPS the adapter with
an explicit note rather than trusting a feed the scanned repo controls; use
trivy or osv-scanner (their own local vuln DBs, not repo-writable) to still get
coverage on such a repo.

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

- **`scan --docker`** runs each scanner from its official image's rolling
  `latest` tag on demand (repo bind-mounted at `/work`, paths rewritten back to
  repo-relative). `docker run` always carries `--pull always` (`src/tools/run.ts`
  `runDocker`) so a stale cached `latest` is never silently reused — trading
  reproducibility for always-current CVE/rule coverage. Only Docker is needed.
  Adapters with an official image: trivy (`ghcr.io/aquasecurity/trivy`),
  gitleaks (`ghcr.io/gitleaks/gitleaks`), osv-scanner
  (`ghcr.io/google/osv-scanner`), semgrep (`semgrep/semgrep`, entrypoint isn't
  the tool so the runner prepends `semgrep`), bandit
  (`ghcr.io/pycqa/bandit/bandit`), gosec (`ghcr.io/securego/gosec`), checkov
  (`bridgecrew/checkov`), hadolint (`hadolint/hadolint`) — all track `:latest`.
  opengrep, kingfisher → native-only for now.
- **Toolbox image** (`docker/Dockerfile` + `docker-compose.yml`) bakes the engine +
  the scanners into one image (`docker compose build`), so the whole audit runs
  in-container with everything on PATH. Baked in: trivy, gitleaks, osv-scanner,
  semgrep, gosec, hadolint, bandit, checkov, grype, syft, pip-audit. Every tool
  installs its **latest release by default**; each has an optional
  `--build-arg <TOOL>_VERSION=x.y.z` to pin it instead (see `docker/Dockerfile`).
  Image freshness is therefore the freshness of the last build —
  `docker compose build --no-cache` re-resolves every tool's latest release;
  arch (amd64/arm64) is auto-detected. The grype vulnerability DB and
  package-checker's feeds are deliberately NOT baked in (per-run,
  network-fetched state) — see the comment in `docker/Dockerfile` for the
  air-gapped warm-up commands.

## Recommended additions (researched, not yet adapters)

Net-new coverage worth adding next (none overlap trivy), phase-2 candidates:

- **GuardDog** (`ghcr.io/datadog/guarddog`) — malicious-package / typosquat
  detection, a class no CVE scanner sees (opt-in network). Adapter sketch:
  `category: "dep"`, `argv` runs `guarddog npm|pypi verify <lockfile> --output-format json`
  per detected ecosystem (mirrors the pm-audit multi-ecosystem gate), `parse`
  maps each flagged package into a Finding the same way package-checker does.
- **TruffleHog** — *live* secret verification (verified/unverified) to feed the
  `verified` field on secret-category findings; `category: "secret"`.
- **cppcheck** — C/C++ memory-safety via SARIF (needs stderr capture).

Brakeman and CodeQL were screened out (non-commercial / private-repo licence);
**osv-scalibr** was screened out too — it's an inventory extractor already
embedded in osv-scanner v2, not a standalone advisory source. Also screened out,
one-liners: **lockfile-lint** — checks lockfile *integrity* (registry pinning,
no injected entries), a niche supply-chain-tampering concern distinct from the
per-dependency advisories every adapter here reports; **OSSF Scorecard** — scores
a repo's overall security *posture* (branch protection, CI hygiene, …), not
per-dependency vulnerabilities, so it doesn't fit the Finding model. Add one by
following "Adding an adapter" below.

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

Three optional hooks (`src/tools/run.ts`) cover the rest of what a real-world
adapter needs beyond `argv`/`parse`:
- **`command()`** — override the executable (argv0 prefix), e.g. `["bash", scriptPath()]`
  or `["yarn", "npm"]`; return `null` for a graceful "not installed" skip. Replaces
  the default PATH probe of `name` (see `package-checker.ts`, `pm-audit.ts`).
- **`applicable(repo)`** — a repo-content gate: `null` runs the tool, a string is a
  skip note (e.g. `"no requirements.txt"`); unlike `enumerate`, the result is
  **not** appended to argv (see `pip-audit.ts`).
- **`network`** — `true`, or a function answering per-run, when the tool hits the
  network on every invocation (registry/feed queries); skipped under `--offline`.

**Tool takes no positional file args (it scans by flag/config, not a path list)?
Use `applicable`, not `enumerate`** — `enumerate` is only for tools that scan
explicit *files* (its return value is appended to argv); a tool with nothing to
point at a directory needs a content gate instead.

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

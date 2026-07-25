# Tooling internals (maintainer reference)

Implementation detail behind the scanner belt: how the package-checker is vendored and
refreshed, how `tools --upgrade` infers a binary's origin, how Docker mode is wired, the
roadmap adapters, and how to add a new one.

This is **not** part of the shipped skill. The auditor-facing material — what each scanner
covers, how findings are correlated and ranked, and how to triage what they produce — lives in
`skills/ultrasec/references/tools.md` and `skills/ultrasec/references/supply-chain.md`.

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


## Keeping native tools fresh: `tools --upgrade`

ultrasec is latest-first everywhere — docker mode tracks `:latest` with
`--pull always`, `package-checker` resolves upstream's latest release at scan
time — and `tools --upgrade` completes that story for NATIVE binaries: for
every INSTALLED tool it infers which package manager put it there and drives
that manager's own "upgrade to latest" command. `--dry-run` prints the exact
commands without running any of them.

```bash
node scripts/ultrasec.mjs tools --upgrade --dry-run   # preview
node scripts/ultrasec.mjs tools --upgrade              # actually upgrade
```

**Origin inference** (`inferOrigin`, `src/tools/origin.ts`) reasons purely from
the installed binary's resolved, symlink-followed absolute path (`resolveBinaryPath`
in `src/tools/registry.ts`), checked in this order:

| # | Signal | Manager | Upgrade command |
|---|---|---|---|
| 1 | tool name is `npm` | `npm` | `npm install -g npm@latest` — npm has no separate Homebrew formula, so self-upgrade is the only universally correct move regardless of how Node was installed |
| 1 | tool name is `pnpm`/`yarn`, or the path contains `/corepack/` | `corepack` | `corepack up` — pnpm/yarn "ship via Corepack, not a separate install" (this registry's own stance); deliberately overrides even a `brew install pnpm` formula |
| 2 | `/opt/homebrew/` or `/usr/local/Cellar/` in the path | `brew` | `brew upgrade <formula>` — both dirs are Homebrew-exclusive, unambiguous on their own |
| 2 | `/usr/local/bin/` in the path **and** a `brew` binary sits alongside it | `brew` | `brew upgrade <formula>` — bare `/usr/local/bin` is also the generic Linux/FHS "manually installed" dir, so it only counts as brew when a sibling `brew` confirms it (no PATH search, no subprocess) |
| 3 | `.local/pipx` or `pipx/venvs` in the path | `pipx` | `pipx upgrade <package>` |
| 4 | under `$GOPATH/bin`, or `~/go/bin` when GOPATH is unset | `go` | `go install <module-path>@latest` |
| 5 | under `~/.cargo/bin` | `cargo` | `cargo install <crate> --force` (`--force` because `cargo install` no-ops a same-version reinstall) |
| 6 | Linux only: `/usr/bin/*` and `dpkg -S` claims it | `apt` | **print-only** — `sudo apt install --only-upgrade <pkg>`; ultrasec never runs `sudo` |
| — | nothing matched | `unknown` | **print-only** — falls back to the tool's registry install hint |

The package/module/crate identifier defaults to the tool's own name and is
overridden per manager via `ToolSpec.packageIds` (`src/tools/registry.ts`) only
where it genuinely differs — today that's exclusively the three Go-installed
tools, whose import path has nothing in common with the binary it builds:
`govulncheck` → `golang.org/x/vuln/cmd/govulncheck@latest`, `gosec` →
`github.com/securego/gosec/v2/cmd/gosec@latest`, `osv-scanner` →
`github.com/google/osv-scanner/cmd/osv-scanner@latest`. Every brew/pipx/cargo
entry today has a formula/package/crate name identical to the binary, so none
needed an override.

`npm-audit`/`pnpm-audit`/`yarn-audit` probe and upgrade their REAL binary
(`ToolSpec.binaryName`: `npm`/`pnpm`/`yarn`) rather than their display name.
`package-checker` is skipped entirely — it isn't a single PATH binary (its
presence check is bash+awk+curl) and already self-updates at scan time; the
summary notes this instead of attempting a command. Docker-mode scans get a
one-line reminder that they already refresh via `--pull always`.

Per-tool outcomes (`upgraded`/`already-latest`/`failed`/`skipped-unknown-origin`)
are independent and never fatal — one tool's upgrade failing (wrong exit code,
timeout, missing manager) is recorded and the run continues; `tools --upgrade`
itself never throws and never exits non-zero for a per-tool failure. Versions
are compared before/after via the same `detect()` probe the default listing
uses, so an actual version change prints `old → new`; an unchanged version
(or one that isn't cheaply parseable) prints `already-latest`.

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

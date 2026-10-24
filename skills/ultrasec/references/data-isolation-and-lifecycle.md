# Data isolation and lifecycle

> Adapted from Cloudflare's [security-audit skill](https://github.com/cloudflare/security-audit-skill) (MIT).

An endpoint can check ownership perfectly and the data can still leak — through the search index,
the cache, the export, the backup, the restore. This file follows **one protected record through
every copy and every state change**. Open it because the system holds multi-tenant or
access-controlled data and derives copies of it, issues object links, exports or restores, migrates
schemas, or promises deletion and revocation — not because it uses Postgres or S3. It is the
knowledge behind:

```bash
ultrasec investigate --run .ultrasec --lens lifecycle
```

Endpoint-level tenant and object authorization is [access-control.md](access-control.md); retention
and erasure seen from the data subject's side (lawful basis, processors, personal data in logs) is
[privacy-and-data-protection.md](privacy-and-data-protection.md). This file is the security
contract in between: who can read or act on the record, in every copy, for as long as it exists.

```
rg -n "unscoped|withoutGlobalScope|withTrashed|bypassRLS|service_role|SECURITY DEFINER|deleted_at|soft_?delete"
rg -n "cache\.(get|set)|redis\.(get|set)|index\(|bulk\(|export|backup|snapshot|restore|presign|signedUrl|getSignedUrl"
```

## Discipline

- **A tenant field on a record is not isolation.** Find the query predicate, key, path, policy or
  row-level control that enforces it on each read and write path.
- **Derived copies have their own ACLs.** Primary data that is safe can become unsafe in search,
  cache, analytics, export, previews, logs, replicas and backups, each with different access and
  retention rules.
- **Deletion and revocation are contracts.** Check current, historical, cached, indexed, exported,
  restored and queued copies, within the boundary the product actually promises.
- **A privacy preference is not automatically a security bug.** Require an explicit access boundary
  or deletion/revocation guarantee *and* an unauthorized reader or later operation; otherwise it
  belongs in the privacy file, rated there.

## Tenant and object isolation

**Where it hides.**

- **Missing tenant/owner binding** — a read, update, delete, list, count or bulk query selects by id
  without the session's tenant, or takes the tenant from the body. Compare direct, nested-relation,
  background, admin, import and legacy paths.
- **Composite-key collisions** — cache keys, object paths, unique constraints, search document ids,
  temp files or dedup keys that omit tenant or environment, so two principals overwrite or read
  the same logical key while their records carry separate owners.
- **Policy/query disagreement** — row-level security, ORM default scopes, authorization filters and
  raw or service clients applying different predicates: joins, aggregates, views, `unscoped`, a
  service-role client, an error path where the tenant context is missing.
- **Blob and signed-reference overreach** — object keys, attachment or version ids, share links and
  signed URLs that allow other operations or namespaces than the issuer had, or stay valid after the
  ACL changes. Bind operation, exact object and version, audience, expiry and tenant.

**How to prove it.** Two dummy tenants through the same local service method; tenant A's request
returns or overwrites tenant B's record. Cite the source-of-truth policy *and* the path that omits
it, and confirm no other layer enforces the same predicate.

**How to rate it.** Cross-tenant read of sensitive records ⇒ **HIGH**, **CRITICAL** if
unauthenticated and at scale; collision limited to non-sensitive cache entries ⇒ **LOW**.

**Usually nothing.** A global scope or RLS policy you had not found yet; random 128-bit object keys
with no listing path (still say how they leak, if they do).

## Derived data and disclosure

**Where it hides.**

- **Search, cache and index drift** — the primary record's ACL or state changes, and the searchable,
  cached, embedded, thumbnail, RSS, preview or index copy does not follow. Filtering must happen at
  retrieval, not only at ingest and invalidation.
- **Logs, analytics, traces and diagnostics as alternate readers** — private content or credentials
  emitted into systems with wider access, longer retention or tenant mixing.
- **Enumeration and aggregate oracles** — counts, filters, sort order, errors, unique-constraint
  messages, timing, notifications or existence checks that answer a confidential yes/no.

**How to prove it.** Change the ACL (or delete) on a dummy record, then show the derived copy still
serves it to the now-unauthorized dummy user; for oracles, the two distinguishable responses.

**How to rate it.** By the data and the reader: another tenant's documents in shared search ⇒
**HIGH**; an existence oracle on a sensitive predicate ⇒ **MEDIUM**.

**Usually nothing.** Field names or public ids in logs; operator-only telemetry under intended
policy; general response-time variance.

## Export, backup, restore and migration

**Where it hides.**

- **Export/backup scope** — an export, snapshot, portability package or report that includes other
  tenants, fields the requester cannot see, soft-deleted rows, secrets or history above their
  access. Check per-item authorization after selection *and* authorization to download the
  artifact.
- **Import/restore authority** — restore or import that skips owner, schema, ACL, uniqueness or
  validation rules, overwrites existing resources, or recreates records in a tenant the requester
  cannot write. Treat archive contents as untrusted and authorize the resulting operation.
- **Migration defaults** — old rows without tenant/ACL/lifecycle fields, colliding ids, or a partial
  rollout where old and new readers apply different defaults. Read backfills, dual read/write,
  rollback and resumed-migration paths.
- **Backup and replica drift** — keys, storage accounts, cross-region replicas, restore environments
  or support snapshots scoped wider than primary data.

**How to prove it.** A dummy low-privilege export or import that carries out-of-scope rows; a
migration fixture showing a null tenant read as "visible to all".

**How to rate it.** Export of other tenants' data by a normal user ⇒ **HIGH**; restore into a
foreign tenant ⇒ **HIGH**.

**Usually nothing.** An admin export of the admin's own tenant, as designed.

## Deletion, revocation and lifecycle

**Where it hides.**

- **Soft-delete bypass** — a direct lookup, search, relation traversal, object link, background job
  or restore that ignores `deleted_at` and returns or acts on the record; deleted identifiers
  re-registered while references to them still exist.
- **Stale authorization** — membership removal, ACL change, consent withdrawal, secret revocation
  or role downgrade that leaves sessions, caches, subscriptions, jobs or materialized views still
  authorizing future operations.
- **Retention overrun** — primary storage deletes, then queued processors, retries, exports,
  analytics or generated artifacts recreate or keep the data past the promised boundary. Look for
  idempotent deletion and tombstone propagation.
- **Restore reintroduces invalid state** — backup, undo, undelete or replica recovery brings back
  data, credentials, memberships or permissions current policy no longer allows. Restored state must
  be re-authorized and later lifecycle changes reapplied.

**How to prove it.** Remove dummy user B from a workspace, then show B's session, cached link or
queued job still reaches the workspace; or delete a record and show a retry recreating it.

**How to rate it.** Revoked access still usable ⇒ **HIGH** when it crosses a gated boundary; a
deleted record lingering only in an operator-only cache ⇒ **LOW**.

**Usually nothing.** Soft delete documented as recoverable by the owner; a short, bounded cache TTL
the product explicitly accepts.

## Before you report

- Draw the lineage for one protected record: write, query, cache, index, event, export, backup,
  deletion and restore, with the principal and tenant marked on every edge. Start at bypass clients,
  background jobs, migrations, global uniqueness and cache keys — they drop request-scoped identity.
- `confirmed` only with a cited `[file:line]` lineage plus bounded local evidence: dummy tenants and
  non-sensitive fixtures, stopping at the minimum observable record.
- A required fact outside the repo — the provider's bucket policy, CDN cache behavior, replica lag,
  backup access, the deployed retention job — makes it `needs-human`; the note names that fact and a
  safe owner-side check ("confirm the nightly export bucket is not readable by the support role").
- Dismissing a high/critical needs a named brocard from
  [dismissal-brocards.md](dismissal-brocards.md): `no-threat-model`, `exploit-from-the-heavens`,
  `outside-usage`, `standard-behavior`, `documented-behavior`, `cure-worse-than-disease`,
  `report-not-dispositive`.
- Proof stays benign: never real user data, never a destructive operation on shared storage. Rate
  with [severity-and-discipline.md](severity-and-discipline.md).

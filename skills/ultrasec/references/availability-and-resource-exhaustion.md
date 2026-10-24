# Availability and resource exhaustion

> Adapted from Cloudflare's [security-audit skill](https://github.com/cloudflare/security-audit-skill) (MIT).

Reach for this file when **untrusted input can spend something the requester does not own**: CPU,
memory, disk, connections, worker slots, queue capacity, a paid upstream API or LLM budget — or can
crash or deadlock a process other people depend on. Pick it because that shared resource sits
behind the boundary, not because a loop looks slow. It is the knowledge behind
`ultrasec investigate --lens dos`.

Its job is to separate an availability *vulnerability* you can read in source from a performance
issue. Several shapes are already enumerated by the engine, and this file is how you rate what
they return:

- **ReDoS (CWE-1333)** — the regex shapes and the runtime question (backtracking vs RE2) are in
  [attack-classes.md](attack-classes.md#injection-variants-the-catalog-doesnt-carry).
- **Algorithmic DoS inside a library call (CWE-407)** — `paths --kind algodos`; why taint cannot
  see it is in [hunting-heuristics.md](hunting-heuristics.md#the-ordinary-classes).
- **Zip bombs and archive expansion** — part of the upload checklist in
  [attack-classes.md](attack-classes.md#file-upload).
- **No rate limit on a route** — `guards --lens throttle` builds the absence matrix; an
  `unthrottled` verdict becomes a cited CWE-770 (CWE-307 on an auth-shaped handler).

Memory *corruption* is [memory-safety-and-native.md](memory-safety-and-native.md) and broker
delivery logic is [protocols-and-messaging.md](protocols-and-messaging.md) — but a reachable fatal
error is rated here for its shared impact even when the parser that hits it is covered there.

## Discipline

- **Three things or no finding:** an input-to-cost path, a missing *effective* bound, and impact
  on someone else — another user, a shared service, a safety function, or operator-owned spend.
  Work that only slows the requester's own process is not a service vulnerability.
- **A missing rate limit is not enough.** Before calling a path unbounded, look for body, message
  and file caps, concurrency limits, queue depth, deadlines, database constraints, the upstream
  gateway and per-tenant quotas. A limit that exists elsewhere is not a missing limit (the
  calibration table in [severity-and-discipline.md](severity-and-discipline.md) says so).
- **Never prove it by causing it.** No stress test, no saturation, nothing against a shared or
  live service. Use asymptotic analysis, a few small growth points under strict local CPU, memory
  and time limits, mocked paid calls, and deterministic cancellation tests.
- **State the economics:** attacker cost, service work, persistence, scope, recovery.
- **`confirmed`** for a source-visible missing bound demonstrated safely; **`needs-human`** when
  upstream caps, deployed topology, autoscaling, paid quota or recovery live outside the repo.

## Rating it

One input that **stops a shared service** — an unauthenticated request that panics the only
process, a poison message that wedges every tenant's queue, a superlinear parse that pins all
workers — is **HIGH**, and only when that outage is shown in a fixture, not imagined. An effect
that needs **sustained volume** to matter is
**LOW**, in line with the rubric's "DoS needing sustained effort". In between, raise for low
attacker cost, no authentication, cross-tenant scope, persistence and poor recovery; lower for
authenticated, per-tenant, self-healing. Unbounded spend on a paid API is rated by the money and
who pays it.

## Computational amplification

**Superlinear parsing, matching or evaluation.** A small accepted input drives catastrophic regex
backtracking, nested parsing, recursive validation, symbolic or template evaluation, graph
traversal, GraphQL depth and complexity, or adversarial sort and hash-collision behaviour. Derive
the accepted depth or cardinality and the complexity, then show a bounded growth curve locally
(n = 10, 20, 40 — not n = a million). *Usually nothing* when a size cap upstream keeps n tiny.

**Decompression and representation amplification.** Compressed, sparse, nested, aliased or encoded
input expands far past the checked transfer size: archives, images (pixel dimensions vs file
size), fonts, XML entity expansion and YAML anchors, PDF object streams, HTTP/2 HPACK and other
protocol compression tables. The limit must hold *after* every expansion stage, not just on the
bytes received.

**Database and downstream query amplification.** A small request triggers a full scan, a
pathological join, unbounded sort or aggregation, N+1 fan-out or many downstream calls, because
depth, filter cardinality, page size or `expand=` fields are not bounded. First confirm that
authorization doesn't intentionally grant that scope — an export an admin is allowed to run is
not an attack.

## Resource accumulation

**Unbounded buffering and cardinality.** Request bodies, out-of-order stream frames, uploads,
sessions, unique cache keys, metrics labels, log fields, subscriptions or pending jobs accumulate
with no per-item *and* aggregate limit. Find the cleanup on disconnect, timeout, cancellation and
partial parse — the leak is usually on the path nobody tested.

**Descriptor, handle and temporary-resource leaks.** Malformed or cancelled work skips cleanup
and keeps a socket, file, cursor, timer, subprocess, temp file or object reference. Show the
retention repeating across a bounded number of local iterations and name the shared pool it
drains.

**Detached work after cancellation.** A client timeout, disconnect, cancelled job or *failed
authorization* returns control while the database query, model call, network fetch or worker task
keeps running. Trace the context or deadline through every layer; an expensive LLM call that
outlives a rejected request is spend the attacker never paid for.

## Quota and scheduling

**Pre-authentication work imbalance.** Expensive parsing, key lookup, password hashing,
signature verification, decompression or an outbound request happens before authentication and
before the earliest size or rate gate. Compare the requester's minimal effort with the shared cost,
and check what the edge already limits.

**Quota accounting scope and reset gaps.** The budget is keyed on something the attacker steers —
IP behind a proxy that trusts `X-Forwarded-For`, route, key prefix, task id, a tenant field in the
body — so one principal escapes its budget or burns another's. Also look for counter overflow,
distributed races, resets on reconnect or retry, and account switching.

**Worker, pool and priority starvation.** Attacker-controlled or low-priority jobs hold shared
locks, workers, database connections, event-loop turns or scheduler priority that unrelated users
need. It is a finding when the path bypasses queue or concurrency fairness, or keeps a slot past
its deadline — a synchronous `readFileSync` or CPU loop on the Node event loop is the common case.

## Failure and recovery

**Reachable fatal error or deadlock.** Untrusted input reaches `panic!`, `.unwrap()`, `abort`, a
fatal assertion, an unhandled exception or rejection, `process.exit`, a lock cycle or an infinite
loop in a shared process. Establish the supervisor scope: one request, one worker, or the whole
service. A restarted isolated worker reduces impact; it does not erase the defect.

**Retry storms and fail-open amplification.** Timeouts, dependency errors, partially processed
messages or failing health checks trigger synchronized or unbounded retries with no jitter,
ceiling, circuit breaker or deduplication. Show that one bounded failure source produces
persistent aggregate work. If the failure path also *fails open* (skips a check to stay up), that
half is an access-control finding.

**Poison record and head-of-line blocking.** One malformed record fails forever at the head of a
shared queue, partition, startup scan, migration or recovery loop. Read the skip and quarantine
policy, the offset handling, and whether other tenants share the blocked unit.

**Unsafe recovery and capacity rollback.** A restart, restore, fallback or cleanup rebuilds
unbounded state, ignores current quotas, or replays the very input that caused the crash.
Recovery is part of availability: a crash loop is worse than a crash.

## Moves that pay everywhere

- **Build the input-to-resource table:** earliest accepted size and cardinality, work done before
  auth, downstream fan-out, persistence, shared pool, who owns the limit and the cleanup, recovery.
- **Compare aggregate limits with per-object limits.** Ten thousand valid one-byte items pass a
  per-message cap and still exhaust tenant-wide or process-wide state.
- **Stop at observable.** Validate only in an isolated fixture with strict limits and small growth
  points, mock every external and paid call, and stop as soon as the missing bound or the missing
  cancellation is visible.

## Before you report

1. Name the untrusted input, the requester's work, the amplification or retained resource, the
   shared blast radius and the recovery — each source step with a `[file:line]`. Missing limits
   with no concrete shared impact are a **hardening note**, not a finding.
2. Confirm that no source-visible upstream, parser, queue, tenant or framework bound stops the
   path. When the deciding control is deployed (CDN or gateway limit, ingress body cap,
   autoscaling, provider quota, supervisor restart policy), the verdict is `needs-human` and the
   note names that fact plus a safe owner-side check ("confirm the ingress `client_max_body_size`
   for `/import`").
3. Superlinear claims show the accepted complexity and a small local growth curve; leaks show
   repeatable retention after cleanup should have run; fatal paths name the process and
   supervisor isolation.
4. Never turn ordinary load into a shared-service DoS on paper. Report what you observed: "4×
   input, 16× CPU in the fixture", not "takes the cluster down".
5. Dismissing a high/critical needs a named brocard from
   [dismissal-brocards.md](dismissal-brocards.md) — `outside-usage` when only a cron job feeds the
   input, `exploit-from-the-heavens` when only an operator can submit it,
   `cure-worse-than-disease` belongs on the remediation, not on the finding.

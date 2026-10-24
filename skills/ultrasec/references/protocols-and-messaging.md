# Protocols, RPC and messaging

> Adapted from Cloudflare's [security-audit skill](https://github.com/cloudflare/security-audit-skill) (MIT).

Reach for this file when **a message crosses a boundary that is not a plain REST request**: gRPC,
GraphQL, WebSocket, Cap'n Proto, Thrift, Protobuf/Avro over custom framing, streaming RPC,
webhooks, brokers, queues, pub/sub and event buses. Pick it because a producer and a consumer sit
on different sides of a trust boundary — not because `grpc` appears in the lockfile. It is the
knowledge behind `ultrasec investigate --lens messaging`.

The questions here are peer identity, how a decoded message is interpreted, where it is routed,
and what happens when it is replayed, reordered or delivered twice. Parser *memory* safety is
[memory-safety-and-native.md](memory-safety-and-native.md); availability impact of a message is
[availability-and-resource-exhaustion.md](availability-and-resource-exhaustion.md); the per-object
ownership question every handler still owes is [access-control.md](access-control.md).

Split large systems by producer/consumer pair, external vs internal peer role, synchronous RPC,
streaming, and asynchronous message path — one region each.

## Discipline

- **"Internal" is not authentication.** Name the authenticated peer at every hop, and show how
  that identity becomes the application principal the authorization check uses.
- **A schema proves shape, nothing else.** Protobuf, JSON Schema or GraphQL types do not prove
  provenance, resource authority, ordering or safe values. Follow decoded fields to the policy
  check and to the side effect.
- **Broker guarantees are not application guarantees.** Write down retry, ordering,
  acknowledgement, deduplication and transaction behaviour *before* you reason about state.
- **A parser-disagreement claim needs two concrete readers** — two consumers, two schema versions
  or two wire representations — and one divergent value that matters to security.
- **`confirmed` needs the full in-repo path plus a bounded local producer/consumer test.** Broker
  ACLs, service-mesh identity, topic attachment and cross-version compatibility that live outside
  the repo make it `needs-human`.

## Framing, schema and interpretation

**Message boundary and canonicalization disagreement.** Two components disagree on length,
compression, duplicate fields (last-wins vs first-wins), unknown fields, encoding, numeric width,
normalization, or envelope vs body precedence. Compare generated and hand-written parsers,
gateways, language bindings and version converters. *Prove* by feeding the same fixture to both
readers and showing which principal, resource or operation differs. *Usually nothing* if either
side rejects the ambiguous input outright.

**Union, enum and default confusion.** An unknown variant, a missing discriminator, a proto3 zero
value, a default privilege or a compatibility mapping reaches code that assumes a validated case.
Read every `default:` branch and ask how an *old* consumer reads a field a *new* producer added —
`role = 0` meaning `ADMIN` is the classic.

**Envelope and payload identity mismatch.** Authorization reads trusted-looking routing or
envelope metadata while the handler acts on a different tenant, account, subject, object or
sender named in the body. Establish which one is authoritative and that the client cannot set it.
*Rate* like the IDOR it is: tenant crossing is **HIGH**.

## RPC identity and authorization

**Interceptor and method-path inconsistency.** An authn/authz interceptor covers unary calls but
not streams, server reflection, health, gateway-transcoded HTTP paths, legacy service names, or
the individual messages of a stream. List every registration and route that reaches the same
operation and compare their guard chains — the same delta method as
[access-control.md](access-control.md).

**Peer identity vs application principal.** mTLS, workload identity, bearer metadata, a
forwarded-identity header or broker credentials authenticate the *channel*, then a
caller-controlled field picks the user or tenant. The channel identity and the claimed principal
must be bound by deterministic policy; a service allowed to call `GetInvoice` is not thereby
allowed to name any customer.

**Per-item and streaming authorization gaps.** A stream, subscription, batch or bulk message is
authorized once; later items name other resources, or the stream keeps flowing after a role
change, membership removal or token revocation. Re-check wherever scope can change, and bind each
subscription to the principal that opened it.

**Callback and reply-correlation confusion.** Predictable, reused or cross-tenant correlation
ids let a response, webhook, cancellation or acknowledgement satisfy someone else's pending
operation. Each outstanding request must be bound to the authenticated peer, tenant, operation
and lifecycle. Webhook *receivers* also owe a signature check over the raw body and a replay
window — a webhook that trusts its own payload is the next class.

## GraphQL, WebSocket and gRPC surfaces

**GraphQL field-level authorization.** The resolver, not the query, is the boundary. An object
reachable through a nested field (`me { team { members { email } } }`) or a `node(id:)` lookup
often skips the check enforced on the top-level query. Grep the resolver map and the directive or
middleware that guards it, then walk every edge that returns the same type. *Rate* as access
control. *Usually nothing*: a schema-wide auth directive or a data-loader that filters by session.

**Introspection, depth and complexity.** Introspection on in production is recon, not a finding by
itself. Missing depth and complexity limits let recursive fragments or wide list fan-out cost
the server far more than the client — rate it under
[availability-and-resource-exhaustion.md](availability-and-resource-exhaustion.md).

**Batching and aliases as rate-limit bypass.** A thousand `login` mutations in one batched array,
or one document with a thousand aliased `login` fields, count as a single request to a per-request
limiter. On an authentication or OTP mutation that defeats brute-force protection: **MEDIUM** to
**HIGH** by what the guessed secret opens. `guards --lens throttle` sees the route, not the
fan-out inside it — check the limiter's unit.

**Whole-object input mutations.** A mutation taking an input type that maps straight onto the
model (`updateUser(input: UserInput)` with `role` in it) is mass assignment; see
[access-control.md](access-control.md).

**Auth at connect, never again.** WebSocket, gRPC streams, SSE and GraphQL subscriptions check
the token on the handshake and then trust every message for the life of the connection. Look for
per-message or per-method authorization, and for what happens on logout or revocation. Browser
WebSockets also carry cookies cross-origin: a handshake that does not check `Origin` on a
cookie-authenticated socket is cross-site WebSocket hijacking (CSRF with read).

## Broker and queue isolation

**Topic, routing-key and subscription scope.** A publisher or subscriber can pick another
tenant's topic, wildcard, consumer group, partition, reply queue or dead-letter route. Check the
broker ACLs where they are visible and the application code that builds the namespace. A tenant
id inside the payload is not isolation.

**Dead-letter, retry and diagnostic disclosure.** Messages rerouted to a DLQ, an error topic,
tracing or an operator console carry secrets or cross-tenant payloads to a lower-trust reader.
Review redaction and access on the *failure* path, not just on normal delivery; this overlaps
[privacy-and-data-protection.md](privacy-and-data-protection.md) when the payload is personal.

**Untrusted producer treated as control plane.** A message body declares itself an admin event,
provider callback, replication record or migration instruction, and nothing independently
authenticates the producer and the event type. Verify a signature and the source/account/audience
binding before any privileged handling. *Rate* by what the forged event does: account takeover or
entitlement grant is **HIGH** or **CRITICAL** when the queue is reachable unauthenticated.

## Replay, ordering and transactions

**Duplicate delivery and idempotency.** At-least-once delivery repeats a side effect because
deduplication is missing, runs after the mutation, or keys on something that collides across
tenants or operations. Name the broker's delivery model and the side effect that is not naturally
idempotent (a payment, a credit, an email with a token).

**Out-of-order and stale messages.** An older state, revoked membership, cancelled job or
pre-step-up authorization lands after the newer state and overwrites it. Look for sequence or
version checks, tombstones, partition reassignment and restore/replay tooling.

**Acknowledgement vs commit ordering.** Ack before durable commit loses security-relevant work (an
audit event, a revocation); commit before an unreliable ack duplicates a mutation. Read the outbox
and inbox, and what recovery does after a crash between the two.

**Partial multi-consumer transitions.** Several consumers jointly carry one authorization or
business transition; retries and partial failure leave a subset committed — the user removed
from the team but still in the channel. Name the invariant that had to become durable atomically,
or the compensation that must re-check current authorization.

## Moves that pay everywhere

- **Draw the hop chain** for each message family: producer → broker/transport → gateway →
  consumer → storage. At each hop note the authenticated peer, the authoritative tenant and
  resource fields, the validation and the side effect.
- **One fixture, every reader.** Feed the same small message to every in-repo schema version and
  language binding: duplicate, missing, unknown, boundary, replayed and reordered — in memory, no
  load.
- **Policy must survive transport changes.** Compare normal, retry, dead-letter, replay,
  migration, reflection, stream and gateway-transcoded routes for the same operation.

## Before you report

1. Name the realistic producer or peer, the accepted message, the authenticated channel identity,
   the principal or resource affected, and the unauthorized mutation or disclosure — each step a
   `[file:line]`.
2. A disagreement claim cites both parsers or consumers and the divergent decoded value. Safe
   rejection by either side defeats it.
3. A replay or ordering claim states the real delivery guarantee and reproduces the broken
   invariant with a bounded in-memory or local transport. Proof is a benign marker message, never a
   replay against a live queue.
4. For authorization and isolation, check every interceptor, gateway, broker ACL and consumer
   layer the repo shows. When the deciding layer is outside it (broker ACL, mesh policy, topic
   attachment, the deployed gateway), the verdict is `needs-human` and the note names that fact
   and a safe owner-side check ("confirm `tenant-*` topics have per-tenant ACLs in the broker
   config").
5. `confirmed` only with the complete message lifecycle and an observed result. Dismissing a
   high/critical needs a named brocard from [dismissal-brocards.md](dismissal-brocards.md) —
   `standard-behavior` when the "duplicate" is at-least-once delivery the broker documents and the
   consumer already deduplicates, `outside-usage` for a topic
   no external producer can reach, `no-threat-model` when nobody untrusted publishes at all.

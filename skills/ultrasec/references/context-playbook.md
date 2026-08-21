# Context playbook (`ultrasec context`)

The highest-leverage twenty minutes of an audit. `CONTEXT.md` is injected into every later
`dossier` and every stage worklist, so a good one improves every verdict you make afterwards —
and a missing one means you adjudicate each candidate blind to whether the app even considers
that input untrusted.

**Additive evidence only.** There is no `--apply`, and nothing in `CONTEXT.md` gates a verdict.
It informs your judgment; it can't overrule the conservative gate.

## 1. Emit the scaffold

```
ultrasec context --repo . --out .ultrasec
```

Writes `CONTEXT.scaffold.json` (frameworks, entry points, auth-middleware candidates, sanitizers,
inferred trust boundaries — shape in [schemas.md](schemas.md)) and `CONTEXT.todo.md`. The
scaffold is deterministic pattern-matching: it tells you where to look, not what's true.

`frameworks` is read from **every** manifest in the tree, not just the root's — a monorepo keeps
its dependencies in the workspace packages. An empty list on a repo that plainly has a web
framework means the manifest is somewhere the bounded walk didn't reach (more than three levels
down), and it is worth saying so in `CONTEXT.md` rather than concluding there is no framework.

Pair it with `map --repo . --out .ultrasec` on anything large — the two together give you the
entry surface and the sink density before you read a line.

## 2. Answer these, in `<run>/CONTEXT.md`

### What is this, and what's the baseline?

App type (web app, API, CLI, library, daemon, agent), who uses it and how, the stack, and — the
part people skip — **a comparable mainstream application to calibrate against**. A CMS is judged
against other CMSes, an API gateway against other gateways.

The comparable is a focusing tool, not a dismissal tool:

- Same pattern, and it has been **exploited** in the comparable ⇒ a **stronger** finding, and you
  know what the exploit looks like.
- Same pattern, **never** exploited there across years of production ⇒ understand *why* before
  reporting. There is usually a mitigation you haven't found yet, and finding it is the work.

A genuinely novel application may have no meaningful comparable. Say so rather than forcing one.

### Trust boundaries and access control

- Where does untrusted input enter? (routes, gRPC, WebSocket, queue consumers, webhooks, file
  uploads, CLI, env, IPC)
- How do callers prove identity — sessions, bearer tokens, API keys, mTLS, SSO?
- How is authorization enforced — middleware, decorators, policy objects, capability checks? Name
  the mechanism and the file, because [attack-classes.md](attack-classes.md) starts by diffing
  the route list against the guard list.
- What runs as what? Root, a service account, a container with which capabilities? Does it drop
  privileges? Is there a sandbox?
- **Bypass modes** — dev/test/setup/debug flags, seed credentials, an admin backdoor for support,
  a `?debug=1`. These are where the audit usually pays for itself.

### Input-surface inventory

Every network surface; every file input (uploads, config, import/export); IPC, CLI and env;
user-generated content that is stored and later rendered (the second-order surface); and every
external integration — OAuth providers, webhooks, plugins, dynamically loaded code, and any
LLM/agent tool bindings.

### Framework protections already in force

What does the template layer autoescape? Does the ORM parameterize by default, and where are its
raw escape hatches? Is CSRF protection on, and does the session mechanism even need it? Write
these down: they are what turns a candidate into a refutation later, and
[frameworks.md](frameworks.md) tells you where to look per stack.

### The intended trust model

If the design says admins are fully trusted, an admin doing admin things is not a finding. If the
design isn't written down anywhere — the common case — **infer it from the code and say that you
inferred it**. An audit that assumes a stricter model than the team intends produces findings
they will (correctly) reject, and an audit that assumes a looser one misses the real ones.

## 3. Keep it short and specific

Two to three screens. Every claim should be something a later stage can act on. "Uses Express" is
noise; "auth is `requireAuth` in `src/middleware/auth.js:12`, applied per-route not globally, and
14 of 31 routes don't have it" is a finding waiting to be written.

Re-read `CONTEXT.md` at the end of the audit and correct what turned out to be wrong. It ships
with the dossier, and the next pass — yours or someone else's — starts from it.

---

Related: [severity-and-discipline.md](severity-and-discipline.md) (what the baseline is for) ·
[frameworks.md](frameworks.md) · [scale-audit-playbook.md](scale-audit-playbook.md) (context on a
repo too big to read).

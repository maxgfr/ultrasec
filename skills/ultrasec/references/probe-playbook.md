# Live-site probe playbook (`ultrasec probe`)

`ultrasec probe <url>` is the ONE dynamic thing ultrasec does, and it is
deliberately walled off from the static audit. It observes a **running** site's
security posture on the wire; it does not scan source, and its findings never
touch the static dossier.

```bash
ultrasec probe https://app.example.com --i-own-this
ultrasec probe https://app.example.com --i-own-this --graphql --deep --out .ultrasec
ultrasec probe http://127.0.0.1:3000  --i-own-this --allow-private   # a local target you own
```

## Authorization first

Probing a host you do not own or are not authorized to test may be unlawful.
`probe` refuses to run without `--i-own-this`, and refuses a target that resolves
to a private / loopback / cloud-metadata address unless you add `--allow-private`.
It is read-only (GET/HEAD/OPTIONS, plus one POST for `--graphql`), single-host,
never crawls, sends no credentials, is rate-limited and capped. Keep it that way.

## What it checks

- **Response headers** — presence and value of Content-Security-Policy (flags
  `unsafe-inline`/`unsafe-eval`/wildcard sources), Strict-Transport-Security
  (missing / `max-age=0` / short), X-Frame-Options or CSP `frame-ancestors`,
  X-Content-Type-Options `nosniff`, Referrer-Policy `unsafe-url`.
- **Cookies on the wire** — HttpOnly / Secure / SameSite on each `Set-Cookie`,
  and the `__Host-` / `__Secure-` prefix rules.
- **TLS** — negotiated protocol (flags TLS 1.0/1.1), certificate trust
  (self-signed / hostname mismatch), and near/after expiry.
- **Transport** — cleartext HTTP, and whether `http://` redirects up to HTTPS.
- **Banners** — `Server` / `X-Powered-By` that disclose a version.
- **CORS** — one crafted preflight with a throwaway Origin; flags reflection and
  wildcard-with-credentials.
- **security.txt** — whether `/.well-known/security.txt` (RFC 9116) exists.
- **GraphQL** (`--graphql`) — a single introspection query; flags a schema that
  answers.
- **Exposed files** (`--deep`) — a small fixed list of well-known sensitive paths
  (`.env`, `.git/config`, `/server-status`), matched by content, on your own host.

## The isolation contract (why probe findings are separate)

Every STATIC finding ultrasec produces is grounded on a resolvable `[file:line]`,
and the `check` gate fails the audit if a citation does not resolve. A probe
finding has no source line — it cites `[response-header:…]`, `[cookie:…]`,
`[tls]`, or `[url:…]`. So probe writes its own artifact:

- **`PROBE.json`** — the structured report (target, resolved IP, findings).
- **`PROBE.md`** — the readable summary, findings worst-first.

It **never** writes `findings.json`, and `check`, `coverage`, `render` and the
MCP tools never read `PROBE.*`. That is what keeps a wire observation from ever
being mistaken for — or breaking — a grounded source finding. Confirm a probe
result by hand and, if it corresponds to a code-level cause, file THAT as a
normal grounded finding.

## Using it in an audit

The probe is a complement, not a substitute: a missing header seen on the wire
often has a code cause the static pass can also find (see the `webconfig`
detector — CORS, cookie flags, headers, TLS-verify). Run `probe` to confirm what
actually ships in production, then fix it at the source. `--strict` makes a
high/critical posture finding a non-zero exit for CI.

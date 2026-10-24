# Client-side and browser surfaces

> Adapted from Cloudflare's [security-audit skill](https://github.com/cloudflare/security-audit-skill) (MIT).

Some trust decisions happen where the server never looks: a URL fragment, `window.name`, a
`postMessage` payload, a value cached by a service worker last week. Open this file because the
browser **holds a boundary** — an SPA that renders attacker-influenced content, a browser extension,
an embedded webview, a service worker, an offline app, cross-window messaging, browser storage —
not because `react` is a dependency. It is the knowledge behind:

```bash
ultrasec investigate --run .ultrasec --lens browser
```

Server-side CSRF and CORS policy live in [attack-classes.md](attack-classes.md#csrf-and-cors);
the native half of a webview bridge in [desktop-mobile-and-ipc.md](desktop-mobile-and-ipc.md).
`ultrasec probe` checks the deployed headers this file keeps asking about (CSP, `frame-ancestors`,
CORS reflection, cookie flags) — see [probe-playbook.md](probe-playbook.md).

```
rg -n "innerHTML|outerHTML|insertAdjacentHTML|document\.write|dangerouslySetInnerHTML|v-html|\[innerHTML\]|bypassSecurityTrust"
rg -n "addEventListener\(['\"]message|postMessage\(|new WebSocket|serviceWorker\.register|BroadcastChannel|localStorage|indexedDB|caches\.open"
```

## Discipline

- **A candidate needs a controllable source and an executing or disclosing sink.** Name both and
  show the attacker's data getting from one to the other.
- **Impact must reach a victim's session, another origin, or shared persistence.** Self-XSS and
  reading your own data are `no-threat-model`.
- **Browser controls are real controls.** Framework escaping, the same-origin policy, CSP,
  COOP/CORP, service-worker scope, `SameSite` and implicit `noopener` all stop attacks; verify which
  are in force before assigning impact.
- **Storage outlives login.** Browser storage and caches are shared per origin. For each record,
  know who writes it, who reads it, and which account, tenant or worker lifecycle clears it.

## DOM and object state

**Where it hides.**

- **DOM XSS** — `location.*`, `document.referrer`, `window.name`, message data and storage flowing
  into `innerHTML`/`outerHTML`, `document.write`, `eval`/`setTimeout(string)`/`new Function`,
  `javascript:` URLs, jQuery `.html()`/`$(html)`, or a framework escape hatch. Interpolation the
  framework escapes is not a finding.
- **DOM clobbering** — injected markup with `id`/`name` attributes that shadows a global, a form
  property, a config object or an init flag the code later trusts. Needs both a markup path that
  keeps the attribute (sanitizers often do) and a security-relevant read of the clobbered value.
- **Prototype pollution gadgets** — an attacker-controlled key reaches a recursive write (deep
  merge, path assignment, query-string parsers that build nested objects), *then* a reachable gadget
  reads the polluted property to change authorization, script loading, navigation or rendering.
  `JSON.parse` alone, a shallow copy, or pollution without a gadget is not enough.

**How to prove it.** A benign marker (`alert(document.domain)` in a local test origin, a clobbered
flag logged to the console). For pollution, show the recursive write and the gadget read.

**How to rate it.** DOM XSS on the app origin that fires from a shared link ⇒ **HIGH**; one that
needs the victim to paste a crafted value ⇒ **MEDIUM**. Pollution rates by its gadget.

**Usually nothing.** Text bound through JSX/`{{ }}`; a sanitizer configured to drop `id`/`name`.

## Cross-origin messaging and network

**Where it hides.**

- **`postMessage` trust** — a handler acts on `event.data` without an exact origin allow-list and,
  when several frames share an origin, without checking `event.source`. Substring, prefix, suffix
  or unanchored-regex matching is not an origin check. Send side: sensitive data posted to `*`
  reaches whoever embeds the page.
- **Cross-site WebSocket hijacking** — the upgrade accepts ambient cookies from any origin with no
  `Origin` check or channel token, so a hostile page reads or drives the victim's session. Needs
  both the permissive upgrade and a handler that matters.
- **Credentialed CORS** — `Origin` reflected or loosely matched together with
  `Allow-Credentials: true` on a sensitive response. A bare `*` with credentials is refused by
  browsers; report the actual reflected path and the data or mutation it exposes.

**How to prove it.** A local attacker page that posts a message, opens the socket or issues the
`fetch` with credentials, against dummy accounts, showing the protected value or state change.

**How to rate it.** Reading or mutating another user's session data cross-origin ⇒ **HIGH**.

**Usually nothing.** A message handler that only resizes an iframe; a WebSocket authenticated by a
token sent in the first frame rather than a cookie.

## Service workers and browser storage

**Where it hides.**

- **Registration and scope takeover** — attacker-influenced content can become the worker script,
  a path gains an over-broad `Service-Worker-Allowed` scope, or `importScripts` pulls code without
  integrity control. Check the final script URL, MIME type, origin, scope and who controls each
  import.
- **Cache identity confusion** — the worker caches personalized responses with no account, tenant,
  auth state or request mode in its policy, then serves them after logout or account switch —
  including from offline and error fallbacks.
- **Stale storage** — tokens, private responses, drafts or cached authorization decisions left in
  `localStorage`, `sessionStorage`, IndexedDB, Cache Storage or extension storage, readable by the
  next account or a less-trusted same-origin component, or still honored after revocation.
- **Cross-context confusion** — `storage` events, `BroadcastChannel`, shared workers or origin-wide
  caches carry identity or commands between tabs without binding them to the current session; a
  stale tab overwrites newer auth state after an account or tenant switch.

**How to prove it.** Lifecycle reachability on a local origin: dummy user A logs in, logs out,
user B logs in, and A's response or token is served or reused.

**How to rate it.** Another account's private data served from cache ⇒ **HIGH**; a token in
`localStorage` with no less-trusted reader ⇒ hardening note.

**Usually nothing.** A same-origin worker with its intended scope; storing a token with no realistic
reader that holds less authority.

## Cross-site leaks, framing and navigation

**Where it hides.**

- **XS-Leaks** — an attacker page distinguishes protected cross-origin state through load/error
  events, frame counts, redirects, timing, cache probing or response size while the browser sends
  the victim's cookies. Needs one concrete secret predicate (does this private object, role or
  account exist?).
- **Window and opener state** — permitted cross-origin window metadata reveals protected state, or
  a retained opener or named-window relationship lets a hostile page steer a privileged navigation.
  Check COOP, frame protections, `noopener`, exact origin.
- **Clickjacking** — a state-changing action that can complete while framed, with no effective
  `frame-ancestors`/`X-Frame-Options`.
- **Navigation confusion** — a client-side source drives `location`/`router.push`/`window.open` with
  no scheme or destination policy, including `javascript:` and `data:`. Reverse tabnabbing only
  where code keeps `window.opener` or targets browsers without implicit `noopener`.

**How to prove it.** A local page demonstrating the oracle's two outcomes, or the framed action
completing; then name the header or rendering change that removes it.

**How to rate it.** An oracle on a sensitive predicate ⇒ **MEDIUM**; clickjacking of a destructive
or money-moving action ⇒ **MEDIUM** to **HIGH**.

**Usually nothing.** Generic timing variance; probing public resources; missing frame headers on
read-only pages (hardening note).

## Before you report

- Cite source, sink, the browser policy that should have stopped it, the affected origin or session,
  and the observable mutation or disclosure.
- `confirmed` only with a cited `[file:line]` client path plus bounded local evidence — a local test
  origin, dummy accounts, no production users or shared services.
- A required fact outside the repo — the deployed CSP or COOP header, an extension's granted
  permissions, a browser version, a renderer — makes it `needs-human`; the note names that exact
  fact and a safe owner-side check (`ultrasec probe` on their own host, or "confirm production
  serves `frame-ancestors 'self'` on /settings").
- Dismissing a high/critical needs a named brocard from
  [dismissal-brocards.md](dismissal-brocards.md): `no-threat-model`, `exploit-from-the-heavens`,
  `outside-usage`, `standard-behavior`, `documented-behavior`, `cure-worse-than-disease`,
  `report-not-dispositive`.
- Proof stays benign: markers and dummy accounts, never a payload that exfiltrates real data. Rate
  with [severity-and-discipline.md](severity-and-discipline.md).

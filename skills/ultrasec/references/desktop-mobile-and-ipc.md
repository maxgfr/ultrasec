# Desktop, mobile and local IPC

> Adapted from Cloudflare's [security-audit skill](https://github.com/cloudflare/security-audit-skill) (MIT).

Reach for this file when **the trust boundary is on the device**: a desktop or mobile app
(Swift, Kotlin, Electron, Tauri), a privileged helper or updater, a local daemon, a webview host,
a deep-link or file-association handler, a browser native-messaging host, a local IPC client or
server. Pick it because a less-trusted actor can reach one of those — not because the repo has an
`ios/` folder. It is the knowledge behind `ultrasec investigate --lens local-ipc`.

The attacker here is never "a local user" in general. Name the starting capability: a downloaded
document, remote web content inside a webview, another installed app, another OS user, a
sandboxed child process, a lower-privilege account. Native parsing and loader safety is
[memory-safety-and-native.md](memory-safety-and-native.md); whether an update is authentic is
[supply-chain.md](supply-chain.md); an IPC protocol's message semantics follow
[protocols-and-messaging.md](protocols-and-messaging.md).

## Discipline

- **Establish the realistic attacker first.** Another app, another OS user, a sandboxed child, an
  untrusted document, a remote origin. Harm a user does to themselves with their own account and
  authority crosses no boundary — that is `exploit-from-the-heavens`.
- **Names are not identity.** A socket path, process name, bundle or package id, or a `sender`
  field is not peer authentication. OS peer credentials (`SO_PEERCRED`, audit tokens), code-signing
  identity, capability handles and protected channel state are.
- **The bridge or helper authorizes each call.** After parsing, every operation and its final
  resource is checked; a trusted UI or broker in front does not make attacker-influenced
  arguments trusted.
- **OS controls are real controls** — sandbox, signing, entitlements, permissions, keychain ACLs,
  exported-component policy, consent prompts — when they are pinned and visible in the repo.
- **`confirmed`** with source evidence plus a bounded local or emulator test. **`needs-human`**
  when signing, manifest merge, OS version, MDM/device policy, installer ACLs or packaging decide
  the outcome and you cannot see them.

## Deep links, callbacks and navigation

**Custom-scheme and deep-link ambiguity.** Another app or a web page invokes a route that mutates
state, imports data, completes authentication or switches account, with no binding to the current
session and no one-time callback token. Read URI normalization, duplicate query parameters,
scheme/host/path matching, `intent-filter`/`CFBundleURLTypes`/universal-link association, and
whether a stale or replayed link still works. *Rate* by what the link does without a user
decision: silent account linking is **HIGH**, a pre-filled form the user must submit is **LOW**.

**App and account handoff confusion.** OAuth, SSO, magic-link, invite, device-pairing,
passwordless or payment callbacks return to the wrong installed app, profile, tenant or pending
transaction — a custom scheme any app can claim is the classic. Bind the state to the initiating
app, session, account, provider, operation and expiry; prefer verified app/universal links and
PKCE.

**File-open and intent authority confusion.** An associated file, share intent, drag-and-drop
item, pasteboard record, notification action or open-file event triggers a privileged operation
without checking content type, sender where it matters, current user intent and the final target.

## Webviews and native bridges

**Navigation origin vs bridge.** Remote or attacker-controlled frames reach a JavaScript-to-native
bridge meant for packaged content: Android `addJavascriptInterface`, `WKScriptMessageHandler`,
Electron `preload`/`ipcRenderer` with `contextIsolation` off or `nodeIntegration` on, Tauri
commands without scope. Origin must be checked at *call* time and after every navigation,
redirect, subframe, popup and error page; a URL-prefix check (`startsWith("https://app.com")`
matches `app.com.evil.io`) or an initial-load check is not enough. *Prove* with a local page that
calls the bridge and returns a benign marker.

**Over-broad bridge capabilities.** A generic bridge lets web content choose arbitrary files,
commands, IPC methods, credentials or system actions (`openExternal(url)` with any scheme,
`shell.exec`, `readFile(path)`). Look for a method allow-list, normalized arguments, user and
tenant authority, gesture or confirmation requirements, and what the return value discloses.
*Rate*: remote content to command execution is **CRITICAL**; to local file read, **HIGH**.

**Webview file and universal access.** Remote content reads app-local files, privileged custom
schemes or internal origins because `setAllowFileAccess`, `allowUniversalAccessFromFileURLs`,
mixed content, remote debugging or a custom protocol handler joins origins unexpectedly. *Usually
nothing*: a permissive setting with no reachable protected content is a hardening note.

## Local IPC and exported components

**IPC peer-authentication gaps.** A Unix socket, named pipe, XPC service, Binder interface, D-Bus
name, native-messaging host, local RPC, shared memory segment or loopback listener accepts a
lower-trust peer without checking OS credentials, code identity, sandbox token or channel
ownership. A loopback HTTP port is reachable from every local process *and*, without `Origin` and
`Host` checks, from web pages via DNS rebinding. It needs a meaningful method or disclosure
behind it to be a finding.

**Claimed principal vs channel identity.** The channel is authenticated as one app or user, then
a request field selects another user, tenant, profile or capability. Bind each method and
resource to the peer credential, never to a caller-declared id — the access-control question of
[access-control.md](access-control.md), moved onto a socket.

**Exported component overreach.** An Android service, activity, receiver or content provider
(`exported="true"`, or implicitly exported by an `intent-filter` on older targets), an iOS URL or
App Intent handler, or a local automation endpoint performs an operation meant for the app itself.
Read the *final merged* manifest, permission and `signature` protection levels,
`grantUriPermissions` path grants and `activity-alias` entries. When the merged manifest is not in
the repo, the verdict is `needs-human`.

**IPC lifecycle and correlation confusion.** Predictable request ids, reused handles, stale
channels, inherited file descriptors, world-writable socket paths in `/tmp`, or restart behaviour
let one peer answer, cancel or reuse another's operation. Check the creation mode and the cleanup
of socket files, locks, ports and shared mappings.

## Privileged helpers and local files

**Privileged helper as confused deputy.** A low-privilege caller picks the command, file, service,
user or system setting a privileged helper acts on, without per-operation authorization. Read the
sudoers, polkit, UAC, `SMJobBless`/XPC helper rules, and check that the helper validates the
normalized arguments itself. *Rate*: unprivileged user to root is **HIGH**; **CRITICAL** when a
remote-content entry reaches it.

**Install, update and repair path trust.** A privileged installer or helper reads manifests,
scripts, packages, symlinks, working directories or repair state that a lower-trust actor can
write after authorization happened. Bind the authorization to immutable content and safe
destination paths; signature and channel authenticity are [supply-chain.md](supply-chain.md).

**Local file ownership and TOCTOU.** The app checks a path, then follows a replacement, symlink,
mount, or case/normalization change during a privileged read or write. The fix is
descriptor-relative operations (`openat`, `O_NOFOLLOW`) and a final ownership check; the general
pattern is in [attack-classes.md](attack-classes.md#race-conditions-and-toctou).

**Credential store and local-secret boundary.** A keychain or keystore item, token file, backup,
log, clipboard entry, notification preview or local config is readable by another app, profile or
user with less authority. The mobile specifics: Keychain accessibility (`AfterFirstUnlock` vs
`WhenUnlockedThisDeviceOnly`), hardware-backed Keystore keys, biometric binding
(`setUserAuthenticationRequired`, `.biometryCurrentSet`), `allowBackup="true"` or iCloud backup on
data that should not leave the device, cleartext SQLite or `SharedPreferences`/`UserDefaults`
holding tokens, world-readable files. Secrets compiled into the binary are visible to anyone with
`strings` — rate them by what they open, as any hardcoded key. *Usually nothing*: plaintext
readable only by the same intended OS account — name the lower-trust reader and what the
credential grants, or there is no finding.

**Release flags and sensitive input fields.** The manifest and layout files carry their own
findings, cheap to check and easy to skip: `android:debuggable="true"` in a release build (any
local debugger reads memory and calls code as the app), `allowBackup` without exclusion rules, a
component exported by an intent filter on an old `targetSdk`. On secret fields — password, PIN,
card, OTP — an `inputType` without `textPassword`/`textNoSuggestions` lets the keyboard learn and
suggest the value, copy-and-paste puts it on a clipboard other apps read, and no `FLAG_SECURE`
lets it reach screenshots and the app switcher. Rate these by the lower-trust reader you can name:
`debuggable` in a shipped build is **MEDIUM**, the input-field items **LOW** or informational.

**Transport trust on the device.** App Transport Security disabled (`NSAllowsArbitraryLoads`), a
trust-all `X509TrustManager` or `HostnameVerifier`, `onReceivedSslError` calling `proceed()`, or a
`network_security_config` permitting cleartext. A network attacker then reads or alters what the
app sends: **HIGH** when credentials or session tokens travel on it.

## Application state and device lifecycle

**Account switch, logout and restore leakage.** Cached data, background tasks, widgets,
notifications, local databases, webview storage or a biometric approval survive logout or account
change and surface under the next account. Check backup and restore, and multi-profile or
work-profile behaviour; overlaps [privacy-and-data-protection.md](privacy-and-data-protection.md).

**Pending action and user presence.** A notification action, widget, shortcut, share sheet,
biometric prompt or deferred operation authorizes a different action than it displayed, runs after
expiry, or uses another profile's pending state. Bind the confirmation to the normalized action,
resource, account and current foreground state.

## Moves that pay everywhere

- **Inventory the device surface:** every process, app component, local endpoint, URI scheme,
  file association, webview origin and helper, with its OS identity, privilege, caller and
  callable operations.
- **Read what ships, not what was written:** the merged manifest, entitlements, installer rules,
  native-messaging registration, protocol-handler registration and ACL creation. Build steps
  overwrite source declarations.
- **Dummy profiles only.** Validate with throwaway accounts and non-sensitive fixtures on an
  isolated machine or emulator; never touch another user's apps, credentials or production
  services.

## Before you report

1. Name the attacker's starting capability, the OS or app principal crossed, the entry channel,
   the accepted argument or state, and the unauthorized operation or disclosure — each step with
   a `[file:line]`.
2. Account for every control that applies: sandbox, peer credential, signing, entitlement,
   permission, consent prompt, installer ACL.
3. A webview finding cites both the navigation/origin control and the privileged native sink. An
   IPC finding cites peer authentication and per-resource authorization. A helper finding shows
   the final normalized destination.
4. Keep proof bounded and benign — a marker file in a temp dir, a dummy account — and stop at the
   boundary result: no persistence, no wider system change, no real credential read.
5. `confirmed` only with a complete source and local evidence chain. When the deciding fact is
   outside the repo (signing identity, merged manifest, OS version, MDM policy, installer ACL,
   packaging), the verdict is `needs-human` and the note names it plus a safe owner-side check
   ("run `aapt dump xmltree` on the release APK and confirm `SyncService` is not exported").
6. Dismissing a high/critical needs a named brocard from
   [dismissal-brocards.md](dismissal-brocards.md) — `exploit-from-the-heavens` for same-user
   self-harm, `documented-behavior` only when the platform documents the security consequence,
   `outside-usage` when the component is unexported in the shipped manifest you actually read.

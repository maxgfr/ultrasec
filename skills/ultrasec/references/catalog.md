# Taint catalog & CWE coverage

The catalog (`src/catalog.ts`) is the deterministic half of taint enumeration:
**sources** (untrusted input), **sinks** (dangerous operations), and
**sanitizers** (neutralizers). It is recall-oriented — a spurious candidate costs
you a glance; a missed flow is a missed bug.

## Sinks → CWE

| kind | CWE | severity | example callees |
|------|-----|----------|-----------------|
| sql | CWE-89 | high | `query`, `execute`, `raw`, `executemany` |
| nosql | CWE-943 | high | `db.find`, `collection.findOne`, `mapReduce`, `aggregate` (receiver-gated) |
| command | CWE-78 | critical | `exec`, `execSync`, `spawn`, `system`, `popen`, `Popen`, `shell_exec` |
| code | CWE-94 | high | `eval`, `Function`, `runInThisContext`, `compile` |
| ssti | CWE-1336 | high | `from_string`, `renderString`, `Template`, `compileString` |
| path | CWE-22 | high | `readFile`, `writeFile`, `sendFile`, `open` · + zip-slip: `extractall`, `extract`, `unzip` |
| ssrf | CWE-918 | high | bare `fetch`, `request`, `urlopen`, `axios`, `got` · + member calls `axios.get`, `http.get`, `requests.get`, `session.post` (receiver-gated) |
| xxe | CWE-611 | high | `parseString`, `parseFromString`, `fromstring`, `SAXParser`, `DocumentBuilder` |
| ldap | CWE-90 | high | `ldap.search`, `client.bind` (receiver-gated) |
| xss | CWE-79 | medium | `res.send`, `res.write`, `render_template_string` |
| crlf | CWE-93 | medium | `res.setHeader`, `res.header`, `addHeader` (receiver-gated) |
| proto | CWE-1321 | high | `_.merge`, `_.defaultsDeep`, `extend` (receiver-gated) |
| deserialize | CWE-502 | high | `pickle.loads`, `yaml.load`, `unserialize`, `readObject` |
| crypto | CWE-327 | medium | `md5`, `sha1`, `createCipher`, `DES` |
| redirect | CWE-601 | medium | `res.redirect` |
| buffer | CWE-120 | high | C/C++ best-effort: `strcpy`, `strcat`, `sprintf`, `gets`, `memcpy` |

> **The severity column is a starting prior, not a verdict.** It says how bad this class *usually*
> is, with no knowledge of your app. Stored XSS in an admin panel outranks the `medium` shown
> here; `md5` used for an ETag is not a finding at all. Rate what you confirm with
> [severity-and-discipline.md](severity-and-discipline.md), which carries worked pairs for
> exactly these cases.

Receiver-gated rules only match when the call's receiver is in a known set (e.g.
`db`/`collection`/`Model` for NoSQL, an HTTP client for SSRF member calls) so common
look-alikes (`Array.prototype.find`, a plain `merge()`, a `cache.get()`) don't flood
the candidate list. The SSRF member-call rule additionally *requires* a receiver, so
a bare `get(x)` never matches. Coverage is deepest for the web stacks; `buffer` is a
best-effort C/C++ scaffold — pair it with cppcheck/gosec.

Every class above is exercised by a labelled per-CWE benchmark
(`tests/fixtures/bench/`, scored by `tests/bench.test.ts` for per-class TPR/FPR/
Youden with a safe twin that must not be flagged) — a CI gate against class-specific
detection regressions.

## Sources

HTTP request input (`req.query/body/params/headers/files`, Flask `request.*`, PHP
`$_GET/$_POST`, servlet `getParameter`, Rails `params`, Go `r.URL/FormValue`),
WebSocket/stream messages (`.on("message"…)`), CLI args (`process.argv`,
`sys.argv`, `os.Args`), env (`process.env`, `os.environ`, `getenv`), and stdin
(`input()`).

## Sanitizers (hints)

Parameterized queries (`?`/`$1`/`:name` placeholders), argv-array exec
(`execFile`, `shlex.quote`, `escapeshellarg`), path confinement (`basename`,
`realpath`, `secure_filename`), HTML escaping (`escapeHtml`, `DOMPurify`,
`bleach`, `markupsafe`), safe loaders (`yaml.safe_load`, `JSON.parse`),
NoSQL operator-stripping (`mongo-sanitize`), XML entity-disabling
(`resolve_entities=False`, `FEATURE_SECURE_PROCESSING`), LDAP escaping
(`ldap.escape`), CR/LF stripping, prototype-pollution guards
(`Object.create(null)`, `__proto__` checks), template autoescaping, and
type-coercion/validation (`parseInt`, `Number`, `validator.*`, `zod`/`Joi`). These
**lower confidence and annotate** a candidate — they do not auto-dismiss it; you
confirm the sanitizer actually covers the flow.

## Extraction tier changes what gets enumerated

Symbols and call sites come from tree-sitter when the grammars are available and from regex
extractors when they aren't. The dossier records which ran, in `manifest.extraction`. This is not
a detail: measured on a 69-file TypeScript repo, the regex tier produced **27 taint candidates
instead of 66**, lost every cross-file command-injection candidate, and dropped two CWE classes
entirely. `ast: false` means the catalog below was applied to a thinner view of the code — check
it before concluding a class is absent, and say so in the report.

## What needs YOU (not in the catalog)

Taint enumeration is structural: it connects a known source to a known sink. Everything whose bug
is an **absence** is out of reach and is your job — broken access control and IDOR, missing
authorization, business logic, auth/session/JWT/SSO, crypto misuse beyond weak-hash detection,
deserialization gadget availability, SSRF allow-list bypasses, race conditions and TOCTOU, mass
assignment, ReDoS, file upload, CSRF/CORS, GraphQL field authz, request smuggling, and the
LLM/agentic surface.

Mechanism-level method per class is in [attack-classes.md](attack-classes.md); the lenses to
apply before you know the class are in [hunting-heuristics.md](hunting-heuristics.md); where each
hides in your stack is [frameworks.md](frameworks.md).

## Extending the catalog

Edit `src/catalog.ts`: add a `SinkRule` (callees + cwe + severity + languages), a
`SourceRule` (a regex tagged by language), or a `SanitizerRule`. Add a fixture
under `tests/fixtures/` and a test asserting the new flow is found (and its
sanitized variant is not). Rebuild (`pnpm build`) and re-run the suite.

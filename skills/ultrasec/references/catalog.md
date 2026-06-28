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
| ssrf | CWE-918 | high | `fetch`, `request`, `urlopen`, `axios`, `got` |
| xxe | CWE-611 | high | `parseString`, `parseFromString`, `fromstring`, `SAXParser`, `DocumentBuilder` |
| ldap | CWE-90 | high | `ldap.search`, `client.bind` (receiver-gated) |
| xss | CWE-79 | medium | `res.send`, `res.write`, `render_template_string` |
| crlf | CWE-93 | medium | `res.setHeader`, `res.header`, `addHeader` (receiver-gated) |
| proto | CWE-1321 | high | `_.merge`, `_.defaultsDeep`, `extend` (receiver-gated) |
| deserialize | CWE-502 | high | `pickle.loads`, `yaml.load`, `unserialize`, `readObject` |
| crypto | CWE-327 | medium | `md5`, `sha1`, `createCipher`, `DES` |
| redirect | CWE-601 | medium | `res.redirect` |
| buffer | CWE-120 | high | C/C++ best-effort: `strcpy`, `strcat`, `sprintf`, `gets`, `memcpy` |

Receiver-gated rules only match when the call's receiver is in a known set (e.g.
`db`/`collection`/`Model` for NoSQL) so common look-alikes (`Array.prototype.find`,
a plain `merge()`) don't flood the candidate list. Coverage is deepest for the web
stacks; `buffer` is a best-effort C/C++ scaffold — pair it with cppcheck/gosec.

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

## What needs YOU (not in the catalog)

Taint enumeration is structural. These classes need cross-file/semantic reasoning
and are your job to find and add: **broken access control / IDOR**, **missing
authorization**, **business-logic abuse**, **auth/session/SSO** flaws, **race
conditions**, **mass assignment**, **feature abuse & data leakage**, **chained
attacks**, **SSTI** in custom templating, and **ReDoS**. Hunt them with the
attacker-mindset angles and the non-taint taxonomy in
[hunting-heuristics.md](hunting-heuristics.md), and calibrate severity with
[severity-and-discipline.md](severity-and-discipline.md).

## Extending the catalog

Edit `src/catalog.ts`: add a `SinkRule` (callees + cwe + severity + languages), a
`SourceRule` (a regex tagged by language), or a `SanitizerRule`. Add a fixture
under `tests/fixtures/` and a test asserting the new flow is found (and its
sanitized variant is not). Rebuild (`pnpm build`) and re-run the suite.

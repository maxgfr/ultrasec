# Taint catalog & CWE coverage

The catalog (`src/catalog.ts`) is the deterministic half of taint enumeration:
**sources** (untrusted input), **sinks** (dangerous operations), and
**sanitizers** (neutralizers). It is recall-oriented — a spurious candidate costs
you a glance; a missed flow is a missed bug.

## Sinks → CWE

| kind | CWE | severity | example callees |
|------|-----|----------|-----------------|
| sql | CWE-89 | high | `query`, `execute`, `raw`, `executemany` |
| command | CWE-78 | critical | `exec`, `execSync`, `spawn`, `system`, `popen`, `Popen`, `shell_exec` |
| code | CWE-94 | high | `eval`, `Function`, `runInThisContext`, `compile` |
| path | CWE-22 | high | `readFile`, `writeFile`, `createReadStream`, `sendFile`, `open` |
| ssrf | CWE-918 | high | `fetch`, `request`, `urlopen`, `axios`, `got` |
| xss | CWE-79 | medium | `res.send`, `res.write`, `render_template_string` |
| deserialize | CWE-502 | high | `pickle.loads`, `yaml.load`, `unserialize`, `readObject` |
| crypto | CWE-327 | medium | `md5`, `sha1`, `createCipher`, `DES` |
| redirect | CWE-601 | medium | `res.redirect` |

## Sources

HTTP request input (`req.query/body/params/headers`, Flask `request.*`, PHP
`$_GET/$_POST`, servlet `getParameter`, Rails `params`, Go `r.URL/FormValue`),
CLI args (`process.argv`, `sys.argv`, `os.Args`), env (`process.env`,
`os.environ`, `getenv`), and stdin (`input()`).

## Sanitizers (hints)

Parameterized queries (`?`/`$1`/`:name` placeholders), argv-array exec
(`execFile`, `shlex.quote`, `escapeshellarg`), path confinement (`basename`,
`realpath`, `secure_filename`), HTML escaping (`escapeHtml`, `DOMPurify`,
`bleach`, `markupsafe`), safe loaders (`yaml.safe_load`, `JSON.parse`), and
type-coercion/validation (`parseInt`, `Number`, `validator.*`, `zod`/`Joi`). These
**lower confidence and annotate** a candidate — they do not auto-dismiss it; you
confirm the sanitizer actually covers the flow.

## What needs YOU (not in the catalog)

Taint enumeration is structural. These classes need cross-file/semantic reasoning
and are your job to find and add: **broken access control / IDOR**, **missing
authorization**, **business-logic abuse**, **auth/session/SSO** flaws, **race
conditions**, **mass assignment**, **SSTI** in custom templating, and **ReDoS**.

## Extending the catalog

Edit `src/catalog.ts`: add a `SinkRule` (callees + cwe + severity + languages), a
`SourceRule` (a regex tagged by language), or a `SanitizerRule`. Add a fixture
under `tests/fixtures/` and a test asserting the new flow is found (and its
sanitized variant is not). Rebuild (`pnpm build`) and re-run the suite.

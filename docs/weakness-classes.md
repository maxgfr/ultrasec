# Weakness classes, idiom packs and the AI hunt

Some bugs have no source→sink flow for the taint walk to follow: a secret compared with `===`,
a CSV whose cells are never neutralized, a client IP read from the first `X-Forwarded-For`
entry, an export route with no row limit, an app that sends no security headers, a logout that
leaves session chunks behind, an environment flag parsed by truthiness. Each was first caught
by hand on a Next.js audit and then hard-coded as a JavaScript idiom — which found it in that
stack and nowhere else, and aged with every framework release.

The model below separates what does not change (the class) from what does (the idiom), so a new
framework is new data and fixtures, never a new detector.

## The three layers

| layer | where | what it is | stable? |
|---|---|---|---|
| **Class** | `src/classes/registry.ts` | One entry per weakness: CWE, base severity, the **invariant** that makes code safe (source → sink → guard), what a valid **guard** looks like, a severity **rubric**, vulnerable/fixed **examples** in several languages. No framework is named. | yes |
| **Pack** | `src/classes/packs/*.ts` | The idioms one ecosystem (`node`, `python`, …) or one framework (`express`, `django`, …) writes a class with, as typed data: the unsafe line, the guard, the version range the data was validated on (`testedWith`), the documentation it was checked against (`sources`). A class that cannot occur in an ecosystem is declared `notApplicable` with the reason. | changes with frameworks |
| **Hunt** | `src/classes/hunt.ts`, via `investigate` | For a class × framework no pack settles, the invariant and examples are handed to the auditor, who finds the repository's own idioms and returns discoveries and **pack suggestions**. | per run |

One engine (`src/classes/engine.ts`) applies every pack. It knows four rule kinds and no
framework:

| kind | fires when | example |
|---|---|---|
| `line` | a code line (comments stripped by the sink matcher's own comment model) matches, no guard on the same line, optional context within N lines above, optional file gate | `=== process.env.API_KEY` |
| `file` | the file produces the thing (gates on the raw text), cites the first/last anchor line, and no guard anywhere in its code | a CSV writer with no `=+-@` neutralization |
| `route-query` | the file is an export route (by path, or a route declaration whose path/name says export) and a query statement has no bound | `User.objects.all()` in `def export_users(request)` |
| `absent` | the line where a protection would be registered exists, and the protection is in neither that file nor (optionally) anywhere in the app's own tree / package | `express()` with no `helmet()` |

Every finding is a candidate grounded on a resolvable `[file:line]`. The rules ported from the
original detectors still report under their historical shapes (`webconfig/csv-formula`,
`authtokens/secret-compare-timing`, …), so finding ids did not change; idioms added since report
under the class (`Weakness — <class title>`).

## The classes

| id | CWE | invariant, in short |
|---|---|---|
| `timing-unsafe-secret-compare` | CWE-208 | a caller-supplied value is compared to a shared secret in constant time |
| `csv-formula-injection` | CWE-1236 | every non-constant CSV cell starting with `= + - @ \t \r` is neutralized |
| `client-ip-first-xff` | CWE-348 | the client address comes from a trusted proxy, counted from the right |
| `unbounded-public-export` | CWE-770 | a public/export route bounds the rows one request materializes |
| `security-headers-absent` | CWE-693 | responses carry the browser protections, by framework default, middleware or proxy |
| `session-cookie-chunks-on-logout` | CWE-613 | logout invalidates every chunk of a split session cookie |
| `env-bool-coercion` | CWE-704 | an environment flag is true only for an explicit true spelling |

## The first lot of packs

| ecosystem | ecosystem pack | framework packs (`testedWith`) |
|---|---|---|
| (any) | `common` — `.split(",")[0]` next to X-Forwarded-For | |
| Node | `node` | `nextjs` (>=12 <17), `express` (>=4 <6), `nestjs` (>=9 <13), `fastify` (>=4 <6); header posture only: `koa`, `hono`, `elysia` |
| Python | `python` | `django` (>=3.2 <7), `flask` (>=2 <4), `fastapi` (>=0.100 <1) |
| Java | `java` | `spring` (Spring Boot >=2.7 <5) |
| Go | `go` | `net-http` (Go >=1.18 <2), `gin` (>=1.7 <2) |
| Ruby | `ruby` | `rails` (>=6 <9) |
| PHP | `php` | `laravel` (>=9 <14) |

The security-header posture is the class where defaults differ most, and each pack encodes its
framework's documented default rather than a blanket "no helmet":

- **Django** sends X-Content-Type-Options, Referrer-Policy and Cross-Origin-Opener-Policy through
  `SecurityMiddleware` and X-Frame-Options: DENY through `XFrameOptionsMiddleware`; HSTS and CSP
  need settings. The pack reports a `MIDDLEWARE` list missing either middleware, or a default
  switched off in settings.
- **Rails** sends X-Frame-Options, X-Content-Type-Options and Referrer-Policy by default
  (`default_headers`), but no CSP until `config/initializers/content_security_policy.rb` sets one:
  the pack reports the CSP absence and a cleared `default_headers`.
- **Spring Security** writes its default headers when it is on the classpath; the pack reports an
  application without it, and `headers(h -> h.disable())`.
- **Express, Fastify, NestJS, Next.js, Flask, FastAPI, Gin, net/http, Laravel** send none by
  default; the pack reports the app construction with no header middleware in the file (or, for
  Flask, Gin, net/http and Laravel, in the whole package). NestJS 12.1's `useSecurityHeaders()`
  counts as one.
- **Gin** also trusts every proxy by default, so `c.ClientIP()` without `SetTrustedProxies` is a
  first-hop X-Forwarded-For read.

The documentation each default was checked against is in the pack's `sources`.

## Frameworks, versions and coverage

`src/frameworks.ts` reads every package's manifest (package.json + npm/pnpm/yarn lock,
requirements/pyproject/Pipfile + poetry/uv/pdm/Pipfile locks, pom.xml/build.gradle, go.mod,
Gemfile + Gemfile.lock, composer.json + composer.lock) and records each framework with its
installed version — or the floor of its declared range, labelled `declared` — and the
`file:line` that declares it, in `manifest.frameworks`. One entry per package directory, so a
monorepo's apps keep their own versions.

`manifest.weaknessClasses` is then the class × framework matrix:

| state | meaning |
|---|---|
| `deterministic` | a pack's rules ran for this cell |
| `not-applicable` | a pack declares the class impossible here, with the reason |
| `not-covered` | no pack has an idiom for it |
| `ai-hunt` | `investigate` emitted the cell's hunt (overlaid by `coverage` from the run) |
| `ai-hunted` | an `investigate --apply` recorded the hunt as worked |

A cell is **degraded** (`degraded: "<why>"`) when the framework has no pack — only its
ecosystem's language idioms ran — or its version is outside the pack's `testedWith`. The rules
still run as a floor, but the cell is reported and hunted, never silently trusted. `coverage`
renders the matrix (and `coverage --classes --json` prints it); REPORT.md carries it too.

## The hunt and PACK-SUGGESTIONS.json

`investigate` appends one item per degraded or uncovered cell to `INVESTIGATE.todo.json`, after
the attack-surface regions: `region` is the hunt id (`hunt:<class>:<framework>[@<dir>]`) and a
`hunt` object carries the invariant, guard, rubric, examples (framework's language first), the
framework and version, why the packs fall short, and which rules already ran. A cell a pack covers
emits nothing.

The auditor answers in the same `INVESTIGATE.json`:

```json
{
  "discoveries": [{ "title": "…", "category": "other", "severity": "medium", "cwe": "CWE-770",
                    "message": "…", "file": "src/export.js", "line": 2,
                    "hunt": "hunt:unbounded-public-export:koa" }],
  "idioms": [{ "hunt": "hunt:unbounded-public-export:koa", "class": "unbounded-public-export",
               "framework": "koa", "kind": "unsafe", "pattern": "ctx.body = await Model.findAll()",
               "regex": "ctx\\.body\\s*=\\s*await\\s+\\w+\\.findAll\\(\\s*\\)", "file": "src/export.js",
               "line": 2, "note": "Koa routes return the query result as the body" }],
  "hunted": ["hunt:unbounded-public-export:koa"]
}
```

Discoveries go through the usual ingest (citation checked, duplicates folded, then
`verify`/`check`). Idioms are citation checked the same way and merged into the run's
`PACK-SUGGESTIONS.json`:

```json
{
  "schema": 1,
  "note": "Proposals recognized by the AI hunt. The engine NEVER applies them: …",
  "hunted": ["hunt:unbounded-public-export:koa"],
  "suggestions": [{ "hunt": "…", "class": "unbounded-public-export", "framework": "koa",
                    "kind": "unsafe", "pattern": "…", "regex": "…", "file": "src/export.js",
                    "line": 2, "note": "…", "evidence": "ctx.body = await Order.findAll();",
                    "seenOn": "koa 2.15.0", "pack": "new pack: koa" }]
}
```

`kind` is `unsafe` (the line that breaks the invariant) or `guard` (the line that establishes
it). `regex` is optional and must compile. `evidence` is the cited line as read at apply time,
`seenOn` the framework version from the manifest, `pack` the pack it would extend. Nothing in
this file is ever applied.

## Adding a class

1. Add its id to `CLASS_IDS` (`src/classes/types.ts`) and its entry to `CLASSES`
   (`src/classes/registry.ts`): invariant, guard, rubric, note, and examples in at least two
   languages.
2. For each ecosystem of the first lot, add its idioms to the ecosystem or framework packs — or a
   `notApplicable` entry saying why the class cannot occur there.
3. Add a vulnerable and a fixed variant per cell under `tests/fixtures/classes/<eco>-vuln/` and
   `<eco>-fixed/`, and the cells to `tests/fixtures/classes/expectations.json`.
4. `pnpm test` — `classes-recall.test.ts` refuses a class whose ecosystems are neither covered by
   a cell nor declared not applicable, and `classes-registry.test.ts` checks the data itself.
5. Map its CWE in a coverage standard (`src/coverage.ts`) if none claims it yet.

## Adding a pack (a framework)

1. Add the framework to `FRAMEWORKS` in `src/frameworks.ts` (id, ecosystem, the dependency names
   that declare it) if it is not detected yet.
2. Add a `Pack` with `framework`, `testedWith` (the versions your fixtures declare) and `sources`
   (the documentation the defaults were checked against), in the ecosystem's file under
   `src/classes/packs/`, and register it in that file's `*_PACKS` list.
3. Express the idioms with the four rule kinds; reuse the shared vocabulary in `packs/shared.ts`
   and the ecosystem's query idioms instead of copying them. Prefer reporting under the class
   (`note:` explains the idiom); a `requiresFramework` gate is for anchors that are weak evidence
   on their own.
4. Add fixtures and expectation cells as for a class. The recall test also checks that every
   framework in the fixtures is detected inside its pack's `testedWith`.
5. Rebuild the bundle (`pnpm run build`) and run `pnpm run check:build`.

## Promoting a suggestion from the AI hunt

A suggestion is evidence that an idiom exists in one repository, not proof it is general.

1. Read the cited `file:line` and the hunt's discoveries: is the idiom the framework's (worth a
   pack rule) or this codebase's own wrapper (worth a line in its CONTEXT.md instead)?
2. Turn it into data: a rule in the framework's pack (or a new pack — see above) whose `match`/
   `anchor`/`unless` generalizes the suggested `regex` without catching the guard.
3. Write the synthetic pair: the vulnerable shape the suggestion describes, and the fixed shape
   with the guard. Never copy the audited repository's code into the fixtures.
4. Add the expectation cell; widen `testedWith` only to versions a fixture declares.
5. `pnpm test` (the recall matrix must stay green on every other cell), then rebuild.

Until then the cell stays degraded or uncovered, and the next run hunts it again.

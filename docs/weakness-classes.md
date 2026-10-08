# Weakness classes, idiom packs and the AI hunt

Some bugs have no source→sink flow for the taint walk to follow: a secret compared with `===`,
a CSV whose cells are never neutralized, a client IP read from the first `X-Forwarded-For`
entry, an export route with no row limit, an app that sends no security headers, a logout that
leaves session chunks behind, an environment flag parsed by truthiness — and the framework
postures: a cookie without its flags, forwarded headers trusted from anyone, a body read with
no limit, GraphQL introspection left on, CSRF protection switched off, debug mode in
production. Each was first caught by hand or hard-coded for one or two stacks — which found it
there and nowhere else, and aged with every framework release.

The model below separates what does not change (the class) from what does (the idiom), so a new
framework is new data and fixtures, never a new detector. Anything the data does not cover
deterministically is not silent: it is a cell of the matrix, and `investigate` hunts it.

## The three layers

| layer | where | what it is | stable? |
|---|---|---|---|
| **Class** | `src/classes/registry.ts` | One entry per weakness: CWE, base severity, the **invariant** that makes code safe (source → sink → guard), what a valid **guard** looks like, a severity **rubric**, vulnerable/fixed **examples** in several languages. No framework is named. | yes |
| **Stack** | `src/stack.ts` | One row per web framework or library: its ecosystem, the dependency names that declare it per registry, its languages. What the context brief names and what becomes a matrix column. | grows with frameworks |
| **Pack** | `src/classes/packs/*.ts` | The idioms one ecosystem (`node`, `python`, …), one framework (`express`, `django`, …) or one library (`next-auth`) writes a class with, as typed data: the unsafe line, the guard, the version range the data was validated on (`testedWith`), the documentation it was checked against (`sources`), and the names its auth/throttle guards go by (`markers`). A class that cannot occur is declared `notApplicable` with the reason; a class that applies but has no idiom yet is declared `{ hunt: reason }`. | changes with frameworks |
| **Hunt** | `src/classes/hunt.ts`, via `investigate` | For a class × framework no pack settles, the invariant and examples are handed to the auditor, who finds the repository's own idioms and returns discoveries and **pack suggestions**. | per run |

One engine (`src/classes/engine.ts`) applies every pack. It knows five rule kinds and no
framework — `tests/classes-no-framework-names.test.ts` fails if the engine, the matrix
(`coverage.ts`) or the hunt (`hunt.ts`) ever spells one in code:

| kind | fires when | example |
|---|---|---|
| `line` | a code line (comments stripped by the sink matcher's own comment model) matches, no guard on the same line, optional context within N lines above, optional file gate | `=== process.env.API_KEY` |
| `file` | the file produces the thing (gates on the raw text), cites the first/last anchor line, and no guard anywhere in its code | a CSV writer with no `=+-@` neutralization |
| `route-query` | the file is an export route (by path, or a route declaration whose path/name says export) and a query statement has no bound | `User.objects.all()` in `def export_users(request)` |
| `absent` | the line where a protection would be registered exists, and the protection is in neither that file nor (optionally) anywhere in the app's own tree / package | `express()` with no `helmet()` |
| `call` | a call whose options decide its safety: one finding per protective flag its balanced arguments (or the statement it starts) lack, each under its own shape | `res.cookie("sid", t)` → no HttpOnly, no Secure |

A `line` rule reads the comment-stripped code, or with `text: "raw"` the raw line comments
included (a commented-out `# protect_from_forgery` IS the finding). Rules can also read
configuration formats no code language claims — `properties`, `yaml`, `conf` — where a
framework's settings live as often as in code (Spring's `application.properties`).

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
| `insecure-session-cookie` | CWE-614 | a session cookie is written with HttpOnly, Secure and a SameSite policy |
| `proxy-headers-trusted` | CWE-290 | X-Forwarded-* are trusted only from the proxies the deployment runs |
| `request-body-unbounded` | CWE-770 | every request body the app buffers has an explicit size limit |
| `graphql-introspection-enabled` | CWE-200 | production GraphQL answers no introspection and serves no IDE |
| `csrf-protection-disabled` | CWE-352 | state-changing routes reachable with ambient credentials keep a CSRF guard |
| `debug-mode-enabled` | CWE-489 | the deployed app runs with the framework's debug mode off |

The last six were detectors in `src/webconfig.ts` that knew one or two frameworks in code. They
moved onto packs with their original shapes (`webconfig/cookie-secure`, `webconfig/trust-proxy`,
…), so their findings keep their ids; what stays in `webconfig.ts` is framework-agnostic (CORS,
TLS verification, literal header values, directory listing).

## The packs

| ecosystem | ecosystem pack | framework / library packs (`testedWith`) |
|---|---|---|
| (any) | `common` — `.split(",")[0]` next to X-Forwarded-For; introspection in YAML/conf | |
| Node | `node` | `nextjs` (>=12 <17), `express` (>=4 <6), `nestjs` (>=9 <13), `fastify` (>=4 <6), `koa` (>=2 <4), `hono` (>=3 <5), `elysia` (>=0.7 <2); libraries `next-auth` (>=4 <6), `trpc` (>=10 <12, guard markers only) |
| Python | `python` | `django` (>=3.2 <7), `flask` (>=2 <4), `fastapi` (>=0.100 <1) |
| Java | `java` | `spring` (Spring Boot >=2.7 <5) |
| Go | `go` | `net-http` (Go >=1.18 <2), `gin` (>=1.7 <2) |
| Ruby | `ruby` | `rails` (>=6 <9) |
| PHP | `php` | `laravel` (>=9 <14) |
| Elixir, Rust, .NET, Deno | — | none: detected, every class hunted |

A **library pack** (`library: "<stack id>"`) holds a library's idioms — NextAuth's chunked
session cookie is NextAuth's, not Node's. Its cells count for every framework column of the
package that declares the library, and its `testedWith` is checked against the LIBRARY's
version: NextAuth 6 degrades that cell and hunts it.

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

`src/frameworks.ts` reads every package's manifest against the one stack table
(`src/stack.ts`): package.json + npm/pnpm/yarn lock, requirements/pyproject/Pipfile/setup.py +
poetry/uv/pdm/Pipfile locks, pom.xml/build.gradle(.kts) + gradle.properties, go.mod,
Gemfile + Gemfile.lock, composer.json + composer.lock, mix.exs + mix.lock, Cargo.toml +
Cargo.lock, *.csproj (versioned by its target framework), deno.json(c). Each web framework and
library is recorded with its installed version — or the floor of its declared range, labelled
`declared` — and the `file:line` that declares it. One entry per package directory, so a
monorepo's apps keep their own versions. The context brief reads the same detection, so the
brief and the matrix cannot disagree about the stack.

**A framework the table does not know** still gets a column, `unknown`, every class hunted, when
a package with no known web framework (in it or above it) shows one in its code: route
declarations (a verb, an absolute path literal and a handler — an HTTP client call never counts)
or request handlers the walk already counts as HTTP entry points. It takes two evidence lines,
or one when the package declares a dependency whose name says it serves HTTP and no table row
explains it; test files never count. The heuristic is data (`ROUTE_EVIDENCE`,
`HTTP_DEPENDENCY` in `src/stack.ts`).

`manifest.frameworks` holds the columns (known and `inferred`) and the libraries a pack or a
catalog row is written against (`kind: "library"`). `manifest.weaknessClasses` is the matrix,
every class plus one `taint-catalog` row per column:

| state | meaning |
|---|---|
| `deterministic` | a pack's rules ran for this cell |
| `not-applicable` | a pack declares the class impossible here, with the reason |
| `not-covered` | no pack has an idiom for it |
| `ai-hunt` | `investigate` emitted the cell's hunt (overlaid by `coverage` from the run) |
| `ai-hunted` | an `investigate --apply` recorded the hunt as worked |

Every class gets a cell in every column. A cell is **degraded** (`degraded: "<why>"`) when:

- the framework has no pack — only language idioms ran (a language pack counts for a column only
  where its rules read the framework's language: Ktor gets the JVM idioms, Fresh the JavaScript
  ones);
- the framework's version is outside its pack's `testedWith` — the WHOLE column, language idioms
  included: a framework release nobody ran the rules against may hand the code its input
  another way;
- a library pack decided the cell and the library's version is outside the library pack's range;
- the framework pack declares the class `{ hunt }` — that outranks a language floor that happened
  to match.

A framework with no pack in an ecosystem with no pack (Phoenix, axum, ASP.NET Core) is a column of
`not-covered` cells, one hunt each. The rules still run as a floor, but a degraded cell is
reported and hunted, never silently trusted. `coverage` renders the matrix (and
`coverage --classes --json` prints it); REPORT.md carries it too.

### The `taint-catalog` row

The taint catalog (`src/catalog.ts`) is mostly language-level, but some rows are one framework's
API: tRPC `.input(…)`, Next.js `searchParams`, the App-Router and Server Action conventions, Hono
`c.req`, Spring's binding annotations, Phoenix `conn.params`, tRPC's callback refutation on SQL
sinks. Those rows carry `idioms: [{ framework, testedWith }]`. The matrix's `taint-catalog` row
reads them: deterministic where the column's framework (or a library declared with it) has
labelled rows in range; degraded and hunted when the version is outside them, or when only the
language-level request shapes apply; not covered when not even those do. Its hunt asks for the
framework's input APIs and routes as the repository writes them — an input API the catalog
cannot see blinds every taint class at once. The rows stay beside the matcher that applies them;
the label is what ties them to the matrix.

## Guard markers

The guard matrix (`guards`), the context brief and the dossier look for authentication and
rate-limiting checks with one vocabulary (`src/classes/markers.ts`): a generic floor
(`requireAuth`, `verifyToken`, `rateLimit`, …) plus each pack's `markers`. `global` names no other
stack uses are matched in every repository (`getServerSession`, `@PreAuthorize`,
`login_required`, …: the default vocabulary is byte-identical to the one that was hard-coded);
`detected` names count only where the pack's framework or library is in the manifest — tRPC
`protectedProcedure`, NextAuth v5 `await auth()`, a FastAPI `Depends(get_current_user)`, a Laravel
`->middleware('auth')`, Rack::Attack.

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
`.work/PACK-SUGGESTIONS.json`:

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
2. For each ecosystem with a language pack, add its idioms to the ecosystem or framework packs —
   or a `notApplicable` entry saying why the class cannot occur there, or `{ hunt: reason }` when
   it can and no idiom is encoded yet.
3. Add a vulnerable and a fixed variant per cell under `tests/fixtures/classes/<eco>-vuln/` and
   `<eco>-fixed/`, and the cells to `tests/fixtures/classes/expectations.json`.
4. `pnpm test` — `classes-recall.test.ts` refuses a class whose ecosystems are neither covered by
   a cell nor declared (not applicable / hunted), and a framework-level class with a first-lot
   framework left undecided; `classes-registry.test.ts` checks the data itself.
5. Map its CWE in a coverage standard (`src/coverage.ts`) if none claims it yet.

## Adding a pack (a framework)

1. Add the framework to `STACK` in `src/stack.ts` (id, ecosystem, the dependency names per
   registry, its languages if not the ecosystem's) if it is not detected yet. A new manifest
   format is a reader in `src/frameworks.ts`. From here on the framework is a hunted column.
2. Add a `Pack` with `framework`, `testedWith` (the versions your fixtures declare) and `sources`
   (the documentation the defaults were checked against), in the ecosystem's file under
   `src/classes/packs/`, and register it in that file's `*_PACKS` list.
3. Express the idioms with the four rule kinds; reuse the shared vocabulary in `packs/shared.ts`
   and the ecosystem's query idioms instead of copying them. Prefer reporting under the class
   (`note:` explains the idiom); a `requiresFramework` gate is for anchors that are weak evidence
   on their own.
4. Add fixtures and expectation cells as for a class. The recall test also checks that every
   framework in the fixtures is detected inside its pack's `testedWith`.
5. Give it `markers` if its guards have names of their own, and label the catalog rows that are
   its API (`idioms` in `src/catalog.ts`).
6. Rebuild the bundle (`pnpm run build`) and run `pnpm run check:build`.

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

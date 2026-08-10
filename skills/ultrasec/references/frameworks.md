# Framework notes

The same vulnerability class hides in a different place in every stack, and the sanitizer that
works in one is a no-op in another. This is the per-framework knowledge that turns a generic
lens ([hunting-heuristics.md](hunting-heuristics.md)) into a specific place to look.

For each stack: **where routes and guards live** (so you can diff the two lists),
**what's auto-escaped** (so you don't report a non-finding), **the ORM's escape hatches** (where
the real SQLi is), and **the stack-specific traps**.

`context --repo <dir>` detects the framework and lists entry points, auth-middleware candidates
and sanitizers — start from `CONTEXT.scaffold.json`, then use the notes below to find what it
couldn't.

---

## Express / Node

**Routes** `app.get/post/…`, `router.*`, and anything mounted with `app.use`. Order matters: a
guard registered *after* a route doesn't protect it, and `app.use('/api', guard)` protects only
what's mounted under that path.
**Guards** middleware functions; check they call `next()` on success and *return* on failure —
`if (!ok) res.status(401).json(...)` without a `return` falls through to the handler.

**Traps:**

- **`req.query` is `qs`-parsed**, so `?a[b]=c` yields an **object**, and `?a=1&a=2` yields an
  **array**. Code that assumes a string gets type-confused: `{ $ne: null }` reaches Mongo
  (NoSQL injection with no obvious sink), and `String.prototype` methods throw or silently
  behave differently. Check every handler that does `req.query.x.something`.
- **`res.send()` picks the content type from the argument**: a string is `text/html` (so
  reflected XSS), an object is `application/json` (so it is not). A finding that assumed HTML
  where the code sends an object is FP-4.
- **Prototype pollution** through `Object.assign`/spread/`lodash.merge` of `req.body`, and
  through `qs` itself on older versions.
- **Error handlers** — a 4-arg middleware is required; a 3-arg one is silently treated as a
  normal handler, so errors fall through to the default handler that leaks stack traces when
  `NODE_ENV !== 'production'`.
- `helmet`, `cors`, `express-rate-limit` present ≠ configured: read the options. `cors()` with
  no arguments is `Access-Control-Allow-Origin: *`.

**SQL** — `mysql`/`pg` `query(sql)` with one argument is raw; the second parameter array is what
binds. Knex `.raw()`, `.whereRaw()`, Sequelize `sequelize.query` without `replacements`, Prisma
`$queryRawUnsafe` (`$queryRaw` with a tagged template is safe). TypeORM `query()` and
`createQueryBuilder().where("... " + x)`.

## Next.js

Everything above, plus:

- **Middleware `matcher`** is the authorization boundary in most Next apps and it is a *path
  pattern*. Anything outside the matcher runs unguarded. Check for trailing-slash, case, encoded
  path segments, and `/api` routes deliberately excluded "for performance".
- **Server Actions are unauthenticated POST endpoints** with a stable id. They are callable
  directly, not only from the form you see. Every action needs its own authorization check —
  the page's guard does not apply.
- **Route handlers vs pages** — `app/api/**/route.ts` doesn't inherit page-level checks.
- **`dangerouslySetInnerHTML`** is the XSS sink; React escapes text children but **not**
  `href`/`src` attributes, so `<a href={userUrl}>` accepts `javascript:`.
- **Server/client boundary leaks** — a secret imported into a component that ends up in the
  client bundle; `NEXT_PUBLIC_*` is public by definition.
- Cache directives (`revalidate`, `force-cache`) on a personalized response cause cross-user
  cache leakage.

## Django

**Routes** `urls.py` (`path`/`re_path`). **Guards** `@login_required`, `@permission_required`,
`PermissionRequiredMixin`, DRF `permission_classes`. In DRF the trap is
`DEFAULT_PERMISSION_CLASSES` set to `AllowAny` globally, with per-view classes assumed.

**Traps:**

- **ORM escape hatches** — `.extra(where=[...])`, `RawSQL()`, `.raw()`, `cursor.execute(f"...")`.
  `filter()` is parameterized; `extra`/`RawSQL` are not, and they are how Django SQLi happens.
- **`SECRET_KEY`** committed or defaulted: session cookies are signed with it, so leakage is
  session forgery — CRITICAL, not "hardcoded secret, medium".
- **`DEBUG = True`** in a production settings path: full traceback with settings and env.
- **`ALLOWED_HOSTS = ['*']`** enables Host-header poisoning (password-reset links).
- Templates autoescape by default — so a reflected value in a template is **not** XSS, unless
  it passes `|safe`, `mark_safe()`, `format_html` with an unescaped arg, or lands in a
  `<script>` block or an unquoted attribute.
- `@csrf_exempt`, and `SessionAuthentication` swapped for something that skips CSRF.
- Mass assignment via a `ModelForm`/serializer with `fields = '__all__'`.

## Flask / FastAPI

**Routes** `@app.route`, `@router.get`. **Guards** decorators, or FastAPI `Depends(...)` — a
dependency declared on the app is global, one declared per route is not; check which.

- `render_template_string(user_input)` is **SSTI → RCE** in Jinja2, not XSS. `{{7*7}}` returning
  `49` is the proof. `render_template` with a variable is safe.
- Jinja2 autoescapes `.html` templates; a `.txt` template or a manually constructed `Template`
  does **not**.
- `SECRET_KEY` (Flask session cookies are signed-not-encrypted, and readable client-side).
- `app.run(debug=True)` exposes the Werkzeug console — RCE if reachable.
- FastAPI: a Pydantic model validates types, not authorization. `response_model` is what stops
  over-fetching leaks; without it the whole ORM object serializes, including hashes and internal
  flags.

**SQL** — SQLAlchemy `text()` with f-string interpolation, `.execute(raw)`, `Query.from_statement`.

## Rails

**Routes** `config/routes.rb` — `resources :x` generates seven actions; auditing only the two you
see in the controller misses five. **Guards** `before_action`, with `only:`/`except:` lists that
drift as actions are added.

- **Mass assignment** — `params.permit!`, `permit(...)` with a `role`/`admin` field, or
  `update(params[:user])` outside strong params.
- **SQL** — `find_by_sql`, `where("name = '#{x}'")`, `order(params[:sort])` (order/limit take raw
  SQL), `pluck` with an interpolated column.
- ERB autoescapes; `raw`, `html_safe`, `<%== %>` and `sanitize` with a permissive config don't.
- `secret_key_base` leakage ⇒ signed/encrypted cookie forgery ⇒ (historically) deserialization RCE.
- `protect_from_forgery with: :null_session` on an API controller that still uses cookies.

## Spring / Java

**Routes** `@RequestMapping`/`@GetMapping` etc. **Guards** `@PreAuthorize`/`@Secured` plus the
`SecurityFilterChain`.

- **`@PreAuthorize` is proxy-based**: it does nothing on a private method, a method called from
  within the same bean (self-invocation), or a `final` class under CGLIB. A guard that silently
  doesn't run is worse than no guard.
- `SecurityFilterChain` matcher ordering — `permitAll()` on a broad pattern earlier in the chain
  wins over a later `authenticated()`.
- **SpEL injection** — attacker input into `@Value`, `parseExpression`, or a `@PreAuthorize`
  string. RCE.
- **SQL** — `@Query(nativeQuery = true)` with concatenation; `EntityManager.createQuery` built by
  `+`; JPA sort/`Pageable` fields reaching an `ORDER BY`.
- **Deserialization** — `ObjectInputStream`, Jackson `enableDefaultTyping`/`@JsonTypeInfo`,
  SnakeYAML `new Yaml()` (use `new Yaml(new SafeConstructor())`), XStream.
- XXE: `DocumentBuilderFactory`/`SAXParserFactory`/`XMLInputFactory` default to entity resolution
  **on**; look for `FEATURE_SECURE_PROCESSING` or explicit `setFeature(...disallow-doctype...)`.
- Thymeleaf autoescapes with `th:text`, not with `th:utext`; expression preprocessing `__${…}__`
  is an SSTI sink.
- Actuator endpoints (`/actuator/env`, `/heapdump`) exposed without auth.

## Laravel / PHP

- **Mass assignment** — `$fillable` vs `$guarded = []`, `Model::create($request->all())`,
  `->forceFill()`.
- **SQL** — `DB::raw`, `whereRaw`, `orderByRaw`, and `selectRaw` with interpolation.
- Blade `{{ }}` escapes; `{!! !!}` does not.
- `APP_DEBUG=true` in production (Ignition/Whoops pages have been RCE).
- `unserialize()` on request data; the `APP_KEY` signs cookies and encrypts payloads —
  leakage is forgery plus deserialization.
- Native PHP: loose comparison `==` on hashes ("magic hash" collisions), `extract()` on request
  arrays, `include`/`require` with user input (LFI→RCE).

## Go

- **`text/template` vs `html/template`** — only the latter escapes contextually. A handler that
  imports `text/template` and writes HTML is an XSS finding, and the import line is the citation.
- **SQL** — `fmt.Sprintf` into `db.Query`; the `?`/`$1` placeholder form is what binds. `sqlx.In`
  for lists.
- `os/exec.Command("sh", "-c", …)` reintroduces the shell that `exec.Command(name, args...)`
  avoids.
- Path handling: `filepath.Join` **cleans but does not confine** — `filepath.Join(base, "../..")`
  escapes. Confinement needs an explicit prefix check after `filepath.Abs`/`EvalSymlinks`.
- `math/rand` for tokens instead of `crypto/rand`.
- `http.ServeMux` matches by prefix when the pattern ends in `/` — a guard registered on
  `/admin` does not cover `/admin/` sub-paths in older mux versions.
- `govulncheck` is reachability-aware, so its findings carry more weight than a plain lockfile
  scan — see [supply-chain.md](supply-chain.md).

## Rust

Memory safety is not the audit surface — logic is. Look for `unsafe` blocks (and what invariant
they assume), `.unwrap()`/`.expect()` on attacker-influenced input (DoS by panic), integer
overflow in release builds (wrapping by default), `Command::new("sh").arg("-c")`, SQL built with
`format!` instead of `sqlx` macros/bind parameters, and `serde` with `deny_unknown_fields`
missing where the struct backs an authorization decision.

---

## Cloud / Kubernetes / IaC

The `cloud` detector (`scan`, always on) enumerates the statically-decidable
misconfigurations — privileged containers, host namespaces/paths, wildcard IAM
(`Action:*`+`Resource:*`), public principals/storage, ingress from `0.0.0.0/0`,
encryption switched off (`storage_encrypted = false`), publicly-reachable
instances (`publicly_accessible = true`), credentials hardcoded in IaC, and a
hardcoded instance-metadata endpoint (`169.254.169.254` /
`metadata.google.internal`). It is a zero-dependency baseline that fires without
`checkov` and folds into it (via the correlator) when present.

Two precision rules worth knowing, both measured on TerraGoat. **Direction
matters**: `0.0.0.0/0` on an *egress* rule is the normal "may reach the internet"
case and is not reported — only *ingress* from the world is. And the
resource-shaped rules (encryption, public instance, hardcoded credential) run on
**infrastructure files only** (`.tf/.tfvars/.hcl/.yaml/.yml/.json`): a credential
in application code is `gitleaks`' job, which has 221 tuned rules where this
module has one regex. A reference — `var.password`, `${var.x}`,
`data.vault_generic_secret…` — is the *correct* pattern and is never flagged.

The half it can't decide is reachability, and that is `investigate --lens cloud`:

- **SSRF → metadata.** Can any user-controlled URL reach the metadata endpoint?
  That turns a generic SSRF into short-lived cloud credentials — the highest-yield
  cloud bug. The `cloud-metadata` finding marks where the endpoint is named; the
  lens asks whether a source can steer a request there without an allow-list.
- **Over-broad IAM in context.** A wildcard policy is a candidate; whether the
  role is actually assumed on a reachable path (and what it can then touch) is the
  judgment call.
- **Secrets from env / mounted files.** Instance or CI secrets a compromised
  container can read and exfiltrate — see also the `secret` category and `privacy`.
- **Container escape.** `privileged`/`hostPath`/`hostNetwork` turn an app bug into
  node takeover — rate the blast radius accordingly.

For a target that is a live cloud account, a running cluster, or a binary/image
(not source), use `ultrasec route` to get the right external toolkit (prowler,
ScoutSuite, kube-hunter, trivy image…).

## When the stack isn't listed

Ask the same four questions and answer them from the code: where are routes declared, where are
guards attached and what silently disables them, what does the template layer escape by default,
and what is the ORM's raw escape hatch. Record the answers in `CONTEXT.md` — every later stage
reasons with it, and the next auditor inherits it.

import { CATALOG_ROW, type ClassId, type HuntSubject, type MatrixRowId, type WeaknessClass } from "./types.js";

// The weakness classes, defined once and independently of any framework.
//
// Each entry is what an auditor (or the AI hunt) needs to recognize the class
// in a stack nobody wrote a pack for: the invariant that makes code safe, what
// a real guard looks like, and the same bug in several languages. Packs
// (packs/*.ts) encode how a given ecosystem writes it; this file never names an
// idiom a framework could rename.

export const CLASSES: Record<ClassId, WeaknessClass> = {
  "timing-unsafe-secret-compare": {
    id: "timing-unsafe-secret-compare",
    title: "Secret compared with a non-constant-time operator",
    cwe: "CWE-208",
    severity: "medium",
    category: "crypto",
    invariant:
      "A value the caller supplies (header, query, body) is compared to a shared secret (API key, bearer token, webhook secret, password) by an operation whose running time does not depend on how many leading bytes match.",
    guard:
      "A constant-time comparison of equal-length inputs (ideally fixed-length digests of both): Node `crypto.timingSafeEqual`, Python `hmac.compare_digest`, Go `subtle.ConstantTimeCompare`/`hmac.Equal`, Java `MessageDigest.isEqual`, Ruby `ActiveSupport::SecurityUtils.secure_compare`, PHP `hash_equals`. A presence check (`=== undefined`) is not a comparison.",
    rubric:
      "medium for a static shared secret that is the whole authentication of a route; low when the endpoint is rate-limited and the secret is long and random, or the comparison is on a hash; high only with a demonstrated remote timing oracle (local network, many samples).",
    note: "A credential is compared with an operator that returns at the first differing byte, so response time leaks how much of a guess is right. Compare fixed-length digests with the platform's constant-time helper.",
    examples: [
      {
        language: "javascript",
        vulnerable: "if (req.headers.authorization !== `Bearer ${process.env.API_TOKEN}`) return res.sendStatus(401);",
        fixed:
          'const a = createHash("sha256").update(req.headers.authorization ?? "").digest();\nconst b = createHash("sha256").update(`Bearer ${process.env.API_TOKEN}`).digest();\nif (!timingSafeEqual(a, b)) return res.sendStatus(401);',
      },
      {
        language: "python",
        vulnerable: 'if request.headers.get("X-Api-Key") != os.environ["API_KEY"]:\n    abort(401)',
        fixed: 'if not hmac.compare_digest(request.headers.get("X-Api-Key", ""), os.environ["API_KEY"]):\n    abort(401)',
      },
      {
        language: "go",
        vulnerable: 'if r.Header.Get("X-Api-Key") != os.Getenv("API_KEY") {',
        fixed: 'if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Api-Key")), []byte(os.Getenv("API_KEY"))) != 1 {',
      },
      {
        language: "ruby",
        vulnerable: 'head :unauthorized unless request.headers["X-Api-Key"] == ENV["API_KEY"]',
        fixed: 'head :unauthorized unless ActiveSupport::SecurityUtils.secure_compare(request.headers["X-Api-Key"].to_s, ENV["API_KEY"])',
      },
    ],
  },
  "csv-formula-injection": {
    id: "csv-formula-injection",
    title: "CSV cells written without formula neutralization",
    cwe: "CWE-1236",
    severity: "medium",
    category: "config",
    invariant:
      "Every cell of a CSV a user may open in a spreadsheet, whose value is not a constant (request data, or database rows — second-order), is neutralized when it starts with `=`, `+`, `-`, `@`, a tab or a carriage return.",
    guard:
      "A per-cell function that prefixes such a value with `'` (OWASP CSV injection), applied to every non-constant cell before the writer/join; or a writer configured to do it (Python `defusedcsv`). Quoting alone is not a guard.",
    rubric:
      "medium for an export a privileged user opens (admins, analysts) whose cells carry data another user can write; low when every cell is server-generated (ids, dates, enums) — prove it; high when the export is mailed or auto-opened.",
    note: "A CSV is produced from non-constant cells and nothing neutralizes a cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return. Opened in a spreadsheet such a cell is a formula. Prefix those cells with `'`, including values that come from the database.",
    examples: [
      {
        language: "javascript",
        vulnerable: 'const body = rows.map((r) => [r.name, r.email].join(";"));',
        fixed:
          'const cell = (v) => (/^[=+\\-@\\t\\r]/.test(String(v)) ? `\'${v}` : String(v));\nconst body = rows.map((r) => [r.name, r.email].map(cell).join(";"));',
      },
      {
        language: "python",
        vulnerable: "writer = csv.writer(out)\nfor u in users:\n    writer.writerow([u.name, u.email])",
        fixed:
          'def cell(v):\n    s = str(v)\n    return "\'" + s if s[:1] in ("=", "+", "-", "@", "\\t", "\\r") else s\nwriter.writerow([cell(u.name), cell(u.email)])',
      },
      {
        language: "php",
        vulnerable: "fputcsv($out, [$user->name, $user->email]);",
        fixed: "fputcsv($out, array_map(fn ($v) => preg_match('/^[=+\\-@\\t\\r]/', (string) $v) ? \"'\".$v : $v, [$user->name, $user->email]));",
      },
    ],
  },
  "client-ip-first-xff": {
    id: "client-ip-first-xff",
    title: "Client IP taken from the first X-Forwarded-For entry",
    cwe: "CWE-348",
    severity: "medium",
    category: "config",
    invariant:
      "The client address used for a security decision (rate limit, allow-list, audit log, lockout) is the one written by a proxy the application trusts — counted from the RIGHT of X-Forwarded-For, or the socket address when no proxy is trusted.",
    guard:
      "Taking the entry your own proxy appended (the last one, or the N-th from the right for N trusted hops), or a framework helper configured with the trusted proxy list (Express `trust proxy` with a hop count, Werkzeug `ProxyFix(x_for=1)`, Gin `SetTrustedProxies`, Rails `request.remote_ip`).",
    rubric:
      "medium when the address keys a rate limit, lockout or audit log; high when it keys an allow-list that grants access; low when it is only displayed.",
    note: "Proxies APPEND to X-Forwarded-For, so its first entry is whatever the client sent. Taking it lets any caller choose its own IP for rate limits, allow-lists and audit logs. Take the entry your own proxy wrote (count hops from the right), or a helper configured with the trusted proxies.",
    examples: [
      {
        language: "javascript",
        vulnerable: 'const ip = req.headers["x-forwarded-for"].split(",")[0];',
        fixed: 'const hops = String(req.headers["x-forwarded-for"] ?? "").split(",");\nconst ip = hops[hops.length - 1].trim(); // one trusted proxy',
      },
      {
        language: "python",
        vulnerable: 'ip = request.META["HTTP_X_FORWARDED_FOR"].split(",")[0]',
        fixed: 'ip = request.META["HTTP_X_FORWARDED_FOR"].split(",")[-1].strip()  # one trusted proxy',
      },
      {
        language: "go",
        vulnerable: 'ip := strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]',
        fixed: 'router.SetTrustedProxies([]string{"10.0.0.1"})\nip := c.ClientIP()',
      },
    ],
  },
  "unbounded-public-export": {
    id: "unbounded-public-export",
    title: "Public export/listing route queries without a row limit",
    cwe: "CWE-770",
    severity: "medium",
    category: "config",
    invariant:
      "A route reachable without privilege (public, export, download, feed) bounds the rows one request can materialize: a limit, a page size with a ceiling, or a stream with a hard cap.",
    guard:
      "`limit`/`take`/`paginate`/a slice on the query itself, or a streaming/batched iterator with a ceiling. A rate limit in front reduces the rate, not the per-request cost.",
    rubric:
      "medium when the table grows with user data and the route is anonymous; low when the table is small and bounded by construction (a list of countries) — say why; high when the response joins large tables or the route is unauthenticated and cache-less.",
    note: "A route under a public/export path runs a query with no row limit. Every call materializes the whole table in memory and on the wire, and the cost grows with the data rather than the request — an amplification lever even behind a rate limit. Page it, cap it, or stream it with a hard ceiling.",
    examples: [
      {
        language: "javascript",
        vulnerable: "const rows = await db.select().from(declarations);",
        fixed: "const rows = await db.select().from(declarations).limit(PAGE_SIZE).offset(page * PAGE_SIZE);",
      },
      {
        language: "python",
        vulnerable: "def export_users(request):\n    rows = User.objects.all()",
        fixed: "def export_users(request):\n    rows = Paginator(User.objects.order_by('id'), 500).page(request.GET.get('page', 1))",
      },
      { language: "ruby", vulnerable: "def export\n  @users = User.all", fixed: "def export\n  @users = User.order(:id).limit(500)" },
    ],
  },
  "security-headers-absent": {
    id: "security-headers-absent",
    title: "Application serves no security headers",
    cwe: "CWE-693",
    severity: "low",
    category: "config",
    invariant:
      "Every HTML/API response carries the browser protections the deployment relies on — Content-Security-Policy, Strict-Transport-Security, X-Frame-Options or `frame-ancestors`, X-Content-Type-Options, Referrer-Policy — set by the framework's defaults, a middleware, or the proxy in front.",
    guard:
      "The framework's own header defaults left on (Django SecurityMiddleware + XFrameOptionsMiddleware, Rails default_headers, Spring Security headers), a header middleware (helmet, Talisman, secure), or the headers set by the reverse proxy/CDN — which is the thing to check before reporting.",
    rubric:
      "low as a posture note; medium when the app renders user content (CSP is then the XSS backstop) or has state-changing pages that can be framed; nothing when a proxy in front demonstrably sets them (`ultrasec probe`).",
    note: "The application is built without the security headers its framework does not set by default (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy). Add them where the app is built — unless a reverse proxy in front sets them, which is the thing to check (`ultrasec probe` sees what is actually served).",
    examples: [
      { language: "javascript", vulnerable: "const app = express();\napp.use(router);", fixed: "const app = express();\napp.use(helmet());\napp.use(router);" },
      {
        language: "python",
        vulnerable: 'MIDDLEWARE = [\n    "django.contrib.sessions.middleware.SessionMiddleware",\n]',
        fixed:
          'MIDDLEWARE = [\n    "django.middleware.security.SecurityMiddleware",\n    "django.contrib.sessions.middleware.SessionMiddleware",\n    "django.middleware.clickjacking.XFrameOptionsMiddleware",\n]',
      },
      { language: "java", vulnerable: "http.headers(headers -> headers.disable());", fixed: "http.headers(withDefaults());" },
    ],
  },
  "session-cookie-chunks-on-logout": {
    id: "session-cookie-chunks-on-logout",
    title: "Logout clears the session cookie but not its chunks",
    cwe: "CWE-613",
    severity: "medium",
    category: "authz",
    invariant:
      "Logging out invalidates every cookie that carries the session: when a library splits a large session cookie into `<name>.0`, `<name>.1`, …, all of them, on both the `__Secure-` and the plain name — or the session is revoked server-side.",
    guard:
      "The library's own sign-out, or a loop over the cookie jar expiring every name that starts with the session cookie's name; or a server-side session store whose record is deleted.",
    rubric: "medium: a stale chunk set keeps authenticating after logout on a shared device; low when sessions are short-lived and also revoked server-side.",
    note: "A hand-written logout expires the session cookie by name, but the library splits a large session into `<name>.0`, `<name>.1`, … and those chunks still authenticate. Clear every cookie whose name starts with the session cookie's name, or call the library's own sign-out.",
    examples: [
      {
        language: "javascript",
        vulnerable: 'response.cookies.set("next-auth.session-token", "", { maxAge: 0 });',
        fixed: 'for (const c of (await cookies()).getAll()) if (c.name.startsWith("next-auth.session-token")) response.cookies.set(c.name, "", { maxAge: 0 });',
      },
    ],
  },
  "env-bool-coercion": {
    id: "env-bool-coercion",
    title: "Environment flag parsed by truthiness",
    cwe: "CWE-704",
    severity: "medium",
    category: "config",
    invariant:
      'A boolean read from the environment is true only for an explicit true spelling (`true`, `1`, `yes`) — the string `"false"`, `"0"` or `"off"` an operator writes is false.',
    guard:
      'An explicit parse: Node `z.enum(["true","false"]).transform(v => v === "true")` or `z.stringbool()`, Python `strtobool`-style comparison / `env.bool()`, Go `strconv.ParseBool`, Java `Boolean.parseBoolean`, Ruby `ActiveModel::Type::Boolean.new.cast`, PHP `filter_var(…, FILTER_VALIDATE_BOOLEAN)` or Laravel `env()`.',
    rubric: "medium when the flag toggles a test seam, a mock, an auth bypass or a security control (FLAG=false turns it ON); low for cosmetic flags.",
    note: 'An environment variable is turned into a boolean by truthiness: every non-empty string is true, including `"false"` and `"0"`. An operator writing FLAG=false turns the flag ON. Parse the string explicitly.',
    examples: [
      {
        language: "javascript",
        vulnerable: "FAKE_CLOCK: z.coerce.boolean().default(false),",
        fixed: 'FAKE_CLOCK: z.enum(["true", "false"]).default("false").transform((v) => v === "true"),',
      },
      {
        language: "python",
        vulnerable: 'DEBUG = bool(os.environ.get("DEBUG"))',
        fixed: 'DEBUG = os.environ.get("DEBUG", "false").lower() in ("1", "true", "yes")',
      },
      { language: "php", vulnerable: "$debug = (bool) getenv('APP_DEBUG');", fixed: "$debug = filter_var(getenv('APP_DEBUG'), FILTER_VALIDATE_BOOLEAN);" },
    ],
  },
  "insecure-session-cookie": {
    id: "insecure-session-cookie",
    title: "Session cookie written without its protective flags",
    cwe: "CWE-614",
    severity: "medium",
    category: "config",
    invariant:
      "A cookie that carries a session or an auth token is written with HttpOnly (no script can read it), Secure (never sent over plain HTTP) and a SameSite policy — by the call that writes it, or by a framework default the code leaves on.",
    guard:
      'The flags set on the write itself (`httpOnly: true, secure: true, sameSite: "lax"`, `set_cookie(..., httponly=True, secure=True, samesite="Lax")`, `HttpOnly: true, Secure: true`, `ResponseCookie…httpOnly(true).secure(true)`, a Rails cookie hash with `httponly: true, secure: true`), or a session middleware configured with them. A flag bound to an expression (`secure: isProd`) is set — to whatever the deployment decides.',
    rubric:
      "medium for a session or auth cookie; low for a preference cookie with no authority; high when the missing flag is Secure on a cookie sent to an HTTP origin, or SameSite=None without Secure.",
    note: "A cookie is written without HttpOnly or Secure. A session cookie readable from script is stolen by any XSS; one without Secure travels over plain HTTP. Set both on the write, and a SameSite policy.",
    examples: [
      {
        language: "javascript",
        vulnerable: 'res.cookie("sid", token);',
        fixed: 'res.cookie("sid", token, { httpOnly: true, secure: true, sameSite: "lax" });',
      },
      {
        language: "python",
        vulnerable: 'response.set_cookie("sid", token)',
        fixed: 'response.set_cookie("sid", token, httponly=True, secure=True, samesite="Lax")',
      },
      {
        language: "go",
        vulnerable: 'http.SetCookie(w, &http.Cookie{Name: "sid", Value: token})',
        fixed: 'http.SetCookie(w, &http.Cookie{Name: "sid", Value: token, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})',
      },
      { language: "ruby", vulnerable: "cookies[:sid] = token", fixed: "cookies[:sid] = { value: token, httponly: true, secure: true, same_site: :lax }" },
    ],
  },
  "proxy-headers-trusted": {
    id: "proxy-headers-trusted",
    title: "Forwarded headers trusted without a proxy allow-list",
    cwe: "CWE-290",
    severity: "low",
    category: "config",
    invariant:
      "The framework takes the client address, scheme and host from X-Forwarded-* (or Forwarded) only from the proxies the deployment actually runs — a hop count or an address list — never from any caller.",
    guard:
      "Trust configured with a hop count or the proxy's addresses (Express `trust proxy` = 1 or a subnet, Gin `SetTrustedProxies([proxy])`, Werkzeug `ProxyFix(x_for=1)`, uvicorn `--forwarded-allow-ips=<proxy>`, Laravel `trustProxies(at: [proxy])`), on an app that is not reachable except through that proxy.",
    rubric:
      "low as a posture note when the app is only reachable through a proxy that rewrites the headers; medium when the address keys a rate limit, lockout or audit log and the app is reachable directly; high when it keys an allow-list that grants access.",
    note: "The framework is told to trust X-Forwarded-* from every caller, so the client IP, scheme and host it reports are whatever the request says — for rate limits, allow-lists, audit logs and absolute URLs alike. Trust only your own proxy (a hop count or its address), and confirm the app is not reachable around it.",
    examples: [
      { language: "javascript", vulnerable: 'app.set("trust proxy", true);', fixed: 'app.set("trust proxy", 1); // exactly one proxy in front' },
      {
        language: "python",
        vulnerable: "USE_X_FORWARDED_HOST = True",
        fixed: "# Host comes from the request line; the proxy rewrites it if it must\nUSE_X_FORWARDED_HOST = False",
      },
      { language: "php", vulnerable: "$middleware->trustProxies(at: '*');", fixed: "$middleware->trustProxies(at: ['10.0.0.0/8']);" },
    ],
  },
  "request-body-unbounded": {
    id: "request-body-unbounded",
    title: "Request body read with no size limit",
    cwe: "CWE-770",
    severity: "low",
    category: "config",
    invariant:
      "Every request body the application buffers — JSON, form, multipart, raw — is bounded by a size limit the code (or the server in front) sets explicitly, below what one request may cost in memory.",
    guard:
      'An explicit limit where the body is read (`express.json({ limit: "100kb" })`, Go `http.MaxBytesReader`, Flask `MAX_CONTENT_LENGTH`, Django `DATA_UPLOAD_MAX_MEMORY_SIZE`, Spring `spring.servlet.multipart.max-request-size`), or a proxy limit (`client_max_body_size`) the app cannot be reached around.',
    rubric:
      "low as a hardening note when a default limit exists; medium when the body is read whole into memory with no limit anywhere and the route is anonymous.",
    note: "A request body is read with no size limit — or with the framework's limit switched off — so one request can make the process buffer as much as the client sends. Set an explicit limit where the body is read, or confirm the proxy in front enforces one.",
    examples: [
      { language: "javascript", vulnerable: "app.use(express.json());", fixed: 'app.use(express.json({ limit: "100kb" }));' },
      { language: "go", vulnerable: "body, _ := io.ReadAll(r.Body)", fixed: "r.Body = http.MaxBytesReader(w, r.Body, 1<<20)\nbody, err := io.ReadAll(r.Body)" },
      { language: "python", vulnerable: "DATA_UPLOAD_MAX_MEMORY_SIZE = None", fixed: "DATA_UPLOAD_MAX_MEMORY_SIZE = 2_621_440  # Django's default, 2.5 MB" },
    ],
  },
  "graphql-introspection-enabled": {
    id: "graphql-introspection-enabled",
    title: "GraphQL introspection or IDE served in production",
    cwe: "CWE-200",
    severity: "medium",
    category: "config",
    invariant:
      "A production GraphQL endpoint does not answer introspection queries nor serve an IDE (GraphiQL, Playground, Sandbox) unless the schema is meant to be public.",
    guard:
      'Introspection and the IDE turned off outside development (`introspection: process.env.NODE_ENV !== "production"`, graphene `graphiql=settings.DEBUG`, a `DisableIntrospection` validation rule, `spring.graphql.graphiql.enabled=false`), or a schema that is public by design.',
    rubric:
      "medium when the schema exposes internal or administrative operations; low when the API is public and documented anyway; high when introspection reveals operations that lack authorization.",
    note: "GraphQL introspection or an IDE is switched on, which hands anyone the whole schema — every type, field and mutation, including the ones the UI never calls. Turn both off in production unless the schema is public by design.",
    examples: [
      {
        language: "javascript",
        vulnerable: "new ApolloServer({ schema, introspection: true });",
        fixed: 'new ApolloServer({ schema, introspection: process.env.NODE_ENV !== "production" });',
      },
      {
        language: "python",
        vulnerable: 'path("graphql", GraphQLView.as_view(graphiql=True))',
        fixed: 'path("graphql", GraphQLView.as_view(graphiql=settings.DEBUG))',
      },
      {
        language: "go",
        vulnerable: 'http.Handle("/", playground.Handler("GraphQL", "/query"))',
        fixed: 'if os.Getenv("ENV") == "dev" {\n    http.Handle("/", playground.Handler("GraphQL", "/query"))\n}',
      },
    ],
  },
  "csrf-protection-disabled": {
    id: "csrf-protection-disabled",
    title: "CSRF protection switched off",
    cwe: "CWE-352",
    severity: "high",
    category: "config",
    invariant:
      "Every state-changing route an authenticated browser can reach with ambient credentials (cookies, HTTP auth) is protected against cross-site requests — the framework's CSRF guard left on, an Origin check, or credentials that are never ambient.",
    guard:
      "The framework's guard left enabled (Django CsrfViewMiddleware, Rails `protect_from_forgery`, Spring Security's CSRF filter, Laravel's token middleware, Next.js Server Actions' origin check), or an API authenticated only by a header the browser does not attach on its own (a bearer token) — which is the thing to verify before calling an exemption a bug.",
    rubric:
      "high when the exempted routes change state under cookie authentication; medium when they are only reachable with a non-ambient credential; nothing when every exempted route is read-only or authenticated by a bearer header.",
    note: "The framework's CSRF guard is switched off (commented out, skipped, exempted or disabled). Any state-changing route it covered can now be driven from an attacker's page using the victim's cookies. Turn it back on, or prove the routes are authenticated by a credential the browser does not attach on its own.",
    examples: [
      { language: "ruby", vulnerable: "skip_before_action :verify_authenticity_token", fixed: "protect_from_forgery with: :exception" },
      { language: "java", vulnerable: "http.csrf(AbstractHttpConfigurer::disable);", fixed: "http.csrf(withDefaults());" },
      { language: "python", vulnerable: "@csrf_exempt\ndef transfer(request):", fixed: "def transfer(request):  # CsrfViewMiddleware checks the token" },
    ],
  },
  "debug-mode-enabled": {
    id: "debug-mode-enabled",
    title: "Framework debug mode or verbose errors enabled",
    cwe: "CWE-489",
    severity: "medium",
    category: "config",
    invariant:
      "The deployed application runs with the framework's debug mode off: no interactive debugger, no stack traces, configuration or source in error responses.",
    guard:
      'Debug tied to an environment that is false in production (`DEBUG = env.bool("DEBUG", False)`, `app.run(debug=os.getenv("FLASK_DEBUG") == "1")`, `gin.SetMode(gin.ReleaseMode)`, `server.error.include-stacktrace=never`), and the setting checked in the deployed configuration, not the development one.',
    rubric:
      "medium when stack traces or settings reach a remote caller; high when the debugger is interactive (Werkzeug console, Rails web-console) and reachable; low when the file is development-only configuration — say why.",
    note: "Framework debug mode is on: error responses carry stack traces, settings or source, and some debuggers (Werkzeug, web-console) give a remote console. Turn it off in production, driven by the environment rather than hard-coded.",
    examples: [
      { language: "python", vulnerable: "DEBUG = True", fixed: 'DEBUG = os.environ.get("DJANGO_DEBUG", "false") == "true"' },
      { language: "go", vulnerable: "gin.SetMode(gin.DebugMode)", fixed: "gin.SetMode(gin.ReleaseMode)" },
      { language: "ruby", vulnerable: "config.consider_all_requests_local = true", fixed: "config.consider_all_requests_local = false" },
    ],
  },
};

/** Class ids in registry order. */
export const CLASS_LIST = Object.values(CLASSES);

/**
 * The taint-catalog row of the matrix (see `CATALOG_ROW`). Its hunt asks for
 * the framework's own input APIs and route conventions as this repository
 * uses them — what the taint walk needs to see the framework at all.
 */
export const CATALOG_SUBJECT: HuntSubject = {
  id: CATALOG_ROW,
  title: "Framework request inputs and routes known to the taint catalog",
  cwe: "CWE-20",
  invariant:
    "Every way the framework hands request data to application code (parameters, bodies, headers, cookies, path segments, procedure inputs) is a taint SOURCE the engine knows, and every way it exposes code to the network (routes, actions, controllers) is an ENTRY POINT — for the version the repository runs.",
  guard:
    "Not a guard: recognition. The framework's input accessors and route declarations, as THIS repository writes them, matched by catalog rows labelled for the framework at a version range that includes the one detected.",
  rubric:
    "An unrecognized input API is not a vulnerability; it is a blind spot for every taint class at once. Report what the code reads and where it is routed, then hunt the classes the walk could not reach from it.",
  examples: [
    {
      language: "javascript",
      vulnerable: 'app.get("/export", (c) => db.query(c.req.query("q")));',
      fixed: "// Hono: `c.req.query(...)` is the request input; the route is `app.get(path, handler)`.",
    },
    {
      language: "elixir",
      vulnerable: 'def index(conn, params) do\n  Repo.query("SELECT * FROM t WHERE q = \'#{params["q"]}\'")',
      fixed: "# Phoenix: `params` (and `conn.params`) is the request input; the router line is the route.",
    },
    {
      language: "python",
      vulnerable: '@app.get("/export")\nasync def export(request):\n    q = request.args.get("q")',
      fixed: "# Sanic: `request.args` / `request.json` are the inputs; `@app.get` declares the route.",
    },
  ],
};

/** Every matrix row, in order: the classes, then the taint-catalog row. */
export const MATRIX_ROWS: readonly HuntSubject[] = [...CLASS_LIST, CATALOG_SUBJECT];

/** A matrix row's hunt subject, by id. */
export const HUNT_SUBJECTS: Record<MatrixRowId, HuntSubject> = { ...CLASSES, [CATALOG_ROW]: CATALOG_SUBJECT };

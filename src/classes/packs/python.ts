import type { Pack, QueryIdiom } from "../types.js";
import {
  COOKIE_HTTPONLY_SET,
  COOKIE_SAMESITE_NONE,
  COOKIE_SECURE_SET,
  EXPORT_PATH,
  HEADERS_MIDDLEWARE,
  MENTIONS_CSV,
  NEUTRALIZES_FORMULA_ANY,
  SETS_SECURITY_HEADER,
  XFF,
  XFF_LOOKBACK,
} from "./shared.js";

// Python: the language idioms, then Django, Flask and FastAPI.

const PY = ["python"];

const SECRET = String.raw`["'][A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD)["']`;
/** A comparison operand that is a presence test, not a value. */
const NOT_PRESENCE = String.raw`(?!\s*(?:None|""|''))`;
const PY_CONSTANT_TIME = /compare_digest|constant_time_compare/;

/** Statements that materialize a whole SQLAlchemy result set. */
const SQLALCHEMY_QUERIES: QueryIdiom[] = [
  // Flask-SQLAlchemy `Model.query.all()` / `.filter(...).all()`.
  {
    start: /\.query\s*\.\s*(?:all|filter|filter_by|order_by)\s*\(/,
    bounded: /\.(?:limit|paginate|first|get|one|one_or_none|count|slice)\s*\(|\[\s*:\s*\w+\s*\]/,
  },
  // `session.query(Model)….all()` / `db.query(Model).all()`.
  { start: /\b(?:session|db)\s*\.\s*query\s*\(/, requires: /\.all\s*\(/, bounded: /\.(?:limit|slice|yield_per)\s*\(/ },
  // 2.0 style: `session.scalars(select(Model)).all()`.
  { start: /\bsession\s*\.\s*(?:scalars|execute)\s*\(\s*select\s*\(/, requires: /\.all\s*\(/, bounded: /\.limit\s*\(/ },
];

/** A decorated route: `@app.get("/export")`, `@bp.route('/public/feed')`. */
const PY_ROUTE_DECORATOR = /@\w+(?:\.\w+)*\.(?:route|get|post|api_route)\s*\(\s*["']([^"']+)["']/;

export const PYTHON_PACK: Pack = {
  id: "python",
  ecosystem: "python",
  classes: {
    "timing-unsafe-secret-compare": {
      rules: [
        // The original detector's Python rule.
        {
          id: "env-secret",
          kind: "line",
          languages: PY,
          match: new RegExp(`(?:==|!=)\\s*os\\.(?:environ\\[|getenv\\()\\s*${SECRET}`),
          unless: PY_CONSTANT_TIME,
          emit: "authtokens/secret-compare-timing",
        },
        {
          id: "env-secret-left",
          kind: "line",
          languages: PY,
          match: new RegExp(`os\\.(?:environ\\[|environ\\.get\\(|getenv\\()\\s*${SECRET}\\s*[\\])]\\s*(?:==|!=)${NOT_PRESENCE}`),
          unless: PY_CONSTANT_TIME,
          emit: "authtokens/secret-compare-timing",
        },
        {
          id: "settings-secret",
          kind: "line",
          languages: PY,
          match: new RegExp(
            `(?:==|!=)\\s*(?:settings\\.[A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD)\\b|(?:current_)?app\\.config\\[\\s*${SECRET}\\s*\\])|(?:settings\\.[A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD)\\b|(?:current_)?app\\.config\\[\\s*${SECRET}\\s*\\])\\s*(?:==|!=)${NOT_PRESENCE}`,
          ),
          unless: PY_CONSTANT_TIME,
          emit: "authtokens/secret-compare-timing",
        },
        {
          id: "credential-header",
          kind: "line",
          languages: PY,
          match: /headers\.get\(\s*["'](?:x-api-key|authorization|x-webhook-secret|x-auth-token)["'][^)]*\)\s*(?:==|!=)(?!\s*(?:None|""|''))/i,
          unless: PY_CONSTANT_TIME,
          emit: "authtokens/secret-compare-timing",
        },
      ],
    },
    "csv-formula-injection": {
      rules: [
        {
          id: "writer",
          kind: "file",
          languages: PY,
          gate: [MENTIONS_CSV],
          anchor: /\.writerows?\s*\(|["'][,;]["']\s*\.join\s*\(/,
          pick: "last",
          unless: NEUTRALIZES_FORMULA_ANY,
          note: 'A CSV is written from non-constant cells (`csv.writer`/`DictWriter`, or `",".join`) and nothing neutralizes a cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return. Opened in a spreadsheet such a cell is a formula. Prefix those cells with `\'` — or write through `defusedcsv`, which does it.',
        },
      ],
    },
    "client-ip-first-xff": {
      rules: [
        // `.split(",", 1)[0]` and `.partition(",")[0]` — the common pack has `.split(",")[0]`.
        {
          id: "maxsplit-first",
          kind: "line",
          languages: PY,
          match: /\.split\(\s*["']\s*,\s*["']\s*,\s*1\s*\)\s*\[\s*0\s*\]|\.partition\(\s*["']\s*,\s*["']\s*\)\s*\[\s*0\s*\]/,
          context: { re: XFF, before: XFF_LOOKBACK },
          emit: "webconfig/xff-first-hop",
        },
      ],
    },
    "env-bool-coercion": {
      rules: [
        {
          id: "bool-of-env",
          kind: "line",
          languages: PY,
          match: /\bbool\s*\(\s*os\.(?:environ\.get|getenv)\s*\(|\bbool\s*\(\s*os\.environ\[/,
          note: '`bool(os.environ.get("X"))` is True for every non-empty string, including "false" and "0" — an operator writing X=false turns the flag ON. Compare the lowered string against an explicit set of true spellings.',
        },
      ],
    },
    "session-cookie-chunks-on-logout": {
      notApplicable:
        "Python web frameworks keep the session server-side (Django, Flask-Session) or in one signed cookie (Flask's default); none splits it into numbered chunks that a logout could leave behind.",
    },
    // `set_cookie` is Django's HttpResponse, Werkzeug/Flask's Response and
    // Starlette's Response alike, and all three default HttpOnly and Secure off.
    "insecure-session-cookie": {
      rules: [
        {
          id: "set-cookie",
          kind: "call",
          languages: PY,
          call: /\.set_cookie\s*\(/,
          scope: "args",
          flags: [
            { emit: "webconfig/cookie-httponly", present: COOKIE_HTTPONLY_SET },
            { emit: "webconfig/cookie-secure", present: COOKIE_SECURE_SET },
            { emit: "webconfig/cookie-samesite-none-insecure", when: COOKIE_SAMESITE_NONE, present: COOKIE_SECURE_SET },
          ],
        },
      ],
    },
    // graphene-django / Flask-GraphQL `GraphQLView.as_view(graphiql=True)`.
    "graphql-introspection-enabled": {
      rules: [{ id: "graphiql-true", kind: "line", languages: PY, match: /\bgraphiql\s*=\s*True\b/, emit: "webconfig/graphql-introspection" }],
    },
  },
};

// ── Django ──────────────────────────────────────────────────────────────────
// SecurityMiddleware sets X-Content-Type-Options (SECURE_CONTENT_TYPE_NOSNIFF,
// default True), Referrer-Policy (SECURE_REFERRER_POLICY, default
// 'same-origin') and Cross-Origin-Opener-Policy (default 'same-origin');
// XFrameOptionsMiddleware sets X-Frame-Options (X_FRAME_OPTIONS, default
// 'DENY'). HSTS needs SECURE_HSTS_SECONDS (default 0) and CSP needs SECURE_CSP.
// So the posture is decided by those two middlewares being in MIDDLEWARE.
// Sources: https://docs.djangoproject.com/en/stable/ref/middleware/
//          https://docs.djangoproject.com/en/stable/ref/settings/
const DJANGO_SECURITY_MIDDLEWARES =
  /^(?=[\s\S]*django\.middleware\.security\.SecurityMiddleware)(?=[\s\S]*django\.middleware\.clickjacking\.XFrameOptionsMiddleware)/;

const DJANGO_QUERIES: QueryIdiom[] = [
  {
    start: /\.objects\s*\.\s*(?:all|filter|exclude|values|values_list|order_by|select_related|prefetch_related)\s*\(/,
    bounded: /\[\s*\w*\s*:\s*\w+\s*\]|\bPaginator\s*\(|\.(?:iterator|first|last|get|exists|count|aggregate)\s*\(/,
  },
];

export const DJANGO_PACK: Pack = {
  id: "django",
  ecosystem: "python",
  framework: "django",
  testedWith: ">=3.2 <7",
  sources: ["https://docs.djangoproject.com/en/stable/ref/middleware/", "https://docs.djangoproject.com/en/stable/ref/settings/"],
  markers: {
    global: { auth: { words: ["login_required", "permission_required"] } },
    detected: { auth: { words: ["LoginRequiredMixin", "PermissionRequiredMixin", "user_passes_test", "permission_classes"] } },
  },
  classes: {
    "security-headers-absent": {
      rules: [
        {
          id: "middleware-missing",
          kind: "absent",
          languages: PY,
          anchor: /^\s*MIDDLEWARE\s*=/,
          presentInFile: DJANGO_SECURITY_MIDDLEWARES,
          note: "MIDDLEWARE lacks `django.middleware.security.SecurityMiddleware` or `django.middleware.clickjacking.XFrameOptionsMiddleware` (or has them commented out). Those two are what make Django send X-Content-Type-Options, Referrer-Policy, Cross-Origin-Opener-Policy and X-Frame-Options by default; without them the responses carry none. Restore both — and set SECURE_HSTS_SECONDS and SECURE_CSP, which are off by default either way.",
        },
        {
          id: "default-turned-off",
          kind: "line",
          languages: PY,
          match:
            /^\s*(?:SECURE_CONTENT_TYPE_NOSNIFF\s*=\s*False|SECURE_REFERRER_POLICY\s*=\s*None|SECURE_CROSS_ORIGIN_OPENER_POLICY\s*=\s*None|X_FRAME_OPTIONS\s*=\s*["']ALLOWALL["'])/,
          note: "A security header Django sends by default is switched off in settings. Remove the override unless a proxy in front sets the header instead.",
        },
      ],
    },
    "unbounded-public-export": {
      rules: [
        {
          id: "view",
          kind: "route-query",
          languages: PY,
          exportPath: EXPORT_PATH,
          // A view function named for the export, or a URL pattern whose path is one.
          routeDecl: /^\s*(?:async\s+)?def\s+(\w+)\s*\(\s*request\b|^\s*(?:re_)?path\s*\(\s*r?["']([^"']+)["']/,
          queries: DJANGO_QUERIES,
          statement: "balanced",
        },
      ],
    },
    // The original web-config detector's Django rules (raw lines: a
    // commented-out middleware IS the finding).
    "csrf-protection-disabled": {
      rules: [
        { id: "csrf-exempt", kind: "line", languages: PY, text: "raw", match: /^\s*@csrf_exempt\b/, emit: "webconfig/csrf-disabled" },
        {
          id: "middleware-commented",
          kind: "line",
          languages: PY,
          text: "raw",
          match: /^\s*#\s*['"]django\.middleware\.csrf\.CsrfViewMiddleware['"]/,
          emit: "webconfig/csrf-disabled",
        },
      ],
    },
    "debug-mode-enabled": {
      rules: [{ id: "debug-true", kind: "line", languages: PY, text: "raw", match: /^\s*DEBUG\s*=\s*True\b/, emit: "webconfig/debug" }],
    },
    // USE_X_FORWARDED_HOST trusts X-Forwarded-Host for `get_host()` and every
    // absolute URL (password-reset links). Source: https://docs.djangoproject.com/en/stable/ref/settings/#use-x-forwarded-host
    "proxy-headers-trusted": {
      rules: [
        {
          id: "use-x-forwarded-host",
          kind: "line",
          languages: PY,
          match: /^\s*USE_X_FORWARDED_HOST\s*=\s*True\b/,
          note: "`USE_X_FORWARDED_HOST = True` makes `request.get_host()` — and every absolute URL Django builds, password-reset links included — come from X-Forwarded-Host, which any caller can send unless the proxy in front overwrites it. Confirm the proxy sets it on every request, or leave it off.",
        },
      ],
    },
    // DATA_UPLOAD_MAX_MEMORY_SIZE = None removes Django's 2.5 MB body cap.
    // Source: https://docs.djangoproject.com/en/stable/ref/settings/#data-upload-max-memory-size
    "request-body-unbounded": {
      rules: [
        {
          id: "upload-max-none",
          kind: "line",
          languages: PY,
          match: /^\s*DATA_UPLOAD_MAX_(?:MEMORY_SIZE|NUMBER_FIELDS|NUMBER_FILES)\s*=\s*None\b/,
          note: "A Django request-size guard is set to `None`, which removes it: a single request can make the process buffer an arbitrarily large body (or field count). Keep a bound — the 2.5 MB default, or the largest body the app really accepts.",
        },
      ],
    },
  },
};

// ── Flask ───────────────────────────────────────────────────────────────────
// Flask sets none of the security headers; its docs list them and point at
// Flask-Talisman. Source: https://flask.palletsprojects.com/en/stable/web-security/
// Gated on Flask being DECLARED in the package: the original detector left
// Flask out because `Flask(__name__)` alone fires on every throwaway script.
export const FLASK_PACK: Pack = {
  id: "flask",
  ecosystem: "python",
  framework: "flask",
  testedWith: ">=2 <4",
  sources: ["https://flask.palletsprojects.com/en/stable/web-security/"],
  markers: { detected: { auth: { words: ["jwt_required", "roles_required", "fresh_login_required"] }, throttle: { patterns: [/\bLimiter\s*\(/] } } },
  classes: {
    "security-headers-absent": {
      rules: [
        {
          id: "no-talisman",
          kind: "absent",
          languages: PY,
          requiresFramework: "flask",
          anchor: /\bFlask\s*\(\s*__name__/,
          presentInFile: HEADERS_MIDDLEWARE,
          presentInTree: { re: new RegExp(`\\bTalisman\\s*\\(|${SETS_SECURITY_HEADER.source}`, "i"), scope: "package", languages: PY },
          note: "The Flask app is built and nothing in the package sets security headers (no Flask-Talisman, no `after_request` writing CSP / X-Frame-Options / HSTS). Flask sends none by default. Add Talisman or set them in `after_request` — unless the proxy in front sets them.",
        },
      ],
    },
    "client-ip-first-xff": {
      rules: [
        {
          id: "access-route-first",
          kind: "line",
          languages: PY,
          match: /\brequest\.access_route\s*\[\s*0\s*\]/,
          note: "Werkzeug's `request.access_route` is the X-Forwarded-For list followed by the socket address, so element 0 is whatever the client sent. Configure `ProxyFix(app.wsgi_app, x_for=1)` and read `request.remote_addr` instead.",
        },
      ],
    },
    "unbounded-public-export": {
      rules: [
        {
          id: "route",
          kind: "route-query",
          languages: PY,
          exportPath: EXPORT_PATH,
          routeDecl: PY_ROUTE_DECORATOR,
          queries: SQLALCHEMY_QUERIES,
          statement: "balanced",
        },
      ],
    },
    "debug-mode-enabled": {
      rules: [{ id: "run-debug", kind: "line", languages: PY, text: "raw", match: /\.run\([^)]*\bdebug\s*=\s*True/, emit: "webconfig/debug" }],
    },
    // Flask-WTF's CSRF protection, switched off.
    // Source: https://flask-wtf.readthedocs.io/en/stable/config/
    "csrf-protection-disabled": {
      rules: [{ id: "wtf-csrf-off", kind: "line", languages: PY, match: /\bWTF_CSRF_ENABLED["']?\s*\]?\s*=\s*False\b/, emit: "webconfig/csrf-disabled" }],
    },
    // Flask reads JSON and raw bodies whole and sets no MAX_CONTENT_LENGTH.
    // Source: https://flask.palletsprojects.com/en/stable/config/#MAX_CONTENT_LENGTH
    "request-body-unbounded": {
      rules: [
        {
          id: "no-max-content-length",
          kind: "absent",
          languages: PY,
          requiresFramework: "flask",
          anchor: /\bFlask\s*\(\s*__name__/,
          presentInFile: /MAX_CONTENT_LENGTH/,
          presentInTree: { re: /MAX_CONTENT_LENGTH/, scope: "package", languages: PY },
          note: "The Flask app is built and nothing in the package sets `MAX_CONTENT_LENGTH`, so Flask reads request bodies of any size (`request.get_json()`, `request.data`). Set it to the largest body the app accepts — unless the proxy in front enforces a limit.",
        },
      ],
    },
    "proxy-headers-trusted": {
      hunt: "Flask trusts no forwarded header unless the app wraps itself in Werkzeug's `ProxyFix`; check whether it does, and with how many hops (`x_for`, `x_host`, `x_proto`).",
    },
  },
};

// ── FastAPI ─────────────────────────────────────────────────────────────────
// FastAPI documents three built-in middlewares (HTTPSRedirect, TrustedHost,
// GZip) and none sets security headers.
// Source: https://fastapi.tiangolo.com/advanced/middleware/
export const FASTAPI_PACK: Pack = {
  id: "fastapi",
  ecosystem: "python",
  framework: "fastapi",
  testedWith: ">=0.100 <1",
  sources: ["https://fastapi.tiangolo.com/advanced/middleware/"],
  // A dependency that resolves the caller IS FastAPI's guard.
  markers: {
    detected: {
      auth: { patterns: [/\bDepends\s*\(\s*\w*(?:current_user|auth|token|verify|security)\w*/i, /\bSecurity\s*\(/] },
      throttle: { patterns: [/\bLimiter\s*\(/] },
    },
  },
  classes: {
    "security-headers-absent": {
      rules: [
        {
          id: "no-headers-middleware",
          kind: "absent",
          languages: PY,
          anchor: /\bFastAPI\s*\(/,
          presentInFile: HEADERS_MIDDLEWARE,
          emit: "webconfig/helmet-missing",
        },
      ],
    },
    "unbounded-public-export": {
      rules: [
        {
          id: "route",
          kind: "route-query",
          languages: PY,
          exportPath: EXPORT_PATH,
          routeDecl: PY_ROUTE_DECORATOR,
          queries: SQLALCHEMY_QUERIES,
          statement: "balanced",
        },
      ],
    },
    // Starlette's debug mode renders tracebacks to the client.
    // Source: https://www.starlette.io/applications/
    "debug-mode-enabled": {
      rules: [{ id: "app-debug", kind: "line", languages: PY, match: /\bFastAPI\s*\([^)]*\bdebug\s*=\s*True\b/, emit: "webconfig/debug" }],
    },
    // uvicorn trusts X-Forwarded-For/-Proto only from `forwarded_allow_ips`; `*` is everyone.
    // Source: https://www.uvicorn.org/settings/#http
    "proxy-headers-trusted": {
      rules: [
        {
          id: "forwarded-allow-any",
          kind: "line",
          languages: PY,
          match: /\bforwarded_allow_ips\s*=\s*["']\*["']/,
          note: '`forwarded_allow_ips="*"` makes uvicorn take the client address and scheme from X-Forwarded-* sent by ANY caller. List the proxy\'s address instead, and confirm the app is not reachable around it.',
        },
      ],
    },
    "request-body-unbounded": {
      hunt: "FastAPI/Starlette read `await request.json()` and `request.body()` whole with no size limit of their own; check what bounds the bodies (a middleware, the ASGI server, the proxy).",
    },
    "csrf-protection-disabled": {
      hunt: "FastAPI ships no CSRF protection to switch off; check whether any state-changing route is authenticated by a cookie the browser attaches on its own.",
    },
  },
};

export const PYTHON_PACKS: Pack[] = [PYTHON_PACK, DJANGO_PACK, FLASK_PACK, FASTAPI_PACK];

import type { Pack, QueryIdiom } from "../types.js";
import { EXPORT_PATH, HEADERS_MIDDLEWARE, MENTIONS_CSV, NEUTRALIZES_FORMULA_ANY, SETS_SECURITY_HEADER, XFF, XFF_LOOKBACK } from "./shared.js";

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
  },
};

export const PYTHON_PACKS: Pack[] = [PYTHON_PACK, DJANGO_PACK, FLASK_PACK, FASTAPI_PACK];

import type { Pack, QueryIdiom } from "../types.js";
import { COOKIE_CALL, EXPORT_PATH, LEGACY_COOKIE_FLAGS, MENTIONS_CSV, NEUTRALIZES_FORMULA_ANY, SETS_SECURITY_HEADER, XFF, XFF_LOOKBACK } from "./shared.js";

// PHP: the language idioms, then Laravel.

const PHP = ["php"];

/** A config/env read whose key names a credential. */
const SECRET_READ = String.raw`(?:env|getenv|config)\(\s*['"][^'"]*(?:token|secret|key|password)[^'"]*['"]\s*\)`;
const EQ = "(?:===|!==|==|!=)";
const NOT_EMPTY = String.raw`(?!\s*(?:null|''|""|false)\b)`;

export const PHP_PACK: Pack = {
  id: "php",
  ecosystem: "php",
  classes: {
    "timing-unsafe-secret-compare": {
      rules: [
        {
          id: "secret-read",
          kind: "line",
          languages: PHP,
          match: new RegExp(
            `${EQ}\\s*${SECRET_READ}|${SECRET_READ}\\s*${EQ}${NOT_EMPTY}|\\$_SERVER\\[\\s*['"]HTTP_(?:X_API_KEY|AUTHORIZATION|X_WEBHOOK_SECRET)['"]\\s*\\]\\s*${EQ}${NOT_EMPTY}|->header\\(\\s*['"](?:X-Api-Key|X-API-Key|Authorization|X-Webhook-Secret)['"]\\s*\\)\\s*${EQ}${NOT_EMPTY}`,
            "i",
          ),
          unless: /hash_equals/,
          note: "A credential is compared with `===`/`==`, which returns at the first differing byte, so response time leaks how much of a guess is right. Use `hash_equals($known, $provided)`.",
        },
      ],
    },
    "csv-formula-injection": {
      rules: [
        {
          id: "writer",
          kind: "file",
          languages: PHP,
          gate: [MENTIONS_CSV],
          anchor: /\bfputcsv\s*\(|\bimplode\s*\(\s*['"][,;]['"]|->insert(?:One|All)\s*\(/,
          pick: "last",
          // league/csv ships the neutralizer as a formatter.
          unless: new RegExp(`${NEUTRALIZES_FORMULA_ANY.source}|EscapeFormula`, "i"),
          note: "A CSV is written (`fputcsv`, `implode(',')`, league/csv `insertOne`) and nothing neutralizes a cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return. Opened in a spreadsheet such a cell is a formula. Prefix those cells with `'` (league/csv: `EscapeFormula`).",
        },
      ],
    },
    "client-ip-first-xff": {
      rules: [
        {
          id: "explode-first",
          kind: "line",
          languages: PHP,
          match: /explode\s*\(\s*['"]\s*,\s*['"]\s*,[^;]*?\)\s*\[\s*0\s*\]|strtok\s*\([^;]*X_FORWARDED_FOR[^;]*,\s*['"],['"]\s*\)/,
          context: { re: XFF, before: XFF_LOOKBACK },
          emit: "webconfig/xff-first-hop",
        },
      ],
    },
    "env-bool-coercion": {
      rules: [
        {
          id: "bool-cast-env",
          kind: "line",
          languages: PHP,
          match: /\(\s*bool\s*\)\s*(?:getenv\s*\(|\$_ENV\[|\$_SERVER\[)/,
          note: '`(bool) getenv("X")` is true for every non-empty string, including "false". Use `filter_var(getenv("X"), FILTER_VALIDATE_BOOLEAN)` — Laravel\'s `env()` already maps "false"/"(false)" to false.',
        },
      ],
    },
    "session-cookie-chunks-on-logout": {
      notApplicable: "PHP sessions (native and Laravel's drivers) keep one session cookie; none splits it into numbered chunks for a logout to miss.",
    },
    // The original web-config detector's rules (src/webconfig.ts ≤ v1.58.0),
    // moved here with their shapes so their findings keep their ids.
    "insecure-session-cookie": {
      rules: [{ id: "setcookie", kind: "call", languages: PHP, call: COOKIE_CALL, scope: "args", ...LEGACY_COOKIE_FLAGS }],
    },
    "csrf-protection-disabled": {
      rules: [
        { id: "csrf-false", kind: "line", languages: PHP, text: "raw", match: /['"]csrf(?:_protection)?['"]\s*=>\s*false/i, emit: "webconfig/csrf-disabled" },
      ],
    },
    "debug-mode-enabled": {
      rules: [{ id: "debug-true", kind: "line", languages: PHP, text: "raw", match: /['"]debug['"]\s*=>\s*true/, emit: "webconfig/debug" }],
    },
    "request-body-unbounded": {
      notApplicable:
        "PHP enforces `post_max_size` (8 MB by default) before application code runs; a body limit is an ini/web-server setting, not an application idiom.",
    },
    "graphql-introspection-enabled": {
      hunt: "webonyx/graphql-php and Lighthouse answer introspection unless a `DisableIntrospection` validation rule is added (Lighthouse: `security.disable_introspection`); check the production config.",
    },
  },
};

// ── Laravel ─────────────────────────────────────────────────────────────────
// Laravel's default middleware stack sets no security response header (CSP,
// HSTS, X-Frame-Options); they come from a package (spatie/laravel-csp, …), a
// custom middleware or the web server. The trusted-proxy docs are explicit
// that IP addresses are user-controlled input.
// Source: https://laravel.com/docs/12.x/requests (Request IP Address, Trusted Proxies)
const LARAVEL_QUERIES: QueryIdiom[] = [
  // `Model::all()` loads the table, whatever is chained after it.
  { start: /\b[A-Z]\w*::all\s*\(\s*\)/, bounded: /(?!)/ },
  {
    start: /\b(?:[A-Z]\w*::(?:where|query|orderBy|select|with|latest|oldest)|DB::table)\s*\(/,
    requires: /->get\s*\(\s*\)/,
    bounded: /->(?:limit|take|paginate|simplePaginate|cursorPaginate|chunk|chunkById|lazy|lazyById|cursor|first|find|count|exists)\s*\(/,
  },
];

export const LARAVEL_PACK: Pack = {
  id: "laravel",
  ecosystem: "php",
  framework: "laravel",
  testedWith: ">=9 <14",
  sources: ["https://laravel.com/docs/12.x/requests"],
  // Route middleware is Laravel's guard, named in a string.
  markers: {
    detected: {
      auth: {
        patterns: [
          /->middleware\(\s*\[?[^)\]]*['"](?:auth(?::[\w,]+)?|can:[^'"]+|verified)['"]/,
          /\bAuth::(?:check|user|guard)\s*\(/,
          /\bauth\(\)\s*->\s*(?:check|user)\s*\(/,
        ],
      },
    },
  },
  classes: {
    "security-headers-absent": {
      rules: [
        {
          id: "no-headers-middleware",
          kind: "absent",
          languages: PHP,
          requiresFramework: "laravel",
          anchor: /Application::configure\s*\(|class\s+Kernel\s+extends\s+HttpKernel\b/,
          presentInTree: { re: new RegExp(`Spatie\\\\Csp|AddCspHeaders|SecureHeaders|${SETS_SECURITY_HEADER.source}`, "i"), scope: "package", languages: PHP },
          note: "The Laravel application is configured and nothing in it sets security headers: Laravel's default middleware stack writes no CSP, HSTS or X-Frame-Options. Add a header middleware (or spatie/laravel-csp) — unless the web server in front sets them.",
        },
      ],
    },
    "unbounded-public-export": {
      rules: [
        {
          id: "route-or-controller",
          kind: "route-query",
          languages: PHP,
          exportPath: EXPORT_PATH,
          routeDecl: /Route::(?:get|post|any|match)\s*\(\s*['"]([^'"]+)['"]|public\s+function\s+(\w+)\s*\(/,
          queries: LARAVEL_QUERIES,
          statement: "balanced",
        },
      ],
    },
    // Trusting every proxy (`*`) lets any caller set the IP and scheme.
    // Source: https://laravel.com/docs/12.x/requests#configuring-trusted-proxies
    "proxy-headers-trusted": {
      rules: [
        {
          id: "trust-all-proxies",
          kind: "line",
          languages: PHP,
          match: /\btrustProxies\s*\(\s*at\s*:\s*['"]\*\*?['"]|\$proxies\s*=\s*['"]\*\*?['"]/,
          note: "Every proxy is trusted (`*`), so `$request->ip()`, the scheme and the host come from X-Forwarded-* sent by ANY caller that reaches the app directly. List the proxy's addresses, and confirm the app is not reachable around them.",
        },
      ],
    },
    // Every route exempted from the CSRF token check.
    // Source: https://laravel.com/docs/12.x/csrf#csrf-excluding-uris
    "csrf-protection-disabled": {
      rules: [
        {
          id: "except-everything",
          kind: "line",
          languages: PHP,
          match: /\bvalidateCsrfTokens\s*\(\s*except\s*:\s*\[\s*['"]\*['"]|\$except\s*=\s*\[\s*['"]\*['"]/,
          emit: "webconfig/csrf-disabled",
        },
      ],
    },
  },
};

export const PHP_PACKS: Pack[] = [PHP_PACK, LARAVEL_PACK];

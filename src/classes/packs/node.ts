import type { Pack, QueryIdiom } from "../types.js";
import {
  COOKIE_CALL,
  EXPORT_PATH,
  EXPRESS_TRUST_PROXY,
  GRAPHQL_INTROSPECTION_ON,
  HEADERS_MIDDLEWARE,
  LEGACY_COOKIE_FLAGS,
  MENTIONS_CSV,
  NEUTRALIZES_FORMULA,
} from "./shared.js";

// Node.js: the language idioms (any framework), then one pack per framework.
// The rules emitting a `webconfig/…` or `authtokens/…` shape are the original
// detectors' (src/webconfig.ts, src/authtokens.ts as of v1.57.0), moved here
// verbatim so their findings keep the same ids.

const JS = ["javascript"];

// ── Non-constant-time secret comparison ─────────────────────────────────────
// Only operands that ARE a secret by construction: a bearer header rebuilt
// from config, or an environment variable named like a credential. A variable
// called `token` compared with `===` is far more often a CSRF/nonce equality
// or a type check than an authentication decision, so it is not matched.
const SECRET_ENV = String.raw`(?:process\.)?env(?:\.[A-Z0-9_]*(?:TOKEN|SECRET|API_?KEY|APIKEY|PASSWORD|PASSPHRASE)\b|\[\s*["'][A-Z0-9_]*(?:TOKEN|SECRET|API_?KEY|APIKEY|PASSWORD)["']\s*\])`;
const EQ = "(?:===|!==|==|!=)";
const CONSTANT_TIME = /timingSafeEqual|safeCompare|secureCompare|constantTime|compare_digest|tsscmp|safe-compare/i;
/** A comparison against "unset" is a presence check, not a secret comparison. */
const PRESENCE_CHECK = new RegExp(`${SECRET_ENV}\\s*${EQ}\\s*(?:undefined|null|""|''|\`\`)(?![\\w$])|(?:undefined|null|""|'')\\s*${EQ}\\s*${SECRET_ENV}`);
const COMPARE_GUARD = new RegExp(`${CONSTANT_TIME.source}|${PRESENCE_CHECK.source}`, "i");

// ── env boolean coercion ─────────────────────────────────────────────────────
const COERCE_BOOLEAN = /\bz\s*\.\s*coerce\s*\.\s*boolean\s*\(/;
/** An env schema key is UPPER_SNAKE. */
const ENV_KEY_COERCE = /^\s*["']?[A-Z][A-Z0-9_]*["']?\s*:.*\bz\s*\.\s*coerce\s*\.\s*boolean\s*\(/;
const READS_ENV = /\bprocess\.env\b|\bimport\.meta\.env\b|\bcreateEnv\s*\(|\bDeno\.env\b|\bBun\.env\b/;

// ── NextAuth / Auth.js session chunks (NEXT_AUTH_PACK below) ────────────────
const SESSION_COOKIE = /(?:__Secure-)?(?:next-auth|authjs)\.session-token/;
const EXPIRES_COOKIE = /maxAge\s*:\s*0\b|expires\s*:\s*new\s+Date\(\s*0\s*\)|Max-Age=0|\.delete\s*\(|expires=Thu, 01 Jan 1970/i;
/** Any sign the code knows about `<name>.N`: a prefix match, a `.N` suffix, a loop over the jar. */
const HANDLES_CHUNKS =
  /session-token\.\d|session-token\.\$\{|session-token\.["'`]|\.startsWith\s*\([^)]*(?:session|token|name|cookie)|\\\.\\d|\.\$\{\s*i\s*\}|getAll\s*\(/i;

/** Hand-built CSV: cells joined with `;` / `,` / tab. */
const CELL_JOIN = /\.join\(\s*(["'`])(?:;|,|\\t)\1\s*\)/;

// ── Query idioms shared by every Node framework's export routes ─────────────
const NODE_QUERIES: QueryIdiom[] = [
  // Drizzle / Knex-style builders: a select that reads FROM a table.
  { start: /\.\s*select(?:Distinct)?\s*\(/, requires: /\.\s*from\s*\(/, bounded: /\.\s*(?:limit|paginate|\$paginate)\s*\(/ },
  // Prisma.
  { start: /\.\s*findMany\s*\(/, bounded: /\btake\s*:/ },
];
/** Sequelize, TypeORM and Mongoose on top of the builders above. An argument-
 *  less `.find()` cannot be `Array.prototype.find` — that one needs a callback. */
const NODE_ORM_QUERIES: QueryIdiom[] = [
  ...NODE_QUERIES,
  { start: /\.\s*findAll\s*\(/, bounded: /\blimit\s*:/ },
  { start: /\.\s*getMany\s*\(/, bounded: /\.\s*(?:take|limit)\s*\(/ },
  { start: /\.\s*find\s*\(\s*\)/, bounded: /\.\s*(?:limit|take)\s*\(/ },
  { start: /\.\s*find\s*\(\s*\{/, bounded: /\btake\s*:|\.\s*limit\s*\(/ },
];
/** `app.get("/export/users", …)`, `router.route('/public/feed')`, `fastify.get(…)`. */
const JS_ROUTE_DECL = /\b(?:app|router|server|fastify|api|routes?)\s*\.\s*(?:get|post|all|route)\s*\(\s*["'`]([^"'`]+)["'`]/;

export const NODE_PACK: Pack = {
  id: "node",
  ecosystem: "node",
  classes: {
    "timing-unsafe-secret-compare": {
      rules: [
        {
          id: "bearer-template",
          kind: "line",
          languages: JS,
          match: new RegExp(`${EQ}\\s*\`Bearer \\$\\{|\`Bearer \\$\\{[^\`]*\`\\s*${EQ}`),
          unless: COMPARE_GUARD,
          emit: "authtokens/secret-compare-timing",
        },
        {
          id: "env-secret",
          kind: "line",
          languages: JS,
          match: new RegExp(`${EQ}\\s*${SECRET_ENV}|${SECRET_ENV}\\s*${EQ}(?!\\s*(?:undefined|null|""|''|\`\`)\\b)`),
          unless: COMPARE_GUARD,
          emit: "authtokens/secret-compare-timing",
        },
        {
          // The receiver has to be named for credentials: `allowedKeys.has(key)`
          // is as often an object-key allow-list as an API-key one.
          id: "credential-set",
          kind: "line",
          languages: JS,
          match: /\b\w*(?:tokens|secrets|api_?keys|bearers)\w*\s*\.\s*has\s*\(\s*(?:bearer|token|apiKey|api_key|key|secret|provided)\w*\s*\)/i,
          unless: COMPARE_GUARD,
          emit: "authtokens/secret-compare-timing",
        },
      ],
    },
    "csv-formula-injection": {
      rules: [
        // The catalog's `csv` sink knows CSV LIBRARIES; a CSV assembled with
        // `.join(";")` was invisible. The data rows are joined after the
        // header, so the last cell join is the line cited.
        {
          id: "hand-built",
          kind: "file",
          languages: JS,
          gate: [MENTIONS_CSV],
          anchor: CELL_JOIN,
          pick: "last",
          unless: NEUTRALIZES_FORMULA,
          emit: "webconfig/csv-formula",
        },
      ],
    },
    "env-bool-coercion": {
      rules: [
        { id: "zod-coerce-env-key", kind: "line", languages: JS, match: ENV_KEY_COERCE, emit: "webconfig/env-coerce-boolean" },
        { id: "zod-coerce-env-file", kind: "line", languages: JS, match: COERCE_BOOLEAN, fileGate: READS_ENV, emit: "webconfig/env-coerce-boolean" },
        {
          id: "boolean-of-env",
          kind: "line",
          languages: JS,
          match: /\bBoolean\s*\(\s*process\.env(?:\.\w+|\[[^\]]+\])\s*\)/,
          note: '`Boolean(process.env.X)` is true for every non-empty string, including "false" and "0" — an operator writing X=false turns the flag ON. Compare the string explicitly (`process.env.X === "true"`).',
        },
      ],
    },
    // The original web-config detector's rules (src/webconfig.ts ≤ v1.58.0),
    // moved here with their shapes so their findings keep their ids.
    "insecure-session-cookie": {
      rules: [{ id: "cookie-call", kind: "call", languages: JS, call: COOKIE_CALL, scope: "args", ...LEGACY_COOKIE_FLAGS }],
    },
    "graphql-introspection-enabled": {
      rules: [{ id: "options-true", kind: "line", languages: JS, text: "raw", match: GRAPHQL_INTROSPECTION_ON, emit: "webconfig/graphql-introspection" }],
    },
    "csrf-protection-disabled": {
      rules: [{ id: "csrf-false", kind: "line", languages: JS, text: "raw", match: /\bcsrf(?:Prevention)?\s*:\s*false\b/, emit: "webconfig/csrf-disabled" }],
    },
    "debug-mode-enabled": {
      rules: [
        // The `errorhandler` middleware renders stack traces to the client; its
        // own README says development only. Registered with no environment check.
        {
          id: "errorhandler-unconditional",
          kind: "file",
          languages: JS,
          gate: [/require\(\s*["']errorhandler["']\s*\)|from\s+["']errorhandler["']/],
          anchor: /\.use\s*\(\s*\w*[eE]rror[hH]andler\s*\(/,
          pick: "first",
          unless: /NODE_ENV|\.get\(\s*["']env["']\s*\)|isDev\w*|isProd\w*|development/,
          emit: "webconfig/debug",
        },
      ],
    },
  },
};

// ── NextAuth.js / Auth.js — a LIBRARY's idiom ──────────────────────────────
// The session cookie is NextAuth's, not Next.js's nor Node's: its name and its
// chunking (`<name>.0`, `<name>.1`, … once the JWT outgrows one cookie) are
// what the library does, at the versions below. Kept in a library pack so the
// matrix checks `testedWith` against NextAuth's own version, wherever the
// library is declared. Source: https://github.com/nextauthjs/next-auth (cookie chunking, v4 and v5).
export const NEXT_AUTH_PACK: Pack = {
  id: "next-auth",
  ecosystem: "node",
  library: "next-auth",
  testedWith: ">=4 <6",
  sources: ["https://github.com/nextauthjs/next-auth"],
  // `getServerSession` (v4) is NextAuth's alone; v5's `auth()` and `getToken`
  // are names any codebase might use, so they count only where NextAuth is declared.
  markers: {
    global: { auth: { words: ["getServerSession"] } },
    detected: { auth: { patterns: [/\bawait\s+auth\s*\(\s*\)/, /\bgetToken\s*\(/] } },
  },
  classes: {
    "session-cookie-chunks-on-logout": {
      rules: [
        {
          id: "nextauth-manual-logout",
          kind: "file",
          languages: JS,
          gate: [SESSION_COOKIE, EXPIRES_COOKIE],
          anchor: SESSION_COOKIE,
          pick: "first",
          unless: HANDLES_CHUNKS,
          emit: "authtokens/session-chunks-not-cleared",
        },
      ],
    },
  },
};

// ── Next.js ─────────────────────────────────────────────────────────────────
// Next.js sets no CSP, HSTS, X-Frame-Options, X-Content-Type-Options or
// Referrer-Policy by default; they go in `headers()` or middleware.
// Source: https://nextjs.org/docs/app/api-reference/config/next-config-js/headers (v16.4)
const NEXT_CONFIG = /(?:^|\/)next\.config\.(?:js|mjs|cjs|ts|mts)$/;
const NEXT_HEADERS = /\bheaders\s*(?:\(|:)/;
const SETS_CSP = /Content-Security-Policy|\bhelmet\s*\(|next-secure-headers|@nosecone|\bnosecone\b|next-safe/i;
const CONFIG_OBJECT = /(?:const|let|var)\s+\w*[cC]onfig\w*\s*(?::[^=]+)?=\s*\{|module\.exports\s*=|export\s+default\b/;
/** App-Router route handlers and Pages-Router API routes. */
const NEXT_ROUTE_FILE = /(?:^|\/)app\/(?:.*\/)?route\.[cm]?[jt]s$|(?:^|\/)pages\/api\/.+\.[cm]?[jt]sx?$/;

export const NEXTJS_PACK: Pack = {
  id: "nextjs",
  ecosystem: "node",
  framework: "nextjs",
  testedWith: ">=12 <17",
  sources: ["https://nextjs.org/docs/app/api-reference/config/next-config-js/headers"],
  classes: {
    "security-headers-absent": {
      rules: [
        {
          id: "no-headers",
          kind: "absent",
          languages: JS,
          files: NEXT_CONFIG,
          anchor: CONFIG_OBJECT,
          fallbackLine1: true,
          presentInFile: NEXT_HEADERS,
          presentInTree: { re: SETS_CSP, scope: "anchor-dir", languages: JS },
          emit: "webconfig/next-headers-missing",
        },
      ],
    },
    "unbounded-public-export": {
      rules: [
        {
          id: "route-handler",
          kind: "route-query",
          languages: JS,
          routeFile: NEXT_ROUTE_FILE,
          exportPath: EXPORT_PATH,
          queries: NODE_QUERIES,
          statement: "js-legacy",
          emit: "webconfig/unbounded-export",
        },
      ],
    },
    // Server Actions check that the Origin matches the host; `allowedOrigins`
    // widens that list, and a `*` entry turns the check off.
    // Source: https://nextjs.org/docs/app/api-reference/config/next-config-js/serverActions
    "csrf-protection-disabled": {
      rules: [
        {
          id: "server-actions-any-origin",
          kind: "line",
          languages: JS,
          files: NEXT_CONFIG,
          match: /\ballowedOrigins\s*:\s*\[[^\]]*["'`]\*["'`]/,
          note: "`serverActions.allowedOrigins` lists `*`, which turns off the Origin check Next.js applies to every Server Action — its CSRF protection. Any site can invoke the app's actions with the visitor's cookies. List the exact origins a proxy forwards from.",
        },
      ],
    },
    "proxy-headers-trusted": {
      hunt: "Next.js derives the request host and protocol from X-Forwarded-Host/-Proto and exposes no trust setting of its own; whether a caller can forge them depends on the proxy in front — check how the app reads them and what the deployment strips.",
    },
    "request-body-unbounded": {
      hunt: "App-Router route handlers read `await req.json()` with no size limit of their own (Server Actions default to 1 MB, `api.bodyParser.sizeLimit` bounds Pages-Router routes); check what bounds the bodies this app reads.",
    },
    "debug-mode-enabled": {
      hunt: "Next.js has no debug switch in code — `next dev` vs `next start` and `productionBrowserSourceMaps` decide what an error exposes; check the deployed start command and config.",
    },
  },
};

// ── Express ─────────────────────────────────────────────────────────────────
// Express sets no security headers (it does set X-Powered-By); helmet is the
// documented answer. Source: https://expressjs.com/en/advanced/best-practice-security.html
export const EXPRESS_PACK: Pack = {
  id: "express",
  ecosystem: "node",
  framework: "express",
  testedWith: ">=4 <6",
  sources: ["https://expressjs.com/en/advanced/best-practice-security.html"],
  markers: { global: { auth: { words: ["passport\\.authenticate"] } } },
  classes: {
    "security-headers-absent": {
      rules: [
        { id: "no-helmet", kind: "absent", languages: JS, anchor: /\bexpress\s*\(\s*\)/, presentInFile: HEADERS_MIDDLEWARE, emit: "webconfig/helmet-missing" },
      ],
    },
    "unbounded-public-export": {
      rules: [
        {
          id: "router",
          kind: "route-query",
          languages: JS,
          exportPath: EXPORT_PATH,
          routeDecl: JS_ROUTE_DECL,
          queries: NODE_ORM_QUERIES,
          statement: "balanced",
        },
      ],
    },
    "proxy-headers-trusted": {
      rules: [{ id: "trust-proxy", kind: "line", languages: JS, text: "raw", match: EXPRESS_TRUST_PROXY, emit: "webconfig/trust-proxy" }],
    },
    "request-body-unbounded": {
      rules: [
        {
          id: "body-parser-no-limit",
          kind: "line",
          languages: JS,
          text: "raw",
          evidence: "match",
          match: /\b(?:express|bodyParser|body-parser)\s*\.\s*(?:json|urlencoded|text|raw)\s*\((?![^)]*\blimit\s*:)[^)]*\)/,
          emit: "webconfig/body-limit-missing",
        },
      ],
    },
  },
};

// ── NestJS ──────────────────────────────────────────────────────────────────
// No headers unless helmet (Express adapter) / @fastify/helmet is registered —
// or, from NestJS 12.1, the built-in `app.useSecurityHeaders()`.
// Source: https://docs.nestjs.com/security/helmet
export const NESTJS_PACK: Pack = {
  id: "nestjs",
  ecosystem: "node",
  framework: "nestjs",
  testedWith: ">=9 <13",
  sources: ["https://docs.nestjs.com/security/helmet"],
  markers: { global: { auth: { annotations: ["UseGuards"] } }, detected: { auth: { words: ["AuthGuard"] } } },
  classes: {
    "security-headers-absent": {
      rules: [
        {
          id: "no-helmet",
          kind: "absent",
          languages: JS,
          anchor: /\bNestFactory\s*\.\s*create\s*(?:<[^>]*>)?\s*\(/,
          presentInFile: new RegExp(`${HEADERS_MIDDLEWARE.source}|\\.useSecurityHeaders\\s*\\(`),
          emit: "webconfig/helmet-missing",
        },
      ],
    },
    "unbounded-public-export": {
      rules: [
        {
          id: "controller",
          kind: "route-query",
          languages: JS,
          exportPath: EXPORT_PATH,
          routeDecl: /@(?:Controller|Get|Post|All)\s*\(\s*["'`]([^"'`]*)["'`]/,
          queries: NODE_ORM_QUERIES,
          statement: "balanced",
        },
      ],
    },
    // On the Express adapter Nest forwards `app.set` to Express.
    // Source: https://docs.nestjs.com/faq/http-adapter
    "proxy-headers-trusted": {
      rules: [{ id: "trust-proxy", kind: "line", languages: JS, text: "raw", match: EXPRESS_TRUST_PROXY, emit: "webconfig/trust-proxy" }],
    },
    "request-body-unbounded": {
      hunt: "Nest registers the adapter's body parser itself (`NestFactory.create(…, { bodyParser })`, `app.useBodyParser('json', { limit })`); check which limit the app sets.",
    },
  },
};

// ── Fastify ─────────────────────────────────────────────────────────────────
// No default security headers; `@fastify/helmet` registers them.
// Source: https://github.com/fastify/fastify-helmet
export const FASTIFY_PACK: Pack = {
  id: "fastify",
  ecosystem: "node",
  framework: "fastify",
  testedWith: ">=4 <6",
  sources: ["https://github.com/fastify/fastify-helmet"],
  classes: {
    "security-headers-absent": {
      rules: [
        {
          id: "no-helmet",
          kind: "absent",
          languages: JS,
          anchor: /\b(?:fastify|Fastify)\s*\(\s*\)/,
          presentInFile: HEADERS_MIDDLEWARE,
          emit: "webconfig/helmet-missing",
        },
        // The same constructor with an options object, which the original
        // detector's `fastify()` anchor did not see.
        {
          id: "no-helmet-options",
          kind: "absent",
          languages: JS,
          anchor: /\b(?:fastify|Fastify)\s*\(\s*\{/,
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
          languages: JS,
          exportPath: EXPORT_PATH,
          routeDecl: JS_ROUTE_DECL,
          queries: NODE_ORM_QUERIES,
          statement: "balanced",
        },
      ],
    },
    // `trustProxy: true` trusts every hop. Source: https://fastify.dev/docs/latest/Reference/Server/#trustproxy
    "proxy-headers-trusted": {
      rules: [
        {
          id: "trust-proxy-true",
          kind: "line",
          languages: JS,
          match: /\btrustProxy\s*:\s*true\b/,
          note: "`trustProxy: true` makes Fastify take `request.ip`, `request.protocol` and `request.host` from X-Forwarded-* sent by ANY caller. Give it the proxy's address or a hop count instead, and confirm the app is not reachable around the proxy.",
        },
      ],
    },
    "request-body-unbounded": {
      hunt: "Fastify bounds bodies with `bodyLimit` (1 MiB by default); check whether the app raises it or reads `request.raw` itself.",
    },
  },
};

// ── Koa / Hono / Elysia — header posture only (partial packs) ──────────────
// Carried over from the original detector, which grounded the absence on the
// constructor. For every other class these frameworks get what the Node
// language idioms above match (the timing, CSV, first-hop and env-boolean
// rules read any JavaScript) — and where no rule applies at all, the cell is
// hunted. The framework's own idioms for those classes are not encoded.
const ctorPack = (id: string, ctor: RegExp, testedWith: string): Pack => ({
  id,
  ecosystem: "node",
  framework: id,
  testedWith,
  classes: {
    "security-headers-absent": {
      rules: [
        { id: "no-headers-middleware", kind: "absent", languages: JS, anchor: ctor, presentInFile: HEADERS_MIDDLEWARE, emit: "webconfig/helmet-missing" },
      ],
    },
  },
});
// `app.proxy = true` makes Koa trust X-Forwarded-* from every caller.
// Source: https://koajs.com/#settings
export const KOA_PACK: Pack = (() => {
  const pack = ctorPack("koa", /\bnew\s+Koa\s*\(/, ">=2 <4");
  pack.classes["proxy-headers-trusted"] = {
    rules: [
      {
        id: "app-proxy-true",
        kind: "line",
        languages: JS,
        match: /\b(?:app|server)\s*\.\s*proxy\s*=\s*true\b/,
        note: "`app.proxy = true` makes Koa take `ctx.ip`, `ctx.protocol` and `ctx.host` from X-Forwarded-* sent by ANY caller. Set `proxyIpHeader`/`maxIpsCount` to your proxy's hop count, and confirm the app is not reachable around the proxy.",
      },
    ],
  };
  return pack;
})();
export const HONO_PACK = ctorPack("hono", /\bnew\s+Hono\s*\(/, ">=3 <5");
export const ELYSIA_PACK = ctorPack("elysia", /\bnew\s+Elysia\s*\(/, ">=0.7 <2");

// ── tRPC — a library's guard vocabulary ────────────────────────────────────
// A procedure built from an authenticated base is the guard: the middleware
// that checks the session runs before every procedure derived from it. The
// names are conventions of the tRPC docs and templates, so they count only
// where tRPC is declared. Source: https://trpc.io/docs/server/authorization
export const TRPC_PACK: Pack = {
  id: "trpc",
  ecosystem: "node",
  library: "trpc",
  testedWith: ">=10 <12",
  sources: ["https://trpc.io/docs/server/authorization"],
  markers: { detected: { auth: { words: ["protectedProcedure", "authedProcedure", "adminProcedure", "privateProcedure"] } } },
  classes: {},
};

export const NODE_PACKS: Pack[] = [
  NODE_PACK,
  NEXTJS_PACK,
  EXPRESS_PACK,
  NESTJS_PACK,
  FASTIFY_PACK,
  KOA_PACK,
  HONO_PACK,
  ELYSIA_PACK,
  NEXT_AUTH_PACK,
  TRPC_PACK,
];

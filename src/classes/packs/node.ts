import type { Pack, QueryIdiom } from "../types.js";
import { EXPORT_PATH, HEADERS_MIDDLEWARE, MENTIONS_CSV, NEUTRALIZES_FORMULA } from "./shared.js";

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
export const KOA_PACK = ctorPack("koa", /\bnew\s+Koa\s*\(/, ">=2 <4");
export const HONO_PACK = ctorPack("hono", /\bnew\s+Hono\s*\(/, ">=3 <5");
export const ELYSIA_PACK = ctorPack("elysia", /\bnew\s+Elysia\s*\(/, ">=0.7 <2");

export const NODE_PACKS: Pack[] = [NODE_PACK, NEXTJS_PACK, EXPRESS_PACK, NESTJS_PACK, FASTIFY_PACK, KOA_PACK, HONO_PACK, ELYSIA_PACK, NEXT_AUTH_PACK];

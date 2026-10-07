import type { Pack, QueryIdiom } from "../types.js";
import { EXPORT_PATH, FLAG_NAME, MENTIONS_CSV, NEUTRALIZES_FORMULA_ANY, SETS_SECURITY_HEADER, XFF, XFF_LOOKBACK } from "./shared.js";

// Go: the language idioms, then net/http (the standard library) and Gin.

const GO = ["go"];

const SECRET = String.raw`"[A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD)"`;
const NOT_EMPTY = String.raw`(?!\s*"")`;

const GO_QUERIES: QueryIdiom[] = [
  // GORM: `db.Find(&rows)` with no `.Limit(` anywhere on the statement.
  { start: /\.\s*Find\s*\(\s*&/, bounded: /\.\s*(?:Limit|Scopes)\s*\(|\.\s*FindInBatches\s*\(/ },
  // database/sql with a literal SELECT.
  { start: /\.\s*Query(?:Context)?\s*\(/, requires: /\bSELECT\b/i, bounded: /\bLIMIT\b/i },
];

/** Something in the module sets security headers itself or through a middleware. */
const GO_SETS_HEADERS = new RegExp(`secure\\.New\\s*\\(|unrolled/secure|${SETS_SECURITY_HEADER.source}`, "i");

export const GO_PACK: Pack = {
  id: "go",
  ecosystem: "go",
  classes: {
    "timing-unsafe-secret-compare": {
      rules: [
        {
          id: "getenv-secret",
          kind: "line",
          languages: GO,
          match: new RegExp(
            `(?:==|!=)\\s*os\\.Getenv\\(\\s*${SECRET}\\s*\\)|os\\.Getenv\\(\\s*${SECRET}\\s*\\)\\s*(?:==|!=)${NOT_EMPTY}|\\.(?:Header\\.Get|GetHeader)\\(\\s*"(?:X-Api-Key|X-API-Key|Authorization|X-Webhook-Secret)"\\s*\\)\\s*(?:==|!=)${NOT_EMPTY}`,
          ),
          unless: /subtle\.ConstantTimeCompare|hmac\.Equal/,
          note: "A credential is compared with `==`/`!=`, which returns at the first differing byte, so response time leaks how much of a guess is right. Use `subtle.ConstantTimeCompare` (or `hmac.Equal` on digests).",
        },
      ],
    },
    "csv-formula-injection": {
      rules: [
        {
          id: "writer",
          kind: "file",
          languages: GO,
          gate: [MENTIONS_CSV],
          anchor: /csv\.NewWriter\s*\(|\.Write(?:All)?\s*\(\s*\[\]string|strings\.Join\([^)]*,\s*"[,;]"\s*\)/,
          pick: "last",
          unless: NEUTRALIZES_FORMULA_ANY,
          note: "A CSV is written (`encoding/csv`, or `strings.Join` with a comma) and nothing neutralizes a cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return. Opened in a spreadsheet such a cell is a formula. Prefix those cells with `'`.",
        },
      ],
    },
    "client-ip-first-xff": {
      rules: [
        {
          id: "split-first",
          kind: "line",
          languages: GO,
          // One level of nested call allowed in the argument: `Split(r.Header.Get("X-Forwarded-For"), ",")`.
          match:
            /strings\.SplitN?\s*\((?:[^()]|\([^()]*\))*?,\s*"\s*,\s*"(?:\s*,\s*-?\d+)?\s*\)\s*\[\s*0\s*\]|strings\.Cut\s*\((?:[^()]|\([^()]*\))*?,\s*"\s*,\s*"\s*\)/,
          context: { re: XFF, before: XFF_LOOKBACK },
          emit: "webconfig/xff-first-hop",
        },
      ],
    },
    "env-bool-coercion": {
      rules: [
        {
          id: "getenv-not-empty",
          kind: "line",
          languages: GO,
          match: new RegExp(`\\b${FLAG_NAME}\\s*:?=\\s*os\\.Getenv\\(\\s*"[^"]+"\\s*\\)\\s*!=\\s*""`, "i"),
          note: 'The flag is "the variable is non-empty": X=false and X=0 turn it ON. Parse it with `strconv.ParseBool`.',
        },
      ],
    },
    "session-cookie-chunks-on-logout": {
      notApplicable:
        "Go session libraries (gorilla/sessions, scs) keep one cookie per session and refuse an oversized value; none splits it into numbered chunks.",
    },
  },
};

// ── net/http ────────────────────────────────────────────────────────────────
// The standard library sets no security response header on a normal response
// (`http.Error` alone adds X-Content-Type-Options: nosniff).
// Source: https://pkg.go.dev/net/http (go1.27)
export const NET_HTTP_PACK: Pack = {
  id: "net-http",
  ecosystem: "go",
  framework: "net-http",
  testedWith: ">=1.18 <2",
  sources: ["https://pkg.go.dev/net/http"],
  classes: {
    "security-headers-absent": {
      rules: [
        {
          id: "no-headers",
          kind: "absent",
          languages: GO,
          requiresFramework: "net-http",
          anchor: /\bhttp\.ListenAndServe(?:TLS)?\s*\(|&?http\.Server\s*\{/,
          presentInTree: { re: GO_SETS_HEADERS, scope: "package", languages: GO },
          note: "The server is started and nothing in the module sets security headers: net/http writes no CSP, HSTS, X-Frame-Options or X-Content-Type-Options on a normal response. Wrap the handler in a middleware that sets them (e.g. unrolled/secure) — unless the proxy in front does.",
        },
      ],
    },
    "unbounded-public-export": {
      rules: [
        {
          id: "handler",
          kind: "route-query",
          languages: GO,
          exportPath: EXPORT_PATH,
          // Go 1.22 patterns carry the method: "GET /export/users".
          routeDecl: /\b(?:HandleFunc|Handle)\s*\(\s*"(?:[A-Z]+\s+)?([^"]+)"/,
          queries: GO_QUERIES,
          statement: "balanced",
        },
      ],
    },
  },
};

// ── Gin ─────────────────────────────────────────────────────────────────────
// "Gin trusts all proxies by default if you don't specify a trusted proxy
// [...] this is NOT safe" — with every proxy trusted, ClientIP() returns the
// client-written X-Forwarded-For entry. Gin sets no security headers;
// gin-contrib/secure does.
// Sources: https://gin-gonic.com/en/docs/server-config/trusted-proxies/
//          https://github.com/gin-contrib/secure
export const GIN_PACK: Pack = {
  id: "gin",
  ecosystem: "go",
  framework: "gin",
  testedWith: ">=1.7 <2",
  sources: ["https://gin-gonic.com/en/docs/server-config/trusted-proxies/", "https://github.com/gin-contrib/secure"],
  classes: {
    "client-ip-first-xff": {
      rules: [
        {
          id: "clientip-all-proxies-trusted",
          kind: "absent",
          languages: GO,
          anchor: /\.ClientIP\s*\(\s*\)/,
          presentInTree: { re: /\.SetTrustedProxies\s*\(|\bTrustedPlatform\s*=/, scope: "package", languages: GO },
          note: "`c.ClientIP()` is read, and the engine never calls `SetTrustedProxies` (or sets `TrustedPlatform`). Gin trusts every proxy by default, so ClientIP returns the X-Forwarded-For entry the client wrote. Call `router.SetTrustedProxies([]string{<your proxy>})`, or `nil` when there is none.",
        },
      ],
    },
    "security-headers-absent": {
      rules: [
        {
          id: "no-secure-middleware",
          kind: "absent",
          languages: GO,
          anchor: /\bgin\.(?:Default|New)\s*\(\s*\)/,
          presentInTree: { re: GO_SETS_HEADERS, scope: "package", languages: GO },
          note: "The Gin engine is built and nothing in the module sets security headers; Gin sends none by default. Register `gin-contrib/secure` (or a middleware writing CSP, HSTS, X-Frame-Options, X-Content-Type-Options) — unless the proxy in front does.",
        },
      ],
    },
    "unbounded-public-export": {
      rules: [
        {
          id: "route",
          kind: "route-query",
          languages: GO,
          exportPath: EXPORT_PATH,
          routeDecl: /\.(?:GET|POST|Any|Group)\s*\(\s*"([^"]+)"/,
          queries: GO_QUERIES,
          statement: "balanced",
        },
      ],
    },
  },
};

export const GO_PACKS: Pack[] = [GO_PACK, NET_HTTP_PACK, GIN_PACK];

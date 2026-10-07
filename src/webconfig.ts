import { readText, walk, type RepoTree } from "./walk.js";
import type { Finding, Severity } from "./types.js";
import { makeToolFinding } from "./tools/normalize.js";

// API / web misconfiguration — the config shapes a taint walk can't see because
// they have no source and no sink, only a value that is wrong on its own line.
//
// Like `src/actions.ts` this is a LINE / STATEMENT scan, not a full parse: no
// dependency may enter the zero-dep bundle. Every finding is a CANDIDATE the
// auditor confirms against the deployment (a wildcard CORS on an internal-only
// service is a different risk from the same on a public API), and every finding
// is grounded on a resolvable [file:line] so the `check` gate holds. Category is
// always `config`; the CWE is what the coverage packs (Top 10 / API Top 10 /
// CWE Top 25) key on — see src/coverage.ts.

export interface WebConfigShape {
  id: string;
  title: string;
  severity: Severity;
  cwe: string;
  note: string;
}

/** The shapes, kept as data so the reference doc and the engine cannot drift. */
export const WEBCONFIG_SHAPES: Record<string, WebConfigShape> = {
  "cors-reflect": {
    id: "cors-reflect",
    title: "CORS reflects the request Origin",
    severity: "high",
    cwe: "CWE-942",
    note: "Access-Control-Allow-Origin echoes the caller's Origin (or `origin: true`). Any site can read authenticated responses cross-origin — reflection is a wildcard that also passes the credentialed-request check.",
  },
  "cors-wildcard-credentials": {
    id: "cors-wildcard-credentials",
    title: "Wildcard CORS with credentials",
    severity: "high",
    cwe: "CWE-942",
    note: "Access-Control-Allow-Origin `*` together with Allow-Credentials `true`. Browsers block this combination, so shipping it means either it is ineffective or an origin is reflected elsewhere — check which.",
  },
  "cors-wildcard": {
    id: "cors-wildcard",
    title: "Wildcard CORS origin",
    severity: "medium",
    cwe: "CWE-942",
    note: "Access-Control-Allow-Origin `*` exposes responses to every origin. Safe only if the endpoint returns nothing per-user and carries no credentials.",
  },
  "cookie-httponly": {
    id: "cookie-httponly",
    title: "Cookie set without HttpOnly",
    severity: "medium",
    cwe: "CWE-1004",
    note: "A session/auth cookie readable from JavaScript is stealable by any XSS. Set HttpOnly unless the client genuinely must read it.",
  },
  "cookie-secure": {
    id: "cookie-secure",
    title: "Cookie set without Secure",
    severity: "medium",
    cwe: "CWE-614",
    note: "Without Secure the cookie is sent over plain HTTP and can be captured on the wire. Set Secure for anything session-bearing.",
  },
  "cookie-samesite": {
    id: "cookie-samesite",
    title: "Cookie set without SameSite",
    severity: "low",
    cwe: "CWE-1275",
    note: "No SameSite leaves the cookie attached to cross-site requests — the CSRF precondition. Set SameSite=Lax or Strict.",
  },
  "cookie-samesite-none-insecure": {
    id: "cookie-samesite-none-insecure",
    title: "SameSite=None cookie without Secure",
    severity: "high",
    cwe: "CWE-1275",
    note: "SameSite=None opts the cookie INTO cross-site sending; without Secure it also travels over plain HTTP. Browsers reject this pair, so it is both a CSRF and a transport exposure.",
  },
  "tls-verify": {
    id: "tls-verify",
    title: "TLS certificate verification disabled",
    severity: "high",
    cwe: "CWE-295",
    note: "Certificate/hostname verification turned off makes every outbound TLS call trivially machine-in-the-middle-able. This is almost never right outside a test.",
  },
  debug: {
    id: "debug",
    title: "Debug / verbose-error mode enabled",
    severity: "medium",
    cwe: "CWE-489",
    note: "Framework debug mode leaks stack traces, config and (Flask/Werkzeug, Rails) an interactive console or source. It must be off in production.",
  },
  "header-csp": {
    id: "header-csp",
    title: "Content-Security-Policy weakened",
    severity: "medium",
    cwe: "CWE-693",
    note: "`unsafe-inline` / `unsafe-eval` / a `*` source in the CSP re-opens the XSS class the header exists to close.",
  },
  "header-xfo": {
    id: "header-xfo",
    title: "X-Frame-Options allows framing",
    severity: "medium",
    cwe: "CWE-1021",
    note: "`ALLOWALL` (or the deprecated `ALLOW-FROM`) leaves the page framable — the clickjacking precondition. Use DENY/SAMEORIGIN or a CSP frame-ancestors.",
  },
  "header-hsts": {
    id: "header-hsts",
    title: "HSTS disabled (max-age=0)",
    severity: "medium",
    cwe: "CWE-319",
    note: "`max-age=0` turns Strict-Transport-Security off, so a first/again request can be downgraded to HTTP.",
  },
  "header-referrer": {
    id: "header-referrer",
    title: "Referrer-Policy leaks full URL",
    severity: "low",
    cwe: "CWE-200",
    note: "`unsafe-url` sends the full referring URL (path + query, possibly a token) cross-origin.",
  },
  "dir-listing": {
    id: "dir-listing",
    title: "Directory listing enabled",
    severity: "medium",
    cwe: "CWE-548",
    note: "Autoindex / serve-index exposes the file tree, turning any forgotten file into a disclosure.",
  },
  "csrf-disabled": {
    id: "csrf-disabled",
    title: "CSRF protection disabled",
    severity: "high",
    cwe: "CWE-352",
    note: "The framework's CSRF guard is switched off (commented out, skipped, or exempted). Any state-changing route it covered can now be driven from an attacker's page using the victim's cookies.",
  },
  "graphql-introspection": {
    id: "graphql-introspection",
    title: "GraphQL introspection / dev UI enabled",
    severity: "medium",
    cwe: "CWE-200",
    note: "Introspection (or GraphiQL/Playground) hands an attacker the whole schema. Disable it in production.",
  },
  // ── Hardening absent where the app is constructed ─────────────────────────
  // The three below are ABSENCES, which this detector otherwise avoids (an
  // absence has no line to cite). They are grounded on the one line that does
  // exist: the `express()` / `new Hono()` / `FastAPI()` call that builds the
  // app, in the file that builds it — where the middleware would be registered.
  "helmet-missing": {
    id: "helmet-missing",
    title: "No security-headers middleware where the app is built",
    severity: "low",
    cwe: "CWE-693",
    note: "The file constructs the application and registers no `helmet()` / `secureHeaders()` / equivalent. Without it the responses carry no CSP, HSTS, X-Frame-Options or X-Content-Type-Options. Register it first, before any route — unless a reverse proxy in front sets these headers, which is the thing to check.",
  },
  "trust-proxy": {
    id: "trust-proxy",
    title: "`trust proxy` enabled",
    severity: "low",
    cwe: "CWE-290",
    note: "`app.set('trust proxy', …)` makes `req.ip`, `req.protocol` and `req.hostname` come from X-Forwarded-* headers. Correct behind a proxy that strips and rewrites them; when the app is reachable directly, any client can forge its IP (rate limits, allow-lists, audit logs) and its scheme. Confirm the deployment topology and prefer a hop count or an address list over `true`.",
  },
  "body-limit-missing": {
    id: "body-limit-missing",
    title: "Body parser registered without a size limit",
    severity: "low",
    cwe: "CWE-770",
    note: "`express.json()` / `express.urlencoded()` / `bodyParser.*()` with no `limit`. The default (100 kB) is small, so this is a hardening note rather than a hole — but a raised default elsewhere, or a `text()`/`raw()` parser, makes an unbounded body a memory-exhaustion vector. State the limit explicitly.",
  },
  // ── Application-code shapes with no source→sink flow ──────────────────────
  "csv-formula": {
    id: "csv-formula",
    title: "CSV built by hand without formula neutralization",
    severity: "medium",
    cwe: "CWE-1236",
    note: 'The CSV is assembled with `.join(";")` / `.join(",")`, and nothing neutralizes a cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return. Opened in a spreadsheet, such a cell is a FORMULA — `=HYPERLINK(…)` exfiltrates the sheet, DDE-style payloads run commands on older clients. Quoting is not enough. Prefix those cells with `\'` (OWASP CSV injection), including values that come from the database (second-order).',
  },
  "env-coerce-boolean": {
    id: "env-coerce-boolean",
    title: "`z.coerce.boolean()` on an environment variable",
    severity: "medium",
    cwe: "CWE-704",
    note: '`z.coerce.boolean()` is `Boolean(value)`: every non-empty string is true, including `"false"` and `"0"`. An operator writing `FLAG=false` turns the flag ON — for a test seam, a mock or a security toggle, that is the opposite of what the deployment says. Parse the string explicitly (`z.enum(["true","false"]).transform(v => v === "true")`, or `z.stringbool()` in zod 4).',
  },
  "xff-first-hop": {
    id: "xff-first-hop",
    title: "Client IP taken from the first X-Forwarded-For entry",
    severity: "medium",
    cwe: "CWE-348",
    note: 'Proxies APPEND to X-Forwarded-For, so the first entry is whatever the client sent. Taking `split(",")[0]` lets any caller choose its own IP — for rate limits, allow-lists and audit logs alike — and an unbounded value can overflow the column it is stored in. Take the entry your own proxy wrote (count hops from the right), or the platform\'s trusted header.',
  },
  "unbounded-export": {
    id: "unbounded-export",
    title: "Public export/listing route queries without a row limit",
    severity: "medium",
    cwe: "CWE-770",
    note: "A route under a public/export path runs a `select … from` (or `findMany`) with no `limit`/`take`. Every call materializes the whole table in memory and on the wire, and the cost grows with the data rather than with the request — a cheap amplification lever even behind a rate limit. Page it, cap it, or stream it with a hard ceiling.",
  },
  "next-headers-missing": {
    id: "next-headers-missing",
    title: "Next.js app sets no security headers",
    severity: "low",
    cwe: "CWE-693",
    note: "This `next.config` defines no `headers()`, and nothing in the app sets a Content-Security-Policy (no middleware, no helper). Next.js sends no CSP, HSTS, X-Frame-Options, X-Content-Type-Options or Referrer-Policy by default. Add them in `headers()` or middleware — unless a reverse proxy or CDN in front sets them, which is the thing to check (`ultrasec probe` sees what is actually served).",
  },
};

interface Line {
  n: number;
  text: string;
}

function lines(content: string): Line[] {
  return content.split(/\r?\n/).map((text, i) => ({ n: i + 1, text }));
}

function extOf(rel: string): string {
  const i = rel.lastIndexOf(".");
  return i === -1 ? "" : rel.slice(i + 1).toLowerCase();
}

const JS = new Set(["js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts"]);
const CODE = new Set([...JS, "py", "go", "java", "kt", "scala", "php", "rb", "cs"]);
// Files whose CONTENT we scan: code plus the web-server/config formats where
// these values are just as often set.
const SCAN = new Set([...CODE, "conf", "nginx", "yaml", "yml"]);

function hit(rel: string, line: number, shape: WebConfigShape, evidence: string): Finding {
  return makeToolFinding({
    tool: "ultrasec",
    category: "config",
    ident: `webconfig:${shape.id}:${rel}:${line}`,
    title: `Web misconfig — ${shape.title}`,
    severity: shape.severity,
    message: `${shape.note}\n\nEvidence: \`${evidence.trim().slice(0, 160)}\``,
    file: rel,
    line,
    cwe: shape.cwe,
  });
}

function lineOf(content: string, index: number): number {
  let n = 1;
  for (let i = 0; i < index && i < content.length; i++) if (content[i] === "\n") n++;
  return n;
}

// ── TLS certificate verification disabled (CWE-295) ─────────────────────────
// Language-gated so a Python `verify=False` never lints a Go file, and vice versa.
const TLS_RULES: { langs: Set<string>; re: RegExp }[] = [
  { langs: JS, re: /rejectUnauthorized\s*:\s*false/ },
  { langs: new Set(["py"]), re: /\bverify\s*=\s*False\b/ },
  { langs: new Set(["py"]), re: /_create_unverified_context|ssl\.\s*CERT_NONE/ },
  { langs: new Set(["go"]), re: /InsecureSkipVerify\s*:\s*true/ },
  { langs: new Set(["php"]), re: /CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:0|false)\b/i },
  { langs: new Set(["java", "kt", "scala"]), re: /ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|TrustAllCerts|trustAllCerts/ },
];

function scanCors(rel: string, content: string, out: Finding[]): void {
  // Origin-setting sites and whether credentials are enabled anywhere in the file.
  const credentials = /Access-Control-Allow-Credentials['"]?\s*[:,]\s*['"]?\s*true/i.test(content) || /\bcredentials\s*:\s*true/.test(content);
  const reflectRe = /Access-Control-Allow-Origin['"]?\s*[:,]\s*[^,\n)]*\b(?:req|request|ctx|headers?)\b[^,\n)]*origin|(?:^|[^\w.])origin\s*:\s*true\b/gi;
  const wildcardRe = /Access-Control-Allow-Origin\s*:\s*\*|Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*['"]|(?:^|[^\w.])origin\s*:\s*['"]\*['"]/gi;

  const seen = new Set<number>();
  for (const m of content.matchAll(reflectRe)) {
    const ln = lineOf(content, m.index ?? 0);
    seen.add(ln);
    out.push(hit(rel, ln, WEBCONFIG_SHAPES["cors-reflect"]!, m[0]));
  }
  for (const m of content.matchAll(wildcardRe)) {
    const ln = lineOf(content, m.index ?? 0);
    if (seen.has(ln)) continue; // a reflect on this line already covers it
    out.push(hit(rel, ln, WEBCONFIG_SHAPES[credentials ? "cors-wildcard-credentials" : "cors-wildcard"]!, m[0]));
  }
}

// The application-code shapes (csv-formula, env-coerce-boolean, xff-first-hop,
// unbounded-export), the two header-posture absences (helmet-missing,
// next-headers-missing), and the framework postures (cookie flags, trust
// proxy, body limit, GraphQL introspection, CSRF disabled, debug mode) are
// weakness classes now: their idioms live in the packs under
// src/classes/packs, per framework, and run on the class engine, which
// reports them under the shapes above so their ids are unchanged. What stays
// here is framework-agnostic: CORS, TLS verification, header VALUES written
// literally, directory listing.

/**
 * Audit a repo for API / web misconfiguration. Returns candidates — a wildcard
 * CORS on an internal service is a different risk from the same on a public API,
 * and only the auditor knows which this is.
 */
export function auditWebConfig(repo: string, prune?: (rel: string) => boolean, tree?: RepoTree): Finding[] {
  const out: Finding[] = [];
  const read = tree?.read ?? readText;
  for (const wf of tree?.files ?? walk(repo)) {
    if (prune?.(wf.rel)) continue;
    const ext = extOf(wf.rel);
    if (!SCAN.has(ext)) continue;
    const content = read(wf.abs);
    if (!content) continue;
    const rel = wf.rel;
    const ls = lines(content);

    for (const l of ls) {
      for (const r of TLS_RULES) if (r.langs.has(ext) && r.re.test(l.text)) out.push(hit(rel, l.n, WEBCONFIG_SHAPES["tls-verify"]!, l.text));
      // NODE_TLS_REJECT_UNAUTHORIZED=0 is dangerous in any file (code, shell, yaml).
      if (/NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['"]?0\b/.test(l.text)) out.push(hit(rel, l.n, WEBCONFIG_SHAPES["tls-verify"]!, l.text));

      if (/Content-Security-Policy/i.test(l.text) && /unsafe-inline|unsafe-eval|(?:default|script|object)-src[^;'"]*\*/i.test(l.text))
        out.push(hit(rel, l.n, WEBCONFIG_SHAPES["header-csp"]!, l.text));
      if (/X-Frame-Options['"]?\s*[:,]\s*['"]?\s*(?:ALLOWALL|ALLOW-FROM)/i.test(l.text)) out.push(hit(rel, l.n, WEBCONFIG_SHAPES["header-xfo"]!, l.text));
      if (/Strict-Transport-Security[^\n]*max-age\s*=\s*0\b/i.test(l.text)) out.push(hit(rel, l.n, WEBCONFIG_SHAPES["header-hsts"]!, l.text));
      if (/Referrer-Policy['"]?\s*[:,]\s*['"]?\s*unsafe-url/i.test(l.text)) out.push(hit(rel, l.n, WEBCONFIG_SHAPES["header-referrer"]!, l.text));

      if (/^\s*autoindex\s+on\b/i.test(l.text) || /\bserve-index\s*\(/.test(l.text)) out.push(hit(rel, l.n, WEBCONFIG_SHAPES["dir-listing"]!, l.text));
    }

    scanCors(rel, content, out);
  }
  return out;
}

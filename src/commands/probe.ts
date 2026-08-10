import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { request as httpsRequest, type RequestOptions } from "node:https";
import { request as httpRequest } from "node:http";
import type { IncomingMessage } from "node:http";
import type { PeerCertificate, TLSSocket } from "node:tls";
import { lookup } from "node:dns/promises";
import { flagBool, flagStr, numFlag, println, eprintln, shortHash, type ParsedArgs } from "../util.js";
import type { Severity } from "../types.js";

// `ultrasec probe <url> --i-own-this`
//
// The ONE dynamic thing ultrasec does — and it is deliberately walled off from
// everything static. It observes a running site's SECURITY POSTURE ON THE WIRE:
// response headers, cookie flags, TLS, redirects, banners, a single crafted CORS
// preflight, optional GraphQL introspection. It reads; it never fuzzes, never
// crawls, never authenticates, and never mutates.
//
// Isolation is the whole design:
//   * Its findings have NO [file:line] — they cite `[response-header:…]`,
//     `[cookie:…]`, `[tls]`, `[url:…]`. So they must never enter findings.json,
//     where `check` would try (and fail) to resolve them. They go to their OWN
//     artifact, PROBE.json / PROBE.md, which `check`, `coverage` and `render`
//     never read.
//   * It is NOT part of `run`/ALL_STAGES and NOT on the MCP tool surface.
// Safety rails: explicit --i-own-this consent, single host, no crawl, read-only
// methods, private/loopback/metadata targets refused unless --allow-private, a
// hard request cap, and a per-request timeout.

export interface ProbeFinding {
  id: string;
  /** headers | cookie | tls | transport | cors | info | graphql | exposure */
  area: string;
  title: string;
  severity: Severity;
  cwe?: string;
  /** The non-[file:line] grounding: what was observed and where. */
  grounding: string;
  message: string;
}

export interface ProbeReport {
  target: string;
  resolvedIp: string | null;
  note: string;
  requestsMade: number;
  observed: {
    status?: number;
    tlsProtocol?: string;
    server?: string;
    setCookies?: number;
  };
  findings: ProbeFinding[];
}

interface Resp {
  status: number;
  headers: IncomingMessage["headers"];
  body: string;
  tlsProtocol?: string;
  cert?: PeerCertificate;
  authorized?: boolean;
  authError?: string;
}

const UA = "ultrasec-probe (authorized security check)";

function isPrivateHost(ip: string): boolean {
  if (ip === "::1" || ip === "::" || ip === "0.0.0.0") return true;
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
  if (m) {
    const a = Number(m[1]);
    const b = Number(m[2]);
    if (a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true; // link-local, incl. 169.254.169.254 cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    return false;
  }
  const lc = ip.toLowerCase();
  if (lc.startsWith("::ffff:")) return isPrivateHost(lc.slice(7)); // v4-mapped
  return lc.startsWith("fc") || lc.startsWith("fd") || lc.startsWith("fe80"); // ULA + link-local
}

async function resolveIp(hostname: string): Promise<string | null> {
  try {
    return (await lookup(hostname)).address;
  } catch {
    return null;
  }
}

function doRequest(u: URL, opts: { method?: string; headers?: Record<string, string>; body?: string; timeout: number }): Promise<Resp> {
  return new Promise((resolveP, reject) => {
    const isHttps = u.protocol === "https:";
    // Typed as https options (a superset of http's); passing this variable to
    // httpRequest is fine structurally — the extra TLS fields are simply ignored.
    const options: RequestOptions = {
      protocol: u.protocol,
      hostname: u.hostname,
      port: u.port || (isHttps ? 443 : 80),
      path: `${u.pathname}${u.search}`,
      method: opts.method ?? "GET",
      headers: { "user-agent": UA, accept: "*/*", ...(opts.headers ?? {}) },
      // Observe & REPORT certificate problems rather than aborting on them —
      // this is a diagnostic probe, not a client that must stay safe.
      rejectUnauthorized: false,
      servername: u.hostname,
    };
    const onRes = (res: IncomingMessage) => {
      const chunks: Buffer[] = [];
      let size = 0;
      const MAX = 262_144; // 256 KiB is plenty for headers + a schema/probe body
      res.on("data", (c: Buffer) => {
        size += c.length;
        if (size <= MAX) chunks.push(c);
        else res.destroy();
      });
      res.on("end", () => {
        const sock = res.socket as unknown as TLSSocket;
        const out: Resp = { status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") };
        if (isHttps && typeof sock?.getProtocol === "function") {
          out.tlsProtocol = sock.getProtocol() ?? undefined;
          try {
            out.cert = sock.getPeerCertificate();
          } catch {
            /* no cert available */
          }
          out.authorized = sock.authorized;
          const ae = (sock as unknown as { authorizationError?: unknown }).authorizationError;
          if (ae) out.authError = String(ae);
        }
        resolveP(out);
      });
      res.on("error", reject);
    };
    const req = isHttps ? httpsRequest(options, onRes) : httpRequest(options, onRes);
    req.on("error", reject);
    req.setTimeout(opts.timeout, () => req.destroy(new Error("request timed out")));
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

interface Ctx {
  cap: number;
  made: number;
  timeout: number;
  findings: ProbeFinding[];
  truncated: boolean;
}

function add(ctx: Ctx, area: string, title: string, severity: Severity, grounding: string, message: string, cwe?: string): void {
  ctx.findings.push({ id: shortHash(`probe:${area}:${grounding}:${title}`), area, title, severity, grounding, message, ...(cwe ? { cwe } : {}) });
}

async function fetchWithin(ctx: Ctx, u: URL, opts: { method?: string; headers?: Record<string, string>; body?: string }): Promise<Resp | null> {
  if (ctx.made >= ctx.cap) {
    ctx.truncated = true;
    return null;
  }
  ctx.made++;
  try {
    return await doRequest(u, { ...opts, timeout: ctx.timeout });
  } catch {
    return null;
  }
}

function headerStr(h: IncomingMessage["headers"], name: string): string | undefined {
  const v = h[name.toLowerCase()];
  return Array.isArray(v) ? v.join(", ") : v;
}

// ── The header checks: presence + value ─────────────────────────────────────
function checkHeaders(ctx: Ctx, u: URL, res: Resp): void {
  const g = (n: string) => `[response-header:${n}]`;
  const csp = headerStr(res.headers, "content-security-policy");
  if (!csp)
    add(ctx, "headers", "No Content-Security-Policy", "medium", g("Content-Security-Policy"), "No CSP — the last-line XSS mitigation is absent.", "CWE-693");
  else if (/unsafe-inline|unsafe-eval|(?:default|script|object)-src[^;]*\*/i.test(csp))
    add(
      ctx,
      "headers",
      "Weak Content-Security-Policy",
      "medium",
      g("Content-Security-Policy"),
      `CSP allows unsafe-inline/eval or a wildcard source: ${csp.slice(0, 120)}`,
      "CWE-693",
    );

  if (u.protocol === "https:") {
    const hsts = headerStr(res.headers, "strict-transport-security");
    if (!hsts)
      add(
        ctx,
        "headers",
        "No HSTS",
        "medium",
        g("Strict-Transport-Security"),
        "No Strict-Transport-Security — a request can be downgraded to HTTP.",
        "CWE-319",
      );
    else {
      const age = /max-age\s*=\s*(\d+)/i.exec(hsts);
      if (age && Number(age[1]) === 0) add(ctx, "headers", "HSTS disabled (max-age=0)", "medium", g("Strict-Transport-Security"), hsts, "CWE-319");
      else if (age && Number(age[1]) < 15_552_000) add(ctx, "headers", "HSTS max-age below 180 days", "low", g("Strict-Transport-Security"), hsts, "CWE-319");
    }
  }

  const xfo = headerStr(res.headers, "x-frame-options");
  const frameAncestors = csp ? /frame-ancestors/i.test(csp) : false;
  if (!xfo && !frameAncestors)
    add(
      ctx,
      "headers",
      "No clickjacking protection",
      "medium",
      g("X-Frame-Options"),
      "Neither X-Frame-Options nor CSP frame-ancestors — the page is framable.",
      "CWE-1021",
    );
  else if (xfo && /allowall|allow-from/i.test(xfo)) add(ctx, "headers", "X-Frame-Options allows framing", "medium", g("X-Frame-Options"), xfo, "CWE-1021");

  const xcto = headerStr(res.headers, "x-content-type-options");
  if (!xcto)
    add(
      ctx,
      "headers",
      "No X-Content-Type-Options",
      "low",
      g("X-Content-Type-Options"),
      "Missing `nosniff` — the browser may MIME-sniff responses.",
      "CWE-693",
    );
  else if (!/nosniff/i.test(xcto)) add(ctx, "headers", "X-Content-Type-Options not nosniff", "low", g("X-Content-Type-Options"), xcto, "CWE-693");

  const ref = headerStr(res.headers, "referrer-policy");
  if (ref && /unsafe-url/i.test(ref)) add(ctx, "headers", "Referrer-Policy leaks full URL", "low", g("Referrer-Policy"), ref, "CWE-200");

  // Banner disclosure — only when a version is actually exposed (reduces noise).
  for (const name of ["server", "x-powered-by"]) {
    const v = headerStr(res.headers, name);
    if (v && /\d/.test(v)) add(ctx, "info", `Version disclosed in ${name}`, "low", g(name), v, "CWE-200");
  }
}

function checkCookies(ctx: Ctx, res: Resp): void {
  const raw = res.headers["set-cookie"];
  if (!raw) return;
  for (const c of raw) {
    const name = /^([^=]+)=/.exec(c)?.[1]?.trim() ?? "cookie";
    const g = `[cookie:${name}]`;
    const httpOnly = /;\s*httponly/i.test(c);
    const secure = /;\s*secure/i.test(c);
    const sameSite = /;\s*samesite\s*=\s*(strict|lax|none)/i.exec(c);
    if (!httpOnly) add(ctx, "cookie", `Cookie ${name} without HttpOnly`, "medium", g, c.slice(0, 120), "CWE-1004");
    if (!secure) add(ctx, "cookie", `Cookie ${name} without Secure`, "medium", g, c.slice(0, 120), "CWE-614");
    if (!sameSite) add(ctx, "cookie", `Cookie ${name} without SameSite`, "low", g, c.slice(0, 120), "CWE-1275");
    else if (sameSite[1]?.toLowerCase() === "none" && !secure)
      add(ctx, "cookie", `Cookie ${name} SameSite=None without Secure`, "high", g, c.slice(0, 120), "CWE-1275");
    if (name.startsWith("__Host-") && (!secure || /;\s*domain=/i.test(c)))
      add(ctx, "cookie", `__Host- cookie ${name} violates its prefix rules`, "medium", g, c.slice(0, 120), "CWE-614");
    if (name.startsWith("__Secure-") && !secure) add(ctx, "cookie", `__Secure- cookie ${name} without Secure`, "medium", g, c.slice(0, 120), "CWE-614");
  }
}

function checkTls(ctx: Ctx, u: URL, res: Resp): void {
  if (u.protocol !== "https:") return;
  if (res.tlsProtocol && /TLSv1(\.[01])?$/.test(res.tlsProtocol))
    add(ctx, "tls", `Weak TLS protocol ${res.tlsProtocol}`, "high", "[tls]", `The server negotiated ${res.tlsProtocol}; TLS 1.2+ is required.`, "CWE-327");
  if (res.authorized === false)
    add(
      ctx,
      "tls",
      "Certificate not trusted",
      "high",
      "[tls]",
      `Certificate did not validate: ${res.authError ?? "unknown reason"} (self-signed, expired, or hostname mismatch).`,
      "CWE-295",
    );
  const to = res.cert?.valid_to;
  if (to) {
    const exp = Date.parse(to);
    if (!Number.isNaN(exp)) {
      const days = Math.floor((exp - Date.now()) / 86_400_000);
      if (days < 0) add(ctx, "tls", "Certificate expired", "high", "[tls]", `Certificate expired ${-days} day(s) ago (valid_to ${to}).`, "CWE-295");
      else if (days < 21) add(ctx, "tls", "Certificate expiring soon", "medium", "[tls]", `Certificate expires in ${days} day(s) (valid_to ${to}).`, "CWE-295");
    }
  }
}

async function checkTransport(ctx: Ctx, u: URL): Promise<void> {
  if (u.protocol === "http:") {
    add(
      ctx,
      "transport",
      "Served over cleartext HTTP",
      "high",
      `[url:${u.origin}]`,
      "The target is reachable over plain HTTP — traffic can be read and modified on the wire.",
      "CWE-319",
    );
    return;
  }
  // https target: does the http:// origin redirect up to https?
  const httpUrl = new URL(u.toString());
  httpUrl.protocol = "http:";
  httpUrl.port = "";
  const res = await fetchWithin(ctx, httpUrl, { method: "GET" });
  if (!res) return;
  const loc = headerStr(res.headers, "location");
  const redirects = res.status >= 300 && res.status < 400 && !!loc && /^https:/i.test(loc);
  if (!redirects && res.status < 500)
    add(
      ctx,
      "transport",
      "HTTP not redirected to HTTPS",
      "medium",
      `[url:${httpUrl.origin}]`,
      `Plain HTTP returned ${res.status} without a redirect to HTTPS.`,
      "CWE-319",
    );
}

async function checkCors(ctx: Ctx, u: URL): Promise<void> {
  const evil = "https://ultrasec-probe.example";
  const res = await fetchWithin(ctx, u, { method: "OPTIONS", headers: { origin: evil, "access-control-request-method": "GET" } });
  if (!res) return;
  const acao = headerStr(res.headers, "access-control-allow-origin");
  const acac = headerStr(res.headers, "access-control-allow-credentials");
  if (!acao) return;
  const g = "[response-header:Access-Control-Allow-Origin]";
  if (acao === evil)
    add(
      ctx,
      "cors",
      "CORS reflects an arbitrary Origin",
      "high",
      g,
      `The server echoed our test Origin (${evil}) — any site can read authenticated responses.`,
      "CWE-942",
    );
  else if (acao === "*" && /true/i.test(acac ?? ""))
    add(ctx, "cors", "Wildcard CORS with credentials", "high", g, "Access-Control-Allow-Origin `*` with Allow-Credentials true.", "CWE-942");
  else if (acao === "*") add(ctx, "cors", "Wildcard CORS origin", "low", g, "Access-Control-Allow-Origin `*`.", "CWE-942");
}

async function checkSecurityTxt(ctx: Ctx, u: URL): Promise<void> {
  const st = new URL("/.well-known/security.txt", u.origin);
  const res = await fetchWithin(ctx, st, { method: "GET" });
  if (!res) return;
  if (res.status !== 200)
    add(
      ctx,
      "info",
      "No security.txt",
      "low",
      `[url:${st.toString()}]`,
      "No /.well-known/security.txt (RFC 9116) — no documented way to report a vulnerability.",
      "CWE-200",
    );
}

async function checkGraphql(ctx: Ctx, u: URL): Promise<void> {
  const body = JSON.stringify({ query: "{__schema{queryType{name}}}" });
  const res = await fetchWithin(ctx, u, { method: "POST", headers: { "content-type": "application/json" }, body });
  if (!res) return;
  if (/"__schema"|"queryType"/.test(res.body))
    add(
      ctx,
      "graphql",
      "GraphQL introspection enabled",
      "medium",
      `[url:${u.toString()}]`,
      "Introspection returned the schema — an attacker can enumerate every type, query and mutation.",
      "CWE-200",
    );
}

const DEEP_PATHS: { path: string; needle: RegExp; title: string }[] = [
  { path: "/.env", needle: /^[A-Z0-9_]+=/m, title: "Exposed .env file" },
  { path: "/.git/config", needle: /\[core\]|\[remote/i, title: "Exposed .git/config" },
  { path: "/.git/HEAD", needle: /^ref:\s/i, title: "Exposed .git directory" },
  { path: "/server-status", needle: /Apache Server Status|Server uptime/i, title: "Exposed server-status" },
];

async function checkDeep(ctx: Ctx, u: URL): Promise<void> {
  for (const d of DEEP_PATHS) {
    if (ctx.made >= ctx.cap) {
      ctx.truncated = true;
      return;
    }
    const target = new URL(d.path, u.origin);
    const res = await fetchWithin(ctx, target, { method: "GET" });
    if (!res) continue;
    if (res.status === 200 && d.needle.test(res.body))
      add(ctx, "exposure", d.title, "high", `[url:${target.toString()}]`, `${target.pathname} is served and its content matches a sensitive file.`, "CWE-538");
  }
}

function renderProbeMd(r: ProbeReport): string {
  const L: string[] = [`# ultrasec probe — ${r.target}`, ""];
  L.push(
    `> Live-site posture check. Findings are grounded on the WIRE (\`[response-header:…]\`, \`[cookie:…]\`, \`[tls]\`, \`[url:…]\`), NOT on source — they live here, never in findings.json, and the \`check\` gate never sees them.`,
  );
  L.push("");
  L.push(
    `- resolved IP: ${r.resolvedIp ?? "—"}  ·  status: ${r.observed.status ?? "—"}  ·  TLS: ${r.observed.tlsProtocol ?? "—"}  ·  requests: ${r.requestsMade}`,
  );
  if (r.note) L.push(`- note: ${r.note}`);
  L.push("");
  if (!r.findings.length) {
    L.push(`No posture issues observed in what was checked. This is not a clean bill of health — it is a light, unauthenticated, read-only probe.`);
    return `${L.join("\n")}\n`;
  }
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  const bySev = [...r.findings].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  L.push(`| severity | area | finding | grounding | cwe |`);
  L.push(`|---|---|---|---|---|`);
  for (const f of bySev) L.push(`| ${f.severity} | ${f.area} | ${f.title} | \`${f.grounding}\` | ${f.cwe ?? "—"} |`);
  L.push("");
  for (const f of bySev) {
    L.push(`### ${f.severity.toUpperCase()} — ${f.title}`);
    L.push(`- grounding: \`${f.grounding}\`${f.cwe ? ` · ${f.cwe}` : ""}`);
    L.push(`- ${f.message}`);
    L.push("");
  }
  return `${L.join("\n")}\n`;
}

export async function runProbe(args: ParsedArgs): Promise<number> {
  const raw = args._[1];
  if (!raw) {
    eprintln("usage: ultrasec probe <url> --i-own-this [--deep] [--graphql] [--allow-private] [--timeout ms] [--out dir]");
    return 2;
  }
  // Consent is mandatory and explicit: probing a host you do not own may be
  // unlawful, and ultrasec will not do it on an implicit default.
  if (!flagBool(args, "i-own-this")) {
    eprintln("ultrasec probe: refusing without --i-own-this. Only probe a target you own or are explicitly authorized to test.");
    return 2;
  }
  let url: URL;
  try {
    url = new URL(raw.includes("://") ? raw : `https://${raw}`);
  } catch {
    eprintln(`ultrasec probe: '${raw}' is not a valid URL.`);
    return 2;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    eprintln(`ultrasec probe: only http/https targets are supported (got ${url.protocol}).`);
    return 2;
  }

  const allowPrivate = flagBool(args, "allow-private");
  const resolvedIp = await resolveIp(url.hostname);
  if (resolvedIp && isPrivateHost(resolvedIp) && !allowPrivate) {
    eprintln(
      `ultrasec probe: ${url.hostname} resolves to a private/loopback/metadata address (${resolvedIp}). Pass --allow-private for a local target you own.`,
    );
    return 2;
  }

  const deep = flagBool(args, "deep");
  const graphql = flagBool(args, "graphql");
  const timeout = numFlag(args, "timeout") ?? 10_000;
  const out = resolve(flagStr(args, "out") ?? ".ultrasec");
  const ctx: Ctx = { cap: deep ? 24 : 12, made: 0, timeout, findings: [], truncated: false };

  const main = await fetchWithin(ctx, url, { method: "GET" });
  if (!main) {
    eprintln(`ultrasec probe: could not reach ${url.toString()} (connection failed or timed out).`);
    return 1;
  }

  checkHeaders(ctx, url, main);
  checkCookies(ctx, main);
  checkTls(ctx, url, main);
  await checkTransport(ctx, url);
  await checkCors(ctx, url);
  await checkSecurityTxt(ctx, url);
  if (graphql) await checkGraphql(ctx, url);
  if (deep) await checkDeep(ctx, url);

  const report: ProbeReport = {
    target: url.toString(),
    resolvedIp,
    note: ctx.truncated ? `request cap (${ctx.cap}) reached — some optional checks were skipped.` : "",
    requestsMade: ctx.made,
    observed: {
      status: main.status,
      tlsProtocol: main.tlsProtocol,
      server: headerStr(main.headers, "server"),
      setCookies: Array.isArray(main.headers["set-cookie"]) ? main.headers["set-cookie"].length : 0,
    },
    findings: ctx.findings,
  };

  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, "PROBE.json"), `${JSON.stringify(report, null, 2)}\n`);
  writeFileSync(join(out, "PROBE.md"), renderProbeMd(report));

  const counts: Record<string, number> = {};
  for (const f of report.findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  if (flagBool(args, "json")) {
    println(JSON.stringify(report, null, 2));
  } else {
    println(`ultrasec probe → ${join(out, "PROBE.md")} (+ PROBE.json)`);
    println(`  target: ${report.target}  ·  status ${main.status}  ·  TLS ${main.tlsProtocol ?? "—"}  ·  ${ctx.made} request(s)`);
    println(
      `  posture findings: ${report.findings.length}  (crit ${counts.critical ?? 0} · high ${counts.high ?? 0} · med ${counts.medium ?? 0} · low ${counts.low ?? 0})`,
    );
    println(`  NOTE: probe findings live in PROBE.json only — they never enter the static dossier or the check gate.`);
    if (ctx.truncated) println(`  ${report.note}`);
  }

  // Advisory by default; --strict turns a high/critical posture finding into a
  // non-zero exit for CI, matching the other commands' --strict contract.
  const highOrWorse = report.findings.some((f) => f.severity === "critical" || f.severity === "high");
  return flagBool(args, "strict") && highOrWorse ? 1 : 0;
}

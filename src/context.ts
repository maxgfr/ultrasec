import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { findManifestDirs, readText } from "./walk.js";
import { langForFile } from "./lang.js";
import { SANITIZERS } from "./catalog.js";
import type { RepoScan } from "./scan.js";
import type { AttackSurface } from "./map.js";
import { entryWeight } from "./map.js";
import type { ContextScaffold } from "./types.js";
import { byStr } from "./util.js";

// The project-context primer (Phase 1). The cheapest, highest-leverage stage: a
// deterministic scaffold of the project's frameworks, entry points, auth
// middleware, and sanitizers → the agent authors a prose `CONTEXT.md` describing
// the trust model + framework protections. ultrasec then injects CONTEXT.md into
// every dossier and the verify worklist, so later stages reason WITH the project's
// own threat model instead of generic assumptions. It is ADDITIVE EVIDENCE ONLY —
// it never gates or changes a verdict (same discipline as `--blame` provenance).

// Cap each scaffold list so the output stays bounded + deterministic on huge repos.
// The entry-point list gets a larger budget than the others: it now carries one
// line per FILE rather than per line-hit, so each slot is worth far more, and a
// monorepo's HTTP surface spread over five workspaces does not fit in forty.
const MAX_SCAFFOLD = 40;
const MAX_SCAFFOLD_ENTRIES = 80;

// Auth / authorization markers, across ecosystems. Recall-oriented: a match is a
// CANDIDATE protection site for the agent to confirm, not proof a route is guarded.
const AUTH_RE =
  /\b(requireAuth|requiresAuth|isAuthenticated|ensureAuthenticated|ensureLoggedIn|ensureLogin|requireLogin|checkAuth|verifyToken|verifyJwt|jwtVerify|authenticateToken|authMiddleware|requireRole|requireAdmin|hasRole|hasPermission|checkPermission|authorize|authorization|passport\.authenticate|@UseGuards|@PreAuthorize|@Secured|@RolesAllowed|login_required|permission_required|before_action|authenticate_user!|current_user)\b/;

// Dependency name → friendly framework label (package.json deps/devDeps keys).
const JS_FRAMEWORKS: Record<string, string> = {
  express: "express",
  koa: "koa",
  fastify: "fastify",
  "@nestjs/core": "nestjs",
  next: "next.js",
  nuxt: "nuxt",
  "@hapi/hapi": "hapi",
  hapi: "hapi",
  sails: "sails",
  restify: "restify",
  react: "react",
  vue: "vue",
  "@angular/core": "angular",
  svelte: "svelte",
  "apollo-server": "apollo",
  graphql: "graphql",
  "socket.io": "socket.io",
  mongoose: "mongoose",
  sequelize: "sequelize",
  prisma: "prisma",
  knex: "knex",
  typeorm: "typeorm",
  passport: "passport",
  jsonwebtoken: "jwt",
};

// Substring/regex detectors for text-based manifests (offline, tolerant of format).
const TEXT_MANIFESTS: { file: string; rules: [RegExp, string][] }[] = [
  {
    file: "requirements.txt",
    rules: [
      [/\bflask\b/i, "flask"],
      [/\bdjango\b/i, "django"],
      [/\bfastapi\b/i, "fastapi"],
      [/\btornado\b/i, "tornado"],
      [/\bbottle\b/i, "bottle"],
      [/\bpyramid\b/i, "pyramid"],
      [/\bsanic\b/i, "sanic"],
      [/\baiohttp\b/i, "aiohttp"],
      [/\bsqlalchemy\b/i, "sqlalchemy"],
    ],
  },
  {
    file: "go.mod",
    rules: [
      [/gin-gonic\/gin/, "gin"],
      [/labstack\/echo/, "echo"],
      [/gofiber\/fiber/, "fiber"],
      [/go-chi\/chi/, "chi"],
      [/gorilla\/mux/, "gorilla/mux"],
      [/gorm\.io\/gorm/, "gorm"],
    ],
  },
  {
    file: "Gemfile",
    rules: [
      [/\brails\b/i, "rails"],
      [/\bsinatra\b/i, "sinatra"],
      [/\bsequel\b/i, "sequel"],
      [/\bhanami\b/i, "hanami"],
    ],
  },
  {
    file: "composer.json",
    rules: [
      [/laravel\/framework/, "laravel"],
      [/symfony\//, "symfony"],
      [/slim\/slim/, "slim"],
    ],
  },
  {
    file: "build.gradle",
    rules: [[/springframework|org\.springframework|spring-boot/i, "spring"]],
  },
  {
    file: "pom.xml",
    rules: [
      [/springframework/i, "spring"],
      [/jersey/i, "jersey"],
    ],
  },
];

/**
 * Detect frameworks from on-disk manifests. Offline + tolerant: a missing or
 * malformed manifest contributes nothing rather than throwing.
 *
 * EVERY manifest in the tree is read, not just the root's. A monorepo keeps its
 * dependencies in the workspace packages — `targets/frontend/package.json`, not
 * `./package.json` — so reading only the root reported `frameworks: —` on a
 * repo whose whole attack surface was a Next.js app, and the trust boundaries
 * inferred from that emptiness were wrong for the same reason. `findManifestDirs`
 * is the same bounded walk the lockfile adapters already use for exactly this.
 */
function detectFrameworks(repo: string): string[] {
  const found = new Set<string>();

  for (const dir of findManifestDirs(repo, ["package.json"])) {
    try {
      const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
        peerDependencies?: Record<string, string>;
      };
      const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}), ...(pkg.peerDependencies ?? {}) };
      for (const name of Object.keys(deps)) {
        const label = Object.hasOwn(JS_FRAMEWORKS, name) ? JS_FRAMEWORKS[name] : undefined;
        if (label) found.add(label);
      }
    } catch {
      /* malformed package.json — skip */
    }
  }

  for (const m of TEXT_MANIFESTS) {
    for (const dir of findManifestDirs(repo, [m.file])) {
      let raw: string;
      try {
        raw = readFileSync(join(dir, m.file), "utf8");
      } catch {
        continue;
      }
      for (const [re, name] of m.rules) if (re.test(raw)) found.add(name);
    }
  }

  return [...found].sort(byStr);
}

function appliesTo(languages: string[], langId: string): boolean {
  return languages.includes("*") || languages.includes(langId);
}

function inferTrustBoundaries(surface: AttackSurface, authCount: number): string[] {
  const kinds = new Set(surface.entryPoints.map((g) => g.kind));
  const out: string[] = [];
  if (kinds.has("http")) out.push("HTTP request handlers receive untrusted client input (query/body/params/headers/cookies).");
  if (kinds.has("ws")) out.push("WebSocket/stream messages are untrusted client data.");
  if (kinds.has("cli")) out.push("CLI arguments are untrusted when the program is invoked with attacker-controlled args.");
  if (kinds.has("env")) out.push("Environment variables — trust depends on the deployment / secret-management model.");
  if (kinds.has("stdin")) out.push("Interactive/stdin input is untrusted.");
  out.push(
    authCount > 0
      ? `Authentication boundary: ${authCount} candidate auth/authorization site(s) detected — confirm which routes they actually protect.`
      : `No auth/authorization middleware detected — confirm whether endpoints are intentionally public.`,
  );
  return out;
}

/**
 * Build the deterministic project-context scaffold. Reuses the same offline passes
 * as `map`/`scan`: the attack surface (entry points), the SANITIZERS catalog, and
 * a re-read of each language file for auth-middleware markers. Deterministic +
 * bounded (each list capped + id-sorted).
 */
export function buildContextScaffold(repo: string, scan: RepoScan, surface: AttackSurface): ContextScaffold {
  const frameworks = detectFrameworks(repo);

  // ONE entry point per (file, kind), selected by rank, presented by path.
  //
  // Two things were wrong with taking the first MAX_SCAFFOLD of a
  // filename-sorted list. It was an alphabetical PREFIX rather than a sample, so
  // on a monorepo whose web app lives under `targets/` every route in it fell
  // off the end — and detecting MORE routes made that worse, because the extra
  // hits pushed the cap further up the alphabet. And the budget was spent per
  // LINE, so one busy server file with thirty `req.` reads consumed most of it
  // while thirty separate route files got nothing.
  //
  // This is a "where to look" brief. One line per file is the granularity that
  // serves it, and it is what lets a monorepo's whole API surface fit in the
  // list at all. The true total is reported separately, so the cap is never
  // mistaken for the whole surface.
  const rank = new Map(surface.byFile.map((f) => [f.file, f.score]));
  const perFile = new Map<string, { file: string; line: number; kind: string }>();
  for (const g of surface.entryPoints) {
    for (const s of g.samples) {
      const key = `${s.file}\u0000${s.kind}`;
      const seen = perFile.get(key);
      if (!seen || s.line < seen.line) perFile.set(key, { file: s.file, line: s.line, kind: s.kind });
    }
  }
  const entryPoints = [...perFile.values()]
    .sort(
      (a, b) =>
        // Kind first: in a capped brief, an HTTP route earns its slot ahead of
        // an environment read, which presumes a much narrower attacker.
        entryWeight(b.kind) - entryWeight(a.kind) ||
        (rank.get(b.file) ?? 0) - (rank.get(a.file) ?? 0) ||
        byStr(a.file, b.file) ||
        a.line - b.line ||
        byStr(a.kind, b.kind),
    )
    .slice(0, MAX_SCAFFOLD_ENTRIES)
    .sort((a, b) => byStr(a.file, b.file) || a.line - b.line || byStr(a.kind, b.kind));

  const authMiddleware: { file: string; line: number; hint: string }[] = [];
  const sanitizers: { file: string; line: number; kind: string }[] = [];
  for (const fileScan of scan.files) {
    const spec = langForFile(fileScan.rel);
    if (!spec) continue;
    const lines = readText(join(repo, fileScan.rel)).split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      const am = AUTH_RE.exec(line);
      if (am) authMiddleware.push({ file: fileScan.rel, line: i + 1, hint: am[0] });
      for (const rule of SANITIZERS) {
        if (!appliesTo(rule.languages, spec.id)) continue;
        if (rule.re.test(line)) {
          sanitizers.push({ file: fileScan.rel, line: i + 1, kind: rule.kind });
          break; // first matching sanitizer per line
        }
      }
    }
  }
  const bySite = (a: { file: string; line: number }, b: { file: string; line: number }) => byStr(a.file, b.file) || a.line - b.line;

  return {
    frameworks,
    entryPoints,
    authMiddleware: authMiddleware.sort(bySite).slice(0, MAX_SCAFFOLD),
    sanitizers: sanitizers.sort(bySite).slice(0, MAX_SCAFFOLD),
    trustBoundaries: inferTrustBoundaries(surface, authMiddleware.length),
  };
}

/** The CONTEXT.todo.md brief: the scaffold + an outline the agent fills into CONTEXT.md. */
export function renderContextScaffoldMd(repo: string, run: string, s: ContextScaffold): string {
  const L: string[] = [];
  L.push(`# ultrasec project-context primer`);
  L.push("");
  L.push(`- repo: \`${repo}\``);
  L.push("");
  L.push(`> The deterministic scaffold below is a STARTING POINT. Author **\`${join(run, "CONTEXT.md")}\`**`);
  L.push(`> describing the project's purpose, trust model, auth/authorization scheme, and any`);
  L.push(`> framework-provided protections. ultrasec injects CONTEXT.md into every \`dossier\` and the`);
  L.push(`> \`verify\` worklist, so later stages reason WITH your threat model. CONTEXT.md is **additive`);
  L.push(`> evidence only — it never gates or changes a verdict.**`);
  L.push("");

  L.push(`## Detected frameworks`);
  L.push(s.frameworks.length ? s.frameworks.map((f) => `\`${f}\``).join(", ") : "_none detected — confirm the stack manually._");
  L.push("");

  L.push(`## Entry points (untrusted input) — ${s.entryPoints.length}${s.entryPoints.length >= MAX_SCAFFOLD_ENTRIES ? "+" : ""}`);
  L.push("");
  if (!s.entryPoints.length) L.push(`_none detected._`);
  else L.push(`_One line per file, highest attack surface first (HTTP and cross-origin kinds before env/CLI)._`);
  for (const e of s.entryPoints) L.push(`- \`${e.file}:${e.line}\` (${e.kind})`);
  L.push("");

  L.push(`## Auth / authorization sites (candidate protections) — ${s.authMiddleware.length}${s.authMiddleware.length >= MAX_SCAFFOLD ? "+" : ""}`);
  if (!s.authMiddleware.length) L.push(`_none detected — confirm whether endpoints are intentionally public._`);
  for (const a of s.authMiddleware) L.push(`- \`${a.file}:${a.line}\` — ${a.hint}`);
  L.push("");

  L.push(`## Sanitizers / validators present — ${s.sanitizers.length}${s.sanitizers.length >= MAX_SCAFFOLD ? "+" : ""}`);
  if (!s.sanitizers.length) L.push(`_none detected._`);
  for (const sa of s.sanitizers) L.push(`- \`${sa.file}:${sa.line}\` (${sa.kind})`);
  L.push("");

  L.push(`## Trust boundaries (inferred)`);
  for (const t of s.trustBoundaries) L.push(`- ${t}`);
  L.push("");

  L.push(`## Suggested CONTEXT.md outline`);
  L.push(`1. **What the app does** and who its users are.`);
  L.push(`2. **Authentication & authorization model** — who is allowed to do what, and how it's enforced.`);
  L.push(`3. **Trust boundaries** — where untrusted data enters; what is trusted.`);
  L.push(`4. **Framework protections already in place** — ORM parameterization, template auto-escaping, CSRF tokens, etc.`);
  L.push(`5. **Known-safe sinks / accepted risks** — so later stages don't re-litigate them.`);
  L.push(`6. **Exposure** — one of \`internet-facing\` · \`internal\` · \`build-time\`, and`);
  L.push(`   **asset criticality** — \`crown-jewel\` · \`standard\` · \`peripheral\`. Write them as a line`);
  L.push(`   \`Exposure: internet-facing\` / \`Criticality: crown-jewel\`; the risk score reads them and`);
  L.push(`   ranks accordingly. Absent, ranking is unchanged.`);
  L.push(`7. **Threat model (STRIDE)** — per trust boundary, which of Spoofing / Tampering /`);
  L.push(`   Repudiation / Information disclosure / Denial of service / Elevation of privilege you`);
  L.push(`   actually care about, and which you have accepted. For personal data add LINDDUN`);
  L.push(`   (Linking, Identifying, Non-repudiation, Detecting, Data disclosure, Unawareness,`);
  L.push(`   Non-compliance). See references/threat-modeling.md — this is what stops the hunt`);
  L.push(`   being a checklist walk.`);
  L.push("");
  return L.join("\n") + "\n";
}

/**
 * Load the agent-authored `CONTEXT.md` from a run dir, if present and non-empty.
 * Returns `undefined` otherwise — so every grounding consumer is presence-gated
 * and output stays byte-identical to today when no CONTEXT.md exists.
 */
export function loadContextDoc(run: string): string | undefined {
  const p = join(run, "CONTEXT.md");
  if (!existsSync(p)) return undefined;
  try {
    const s = readFileSync(p, "utf8").trim();
    return s.length ? s : undefined;
  } catch {
    return undefined;
  }
}

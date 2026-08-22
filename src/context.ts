import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { buildPruneMatcher, findManifestDirs, readText, walk } from "./walk.js";
import { detectWorkspaces, isTestPath } from "./vendor/codeindex-engine.mjs";
import { langForFile, type LangSpec } from "./lang.js";
import { SANITIZERS, findSinks, findTextSinks } from "./catalog.js";
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
//
// Exported as `AUTH_MARKER` because the guard matrix (`guards.ts`) asks the other
// half of the same question — which of these markers is in scope for which entry
// point. Two copies of this vocabulary would let the context brief and the matrix
// disagree about what a protection even looks like.
export const AUTH_MARKER =
  /\b(requireAuth|requiresAuth|isAuthenticated|ensureAuthenticated|ensureLoggedIn|ensureLogin|requireLogin|checkAuth|verifyToken|verifyJwt|jwtVerify|authenticateToken|authMiddleware|requireRole|requireAdmin|hasRole|hasPermission|checkPermission|authorize|authorization|passport\.authenticate|@UseGuards|@PreAuthorize|@Secured|@RolesAllowed|login_required|permission_required|before_action|authenticate_user!|current_user)\b/;

// Rate-limiting / throttling markers, the same shape of vocabulary for the other
// absence the matrix can enumerate.
//
// "No throttling anywhere" is a FACT about an application, and a real audit
// established it with `grep -E 'rate|429'` returning nothing — then wrote it up
// as one medium finding, correctly. Nothing in the engine could produce that
// fact, so the coverage matrix carried "missing rate limiting" as advice in a
// hint string and no run ever answered it.
//
// `429` earns its place: a repo that answers `TooManyRequests` anywhere has a
// limiter, whatever it is called. It is matched as a bare number only next to a
// status-shaped context, since a bare 429 in a fixture or a phone number would
// otherwise read as a protection.
export const THROTTLE_MARKER =
  /\b(rateLimit\w*|rate_limit\w*|RateLimit\w*|ratelimit\w*|express-rate-limit|rate-limiter-flexible|slowDown|slow_down|throttle\w*|Throttle\w*|@Throttle|ThrottlerGuard|limiter|Bottleneck|leakyBucket|tokenBucket|TooManyRequests|too_many_requests|TOO_MANY_REQUESTS)\b|\b(?:status|statusCode|code|HTTP_429\w*)\b[^\n]{0,12}\b429\b|\b429\b[^\n]{0,12}\b(?:TooManyRequests|Too Many Requests)\b/;

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

/** Shared by every Python manifest — the framework names are the same whichever
 *  file declares them. */
const PY_RULES: [RegExp, string][] = [
  [/\bflask\b/i, "flask"],
  [/\bdjango\b/i, "django"],
  [/\bfastapi\b/i, "fastapi"],
  [/\btornado\b/i, "tornado"],
  [/\bbottle\b/i, "bottle"],
  [/\bpyramid\b/i, "pyramid"],
  [/\bsanic\b/i, "sanic"],
  [/\baiohttp\b/i, "aiohttp"],
  [/\bsqlalchemy\b/i, "sqlalchemy"],
];

// Substring/regex detectors for text-based manifests (offline, tolerant of format).
const TEXT_MANIFESTS: { file: string; rules: [RegExp, string][] }[] = [
  {
    file: "requirements.txt",
    rules: PY_RULES,
  },
  // Same rules, the manifests modern Python actually uses. requirements.txt alone
  // reported "none detected" on any Poetry/PDM/uv or setuptools project.
  {
    file: "pyproject.toml",
    rules: PY_RULES,
  },
  {
    file: "Pipfile",
    rules: PY_RULES,
  },
  {
    file: "setup.py",
    rules: PY_RULES,
  },
  {
    file: "Cargo.toml",
    rules: [
      [/^\s*actix-web\s*=/m, "actix-web"],
      [/^\s*axum\s*=/m, "axum"],
      [/^\s*rocket\s*=/m, "rocket"],
      [/^\s*warp\s*=/m, "warp"],
      [/^\s*tide\s*=/m, "tide"],
      [/^\s*diesel\s*=/m, "diesel"],
      [/^\s*sqlx\s*=/m, "sqlx"],
    ],
  },
  {
    file: "build.gradle.kts",
    rules: [[/org\.springframework/, "spring"]],
  },
  {
    file: "mix.exs",
    rules: [
      [/:phoenix\b/, "phoenix"],
      [/:plug\b/, "plug"],
      [/:ecto\b/, "ecto"],
    ],
  },
  {
    file: "deno.json",
    rules: [
      [/\boak\b/, "oak"],
      [/\bfresh\b/, "fresh"],
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
/**
 * Directories to look for manifests in: the bounded basename walk, UNION the
 * workspaces the repo actually declares.
 *
 * The walk alone is capped at `MANIFEST_MAX_DEPTH` and knows nothing about
 * membership, so a two-deep `packages` layout is found and a four-deep one is
 * not — and it counts a `package.json` in an untracked scratch tree no build sees.
 * `detectWorkspaces` reads the declarations instead (npm/yarn `workspaces`,
 * `pnpm-workspace.yaml`, `lerna.json`, `nx.json`, Cargo, go.work, Maven, uv,
 * Composer, Gradle). It is already vendored and already used by `regionKeyer`
 * for `investigate` regions — so those were workspace-aware while the stack
 * detection right next to them was not.
 *
 * Union, not replacement: a manifest outside any declared workspace is still a
 * manifest, and losing it to be principled would be a worse bug than the one
 * being fixed.
 */
function manifestDirs(repo: string, names: readonly string[]): string[] {
  const dirs = new Set(findManifestDirs(repo, names));
  try {
    for (const w of detectWorkspaces(repo).packages) {
      const dir = resolve(repo, w.dir);
      for (const name of names) if (existsSync(join(dir, name))) dirs.add(dir);
    }
  } catch {
    /* not a workspace, or an unreadable declaration — the walk still stands */
  }
  return [...dirs].sort(byStr);
}

function detectFrameworks(repo: string): string[] {
  const found = new Set<string>();

  for (const dir of manifestDirs(repo, ["package.json"])) {
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
    for (const dir of manifestDirs(repo, [m.file])) {
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
/**
 * Line number → the sink kinds present on that line, for one file.
 *
 * Memoized per file and built lazily: most files never reach a `sinkLineOnly`
 * rule, and the scaffold already re-reads every file once.
 */
const sinkIndexCache = new WeakMap<object, Map<number, Set<string>>>();
function sinkKindsAt(fileScan: RepoScan["files"][number], spec: LangSpec, lines: string[]): Map<number, Set<string>> {
  const cached = sinkIndexCache.get(fileScan);
  if (cached) return cached;
  const index = new Map<number, Set<string>>();
  const hits = [...findSinks(spec, fileScan.calls ?? [], undefined, fileScan.imports), ...findTextSinks(spec, lines.join("\n"))];
  for (const h of hits) {
    let set = index.get(h.line);
    if (!set) index.set(h.line, (set = new Set()));
    set.add(h.kind);
  }
  sinkIndexCache.set(fileScan, index);
  return index;
}

/**
 * A specific sanitizer outranks the generic one. `*` is the catch-all "type
 * coercion / validation present" rule, which matches `parseInt` and `Number(` —
 * true of almost any file, and useless as a "which sanitizers does this project
 * use?" answer next to a real `DOMPurify` or `escapeHtml`.
 */
function sanitizerWeight(kind: string): number {
  return kind === "*" ? 0 : 1;
}

/**
 * Re-order so every KIND's first site comes before any kind's second.
 *
 * Same argument as `breadthFirstByFile` in map.ts, one axis over: this list
 * answers "which sanitizers does this project use?", so it must cover the kinds
 * before it covers repetitions of one. Ranked by weight then path, the cap was
 * still an alphabetical prefix within the specific tier — 40 slots went to
 * `path` and `redos` hits under `app/` and `playwright.config.ts`, and the
 * project's actual HTML sanitizer, three directories later in the alphabet,
 * never appeared.
 */
function breadthFirstByKind<T extends { kind: string }>(ranked: T[]): T[] {
  const rounds = new Map<string, T[]>();
  for (const x of ranked) (rounds.get(x.kind) ?? rounds.set(x.kind, []).get(x.kind)!).push(x);
  const out: T[] = [];
  for (let i = 0; out.length < ranked.length; i++) {
    let any = false;
    for (const list of rounds.values()) {
      const at = list[i];
      if (at) {
        out.push(at);
        any = true;
      }
    }
    if (!any) break;
  }
  return out;
}

/** Rank, spread across kinds, cap, then restore path order for presentation. */
function capBySite<T extends { file: string; line: number; kind?: string }>(items: T[], weight: (x: T) => number, bySite: (a: T, b: T) => number): T[] {
  const ranked = items.slice().sort((a, b) => weight(b) - weight(a) || bySite(a, b));
  const spread = ranked[0]?.kind === undefined ? ranked : breadthFirstByKind(ranked as (T & { kind: string })[]);
  return spread.slice(0, MAX_SCAFFOLD).sort(bySite);
}

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
        // PRODUCTION first. This brief answers "where does untrusted input enter
        // the shipped artifact?", and a test harness is not the artifact — a
        // route mounted only by jest presumes an attacker who already runs the
        // suite. Measured: 19 of 77 slots on a real monorepo went to
        // `__tests__/*.test.ts` and `src/e2e/*.e2e.ts`, ranked level with the
        // production routes they were crowding out.
        //
        // Ranked, never dropped: with room to spare they still appear, below the
        // real surface. `--include-tests` is for auditing the suite itself.
        (isTestPath(a.file) ? 1 : 0) - (isTestPath(b.file) ? 1 : 0) ||
        // Kind next: in a capped brief, an HTTP route earns its slot ahead of
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
  const seenSanitizer = new Set<string>();
  for (const fileScan of scan.files) {
    const spec = langForFile(fileScan.rel);
    if (!spec) continue;
    const lines = readText(join(repo, fileScan.rel)).split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      const am = AUTH_MARKER.exec(line);
      if (am) authMiddleware.push({ file: fileScan.rel, line: i + 1, hint: am[0] });
      for (const rule of SANITIZERS) {
        if (!appliesTo(rule.languages, spec.id)) continue;
        // A rule that only means something ON a sink line gets tested against
        // one. `?` is a parameterized query on a `query()` line and ordinary
        // punctuation everywhere else — and since that rule is first in the
        // catalog and the loop `break`s, letting it match anywhere claimed 3% of
        // every TypeScript line AND shadowed every real sanitizer behind it.
        if (
          rule.sinkLineOnly &&
          !sinkKindsAt(fileScan, spec, lines)
            .get(i + 1)
            ?.has(rule.kind)
        )
          continue;
        if (rule.re.test(line)) {
          // One row per (file, kind), lowest line — ten `path` hits in one file
          // say nothing the first one did not, and they used to eat the budget.
          const key = `${fileScan.rel}\u0000${rule.kind}`;
          if (!seenSanitizer.has(key)) {
            seenSanitizer.add(key);
            sanitizers.push({ file: fileScan.rel, line: i + 1, kind: rule.kind });
          }
          break; // first matching sanitizer per line
        }
      }
    }
  }
  const bySite = (a: { file: string; line: number }, b: { file: string; line: number }) => byStr(a.file, b.file) || a.line - b.line;

  return {
    frameworks,
    entryPoints,
    authMiddleware: capBySite(authMiddleware, () => 0, bySite),
    // Rank BEFORE capping, for the same reason the entry-point brief does: a
    // path-sorted `slice` is an alphabetical PREFIX, not a sample. On a real
    // audit all 40 slots went to `.husky/`, `lighthouserc.cjs` and `app/a…`,
    // while the repo's only HTML sanitizer — the subject of two of its five high
    // findings — never appeared at all.
    sanitizers: capBySite(sanitizers, (x) => sanitizerWeight(x.kind), bySite),
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
  // Marked, not hidden. A test harness is not the shipped artifact, and a reader
  // scanning seventy paths cannot tell one from a route at a glance — which is
  // how `__tests__/service.test.ts` came to sit in a brief titled "entry points
  // (untrusted input)".
  for (const e of s.entryPoints) L.push(`- \`${e.file}:${e.line}\` (${e.kind})${isTestPath(e.file) ? " — **test harness**, not the shipped artifact" : ""}`);
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
/**
 * The sections of CONTEXT.md that bear on ADJUDICATING one candidate: what the
 * attacker can reach, how exposed the deployment is, how much it matters.
 *
 * `dossier` reprints the whole document before every finding, and an adjudicator
 * runs it dozens of times in a row. On a real audit the context was 4.5 KB and
 * the candidate's own path and code — the thing being scrolled for — sat below
 * it every single time. The trust model still has to be there; the purpose
 * statement and the stack inventory do not have to be there fifty times.
 */
const COMPACT_SECTIONS = /^##\s*(hunt list|exposure|criticality|trust model|trust boundaries|auth)/i;

/**
 * CONTEXT.md reduced to its adjudication-bearing sections, or `undefined` when
 * none match — in which case the caller keeps the full document rather than
 * showing nothing, because an unrecognised heading layout must not silently cost
 * the adjudicator their threat model.
 */
export function compactContextDoc(doc: string): string | undefined {
  const lines = doc.split(/\r?\n/);
  const out: string[] = [];
  let keeping = false;
  for (const line of lines) {
    if (/^##\s/.test(line)) keeping = COMPACT_SECTIONS.test(line);
    if (keeping) out.push(line);
  }
  const kept = out.join("\n").trim();
  return kept.length ? kept : undefined;
}

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

// ── Negative claims, and the tree that disagrees with them ──────────────────
//
// CONTEXT.md is injected into every dossier and every worklist. It is the most
// load-bearing prose in the run, and until now nothing ever compared a word of
// it to the code.
//
// One sentence is enough to lose a class. A real audit's CONTEXT.md said "le
// dépôt ne contient aucun `dangerouslySetInnerHTML` en code de production".
// There were seven, in production components. Every later stage read that
// sentence as background, and the whole stored-XSS family went unexamined —
// not because the engine missed the sinks, but because the auditor had told
// themselves there were none.
//
// A negation is the one kind of prose claim that IS mechanically checkable, and
// only through the part of it that is code: the backticked token. This pass
// never parses the claim. It says: you wrote a negation, this identifier follows
// it, and here is where the identifier occurs. Reconciling is one edit.

/**
 * Negations of PRESENCE, and only those.
 *
 * Bare `pas` is deliberately absent. The same audit wrote "React 19 : bloque les
 * URL `javascript:` … (PAS sur `dangerouslySetInnerHTML`)" — a claim about what
 * React protects, not about what the repo contains. Reading that as "there is no
 * dangerouslySetInnerHTML" would fail a gate on a sentence that is true.
 */
const PRESENCE_NEGATION =
  /\b(?:aucune?s?|nulle\s+part|jamais|n['’]existe|n['’]ont|ne\s+contien\w*|n['’]a\s+aucun|pas\s+d['’]|pas\s+de\b|sans\b|z[ée]ro|no\b|none\b|never\b|nowhere\b|not\s+a\s+single|there\s+(?:is|are)\s+no|contains?\s+no|does\s+not\s+contain|do\s+not\s+contain)/gi;

/** An inline code span whose contents are ONE identifier-ish token. A span with
 *  a space in it (`role: super`, `git log --all`) is prose or a command, not a
 *  name a grep can settle. */
const CODE_SPAN = /`([^`\n]+)`/g;

/**
 * How far after the negation a token still belongs to it — deliberately tiny.
 *
 * "aucun `X`", "no `X`", "pas de `X`", "sans `X`" negate the PRESENCE of X and
 * put it within a couple of characters. Anything further along is a different
 * grammatical role, and reading it as a presence claim is how this check would
 * start crying wolf. Measured on the two audited CONTEXT.md files, a wide window
 * turned "pas de protection CSRF sur les routes `pages/api`" and "Pas
 * d'échappement automatique pour ce qu'un handler écrit via `res.write`" into
 * contradictions — both sentences are true, and neither says the token is
 * absent.
 */
const NEGATION_WINDOW = 16;

/** Prose about a token is not the token. A repository's own audit notes,
 *  changelog and README discuss `dangerouslySetInnerHTML` precisely because
 *  someone was worrying about it, and counting those as evidence would make the
 *  check loudest on the repos that document themselves best. Only files a
 *  language recognises are searched; the message says so. */
const isSearchable = (rel: string): boolean => langForFile(rel) !== undefined;

/** Below this, a token is too generic to mean anything (`id`, `os`, `req`). */
const MIN_TOKEN = 4;

/** Claims examined per run. A CONTEXT.md with more negations than this is not
 *  the shape this check was built for; the excess is reported, never dropped
 *  in silence. */
const MAX_CLAIMS = 20;

/** Occurrences listed per contradicted claim, before "+N more". */
const MAX_HITS = 3;

export interface NegativeClaim {
  /** The sentence as written, for the report. */
  sentence: string;
  /** Its line in CONTEXT.md. */
  line: number;
  /** Identifier-shaped tokens that FOLLOW the negation. */
  tokens: string[];
}

export interface ClaimHit {
  file: string;
  line: number;
}

export interface ContradictedClaim {
  claim: NegativeClaim;
  /** The token the tree disagrees about. */
  token: string;
  /** The first few occurrences, for the report. */
  hits: ClaimHit[];
  /** How many occurrences there are in total. */
  total: number;
}

const isToken = (s: string): boolean => s.length >= MIN_TOKEN && /^[\w$@][\w$.@/:-]*$/.test(s) && /[A-Za-z]/.test(s);

/**
 * Every sentence of `md` that negates the presence of a named identifier.
 *
 * Pure — no filesystem, so the extraction is testable on a string and the search
 * that follows is a separate decision.
 */
export function extractNegativeClaims(md: string): NegativeClaim[] {
  const claims: NegativeClaim[] = [];
  const lines = md.split(/\r?\n/);

  // Blocks of consecutive non-blank lines, so a claim wrapped across two lines
  // is still one sentence. Headings end a block: a heading is not prose.
  let block: { text: string; from: number; to: number } | undefined;
  const flush = (): void => {
    if (!block) return;
    const { from, to } = block;
    for (const sentence of block.text.split(/(?<=[.;!?])\s+/)) {
      const tokens: string[] = [];
      PRESENCE_NEGATION.lastIndex = 0;
      let m: RegExpExecArray | null = PRESENCE_NEGATION.exec(sentence);
      while (m) {
        // The window bounds where the span STARTS, not where it ends — a
        // 24-character identifier must not be missed for being longer than the
        // window that is meant to sit in front of it.
        const at = m.index + m[0].length;
        const rest = sentence.slice(at);
        CODE_SPAN.lastIndex = 0;
        let span: RegExpExecArray | null = CODE_SPAN.exec(rest);
        while (span && span.index <= NEGATION_WINDOW) {
          const t = span[1]!.trim();
          if (isToken(t) && !tokens.includes(t)) tokens.push(t);
          span = CODE_SPAN.exec(rest);
        }
        m = PRESENCE_NEGATION.exec(sentence);
      }
      if (!tokens.length) continue;
      // Cite the line the token is ON, not the paragraph's first line — three
      // sentences of one paragraph all reporting the same line reads like a bug.
      let line = from;
      for (let i = from; i <= to; i++) {
        if (lines[i - 1]?.includes(tokens[0]!)) {
          line = i;
          break;
        }
      }
      claims.push({ sentence: sentence.trim(), line, tokens });
    }
    block = undefined;
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (!line.trim() || /^#{1,6}\s/.test(line)) {
      flush();
      continue;
    }
    if (block) {
      block.text += ` ${line.trim()}`;
      block.to = i + 1;
    } else block = { text: line.trim(), from: i + 1, to: i + 1 };
  }
  flush();

  return claims;
}

export interface ClaimCheckOptions {
  gitignore?: boolean;
  exclude?: string[];
  includeVendored?: boolean;
  /** Paths never counted as evidence against a claim. The run's own dossier is
   *  always excluded — a finding quoting the token is not the repo containing it. */
  maxFiles?: number;
}

/**
 * The claims the repository disagrees with.
 *
 * A literal search, on purpose. Anything cleverer would be reading the claim,
 * and reading the claim is the auditor's job — the value here is entirely in
 * putting the sentence and the `[file:line]` next to each other.
 */
export function contradictedClaims(repo: string, claims: readonly NegativeClaim[], opts: ClaimCheckOptions = {}): ContradictedClaim[] {
  const examined = claims.slice(0, MAX_CLAIMS);
  const wanted = new Map<string, ContradictedClaim>();
  for (const claim of examined) {
    for (const token of claim.tokens) {
      const key = `${claim.line}:${token}`;
      if (!wanted.has(key)) wanted.set(key, { claim, token, hits: [], total: 0 });
    }
  }
  if (!wanted.size) return [];

  const pruned = buildPruneMatcher(repo, { gitignore: opts.gitignore, exclude: opts.exclude, includeVendored: opts.includeVendored });
  for (const file of walk(repo, { gitignore: opts.gitignore, exclude: opts.exclude, maxFiles: opts.maxFiles })) {
    if (pruned?.(file.rel) || !isSearchable(file.rel)) continue;
    let text: string;
    try {
      text = readText(file.abs);
    } catch {
      continue;
    }
    if (!text) continue;
    let lines: string[] | undefined;
    for (const entry of wanted.values()) {
      if (!text.includes(entry.token)) continue;
      lines ??= text.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        if (!lines[i]!.includes(entry.token)) continue;
        entry.total++;
        if (entry.hits.length < MAX_HITS) entry.hits.push({ file: file.rel, line: i + 1 });
      }
    }
  }

  return [...wanted.values()].filter((e) => e.total > 0).sort((a, b) => a.claim.line - b.claim.line || byStr(a.token, b.token));
}

/** Claims beyond `MAX_CLAIMS`, so a truncated check never reads as a clean one. */
export function claimsNotExamined(claims: readonly NegativeClaim[]): number {
  return Math.max(0, claims.length - MAX_CLAIMS);
}

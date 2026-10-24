import type { Dossier } from "./store.js";
import type { Finding } from "./types.js";
import type { AttackSurface } from "./map.js";
import type { Graph } from "./graph.js";
import { neighbors } from "./neighbors.js";
import { makeToolFinding } from "./tools/normalize.js";
import { deploymentFacts, scoreFinding } from "./tools/scoring.js";
import { insideRepo, lineCount } from "./check.js";
import { byStr } from "./util.js";
import { redactSecrets } from "./redact.js";
import { leadsForRegion } from "./assumptions.js";
import {
  DISCOVERY_REQUIREMENT,
  coerceRows,
  parseDiscoveryRow,
  requireUsable,
  type DiscoveryRow,
  type DroppedRow,
  type NormalizedRow,
  type ParseResult,
} from "./apply-parse.js";
import type { ClassHunt } from "./classes/hunt.js";
import { isHuntOnlyPayload } from "./classes/hunt.js";

// The agentic-discovery stage (Phase 5). The deterministic engine can't enumerate
// authorization/IDOR, business-logic, or subtle multi-hop flows — so it emits a
// worklist organized by attack-surface REGION (entry/sink files + their 1-hop
// graph neighbours) and the agent investigates each region and returns grounded
// Discovery[]. The engine INGESTS them as `ultrasec-ai` candidates that flow
// through the same dossier → verify → check pipeline as any other finding. Two
// safety rails: a discovery duplicating an existing location folds into `sources`
// (not a new finding), and a citation that doesn't resolve is REJECTED up front —
// so `check` can never later fail on an AI-invented line.

const MAX_FILES_PER_REGION = 8;
const MAX_NEIGHBORS_PER_REGION = 12;
/** Attack-surface regions per worklist; past it the smallest are merged. The
 *  same ceiling as the fan-out's agents, so one region is never split. */
export const MAX_REGIONS = 12;
export const AI_TOOL = "ultrasec-ai";

export interface InvestigateRegion {
  region: string;
  score: number;
  sinks: number;
  sources: number;
  /** Representative entry/sink files in this region. */
  files: string[];
  /** 1-hop graph neighbours of those files (cross-file context). */
  neighbors: string[];
  /** What to hunt for here — the things the deterministic pass can't. */
  prompt: string;
  /**
   * Unenforced assumptions recorded by `assumptions` that fall in this region.
   * A place where the code trusts something nothing verifies is the best hunting
   * lead an audit produces — it names the gap instead of asking you to find it.
   * Absent unless that stage has run.
   */
  leads?: string[];
  /** The regions merged into this one when the worklist passed MAX_REGIONS —
   *  named, so a region folded away is never silently dropped. */
  merged?: string[];
  /**
   * Present on a weakness-class HUNT rather than an attack-surface region: a
   * class × framework cell no pack settles (src/classes/hunt.ts). Its `region`
   * is the hunt id, its files are where the framework lives.
   */
  hunt?: ClassHunt;
}

/**
 * Extra hunting frames the caller can request. A lens does not change what is
 * scanned — it changes the question asked of it, which is the only thing that
 * separates "no findings" from "no findings of the kind I was looking for".
 */
// Access control is the highest-yield class an audit finds and the one taint can
// never enumerate — the engine can point at the routes, only a human decides the
// policy. Kept as one string, shared by the `access-control` name and its `idor`
// alias, so the two can never drift.
const ACCESS_CONTROL_LENS =
  "Access control — the highest-yield class, never enumerable by taint. For every route/handler in these files ask two questions. (1) Is there ANY authorization check before the object is read or written? A missing one is BFLA (broken function-level authz) — the classic shape is an admin/privileged action reachable by a normal role, or a method/version downgrade (GET→PUT, /v2→/v1) that skips the guard. (2) Does the check bind the CALLER to the SPECIFIC object in the request? Compare the guard to the object returned: an owner_id/tenant_id taken from the SESSION/token vs. an id taken from the URL/body/query. When they are not compared, an attacker swaps the id and reads another principal's data — IDOR/BOLA. Hunt horizontal escalation (user A reaching user B via a predictable/sequential/enumerable id), vertical escalation (a normal user reaching an admin object), and tenant-boundary crossing in multi-tenant code. Mass-assignment onto role/isAdmin/tenant/permissions is access control too — a body field that overwrites who you are. Cite resolvable [file:line] for the guard that is missing or the comparison that is absent. See references/access-control.md.";

export const LENSES: Record<string, string> = {
  "sharp-edges":
    "Ask a DIFFERENT question here: not 'is this code vulnerable' but 'does this API make the insecure use easier than the secure one'. Six shapes: an algorithm/mode the caller picks; an insecure default or an ambiguous zero; raw bytes where a semantic type belongs; a config cliff that fails open; a verification that returns instead of throwing; permissions as strings. Model three users — the attacker, the copy-paster, the confused reader. Rate by how EASY the mistake is. See references/sharp-edges.md.",
  "access-control": ACCESS_CONTROL_LENS,
  idor: ACCESS_CONTROL_LENS,
  crypto:
    "Crypto-specific: secrets compared with == or equals() rather than a constant-time helper; key material in a plain buffer never zeroed; a nonce or IV reused or derived from a counter the attacker sees; an algorithm read from attacker-supplied data. See references/attack-classes.md §Cryptography.",
  privacy:
    "Personal data: where it goes (a third-party processor, a log, an analytics beacon), how long it stays, and whether a control named 'anonymisation' actually prevents re-identification. See references/privacy-and-data-protection.md.",
  cloud:
    "Cloud / container reachability, the half the IaC scan can't decide: can any user-controlled URL reach the instance-metadata endpoint (169.254.169.254 / metadata.google.internal) — SSRF to short-lived credentials? Is a wildcard/over-broad IAM role actually assumed on this path? Are instance/CI secrets read from env or a mounted file that a compromised container can exfiltrate? Does a container escape (privileged/hostPath/hostNetwork) turn a bug into node takeover? Beyond the scan: does the app authorize on cloud metadata, labels or namespaces a tenant can set? Is a presigned/signed URL scoped (method, key, expiry, content type)? Is an event source verified (signature, account, topic) before its envelope is trusted? Does credential renewal fall back to a broader identity? Does the edge enforce what the origin assumes? See references/frameworks.md §Cloud and references/supply-chain.md §IaC and cloud.",
  // The domain lenses: one per class of boundary taint never sees. Each string is
  // the reference's discipline condensed — pick one because the boundary EXISTS
  // in these files, not because a library name appears.
  native:
    "Native code, memory safety and privileged binaries. Follow every length, index and count from the input to the allocation and the access: signedness, truncation, unit confusion (bytes vs elements), off-by-one at the boundary. Track ownership across FFI, callbacks and error paths: use-after-free, double free, uninitialized reads, type confusion on a tagged union, refcount races. Check loader search order, signature-to-mapped-image gaps, and privileged dispatch (ioctl/syscall/XPC handlers) that copies user memory or trusts a caller-supplied size. A crash is not code execution: rate what you observed under a sanitizer, not what an exploit chain might reach. See references/memory-safety-and-native.md.",
  ai: "LLM, agent and tool surfaces. Prompt injection alone is not a finding: require a code-level boundary failure — attacker-written content (retrieved document, memory, tool or MCP response, tool description) reaching ANOTHER principal's context, invoking authority the requester lacks, reading data they cannot, or driving a sink they cannot reach directly. Treat model output and tool arguments as untrusted input to the handler: validate and authorize there. Check that the effective identity is the requester's, not a broad service credential; that irreversible actions are bound to an explicit approval of THAT action; that memory and caches are scoped per principal; that sub-agents inherit no more than they need; that loops and delegation are budgeted. A guardrail prompt is not a control. See references/ai-and-agents.md.",
  authn:
    "Authentication protocols, not authorization. Sessions: fixation, rotation on login and privilege change, invalidation on logout/password change, cookie Domain/Path scope against sibling subdomains. Tokens: JWT algorithm and key selection, audience/issuer/expiry, OAuth redirect_uri matching, state/PKCE, OIDC nonce, SAML signature wrapping and assertion binding. MFA: can a factor be enrolled or removed without step-up, can the flow be downgraded, is step-up bound to the action it protects? Passkeys: RP ID, origin and challenge checked server-side. Account linking by unverified email, recovery flows that bypass every factor, API keys used beyond their scope or publishable keys accepted as secret ones, mTLS identity read from a header the edge may not strip. See references/attack-classes.md (Authentication, JWT, MFA/passkeys, API keys/mTLS, HTTP framing).",
  browser:
    "Client-side and browser trust. Trace attacker-reachable values (URL fragment and query, postMessage data, storage, WebSocket frames, server-rendered JSON) into DOM sinks — innerHTML, script src, javascript: URLs, framework escape hatches. Check postMessage origin checks and target origins, cross-site WebSocket handshakes without an Origin check, credentialed CORS reflecting the origin, prototype-pollution sources with a reachable gadget, DOM clobbering of configuration globals, service-worker scope and cache keys, auth state surviving logout in storage or other tabs, window.opener and navigation to attacker URLs, framing of state-changing UI, and cross-site leaks through timing, errors or frame counts. Prove it in a local browser, never against a shared deployment. See references/client-side.md.",
  messaging:
    "Protocols, RPC, queues and streams. Ask whether every hop agrees on the message: canonicalization and duplicate-field handling, enum/union defaults on unknown values, envelope claims (tenant, user, type) trusted over the authenticated channel. Does every RPC method and streamed item pass the same interceptor/authz, or only the first? Is the peer's transport identity mapped to the principal acting? Can a producer write to a topic that acts as a control plane, or read a dead-letter queue full of other tenants' payloads? Check duplicate and out-of-order delivery, ack-before-commit, and correlation ids an attacker can collide. GraphQL and WebSocket: authorize per resolver and per message, not just at connect. See references/protocols-and-messaging.md.",
  dos: "Availability and resource exhaustion — the CHEAP-for-attacker, EXPENSIVE-for-service asymmetry, not volume. Look for superlinear work on attacker input (regex, nested parsing, sorting, similarity), decompression and expansion ratios, query amplification (unbounded pagination, N+1, GraphQL depth), unbounded buffers, maps keyed by attacker values, file-descriptor or connection leaks on error paths, work that keeps running after the client cancels, expensive work before authentication, quotas keyed or reset wrongly, one tenant starving a shared worker pool, a poison message that blocks a queue, and retry storms. One unauthenticated request that stops a shared service is high; an effect that needs sustained traffic is low. See references/availability-and-resource-exhaustion.md.",
  lifecycle:
    "Data isolation across the whole lifecycle, not just the request. For every derived copy — cache, search index, export, report, log, analytics, backup, replica — does the same tenant/object authorization apply as on the primary read? Check composite keys and cache keys that omit the tenant, row-level policy bypassed by an unscoped client, signed blob references that outlive or exceed the grant, aggregate endpoints that work as an oracle, imports and restores that accept another tenant's ids, migrations whose defaults widen access, soft-deleted rows still served, authorization copied into a derived record and never revoked, and retention that outlives deletion. See references/data-isolation-and-lifecycle.md.",
  "local-ipc":
    "Desktop, mobile and local IPC. Deep links and URL schemes: is the handler's input validated, and can a link trigger an action without the user's intent? Exported components, intents, XPC/D-Bus/Binder/named pipes/local sockets: is the PEER authenticated (code signature, UID, package), or only the claimed identity in the message? Webview bridges: which origins can reach the JS interface, can navigation leave the allow-list, is file access on? Privileged helpers and installers: do they trust paths, environment or a caller-writable directory? Local files: TOCTOU between check and use, world-readable secrets, credentials outside the platform keystore, data leaking across account switches. See references/desktop-mobile-and-ipc.md.",
  release:
    "Release, update and plugin integrity in the APPLICATION's own code. An updater: is metadata signed, fresh and monotonic (no rollback or freeze), is the downloaded artifact verified against a pinned identity before it runs? Signing: is a signature checked against the EXPECTED signer and digest, or merely present? Plugins and extensions: does loading one expand its trust beyond what was granted — filesystem, network, other plugins' data? Build and codegen: are generated sources, build contexts and cached artifacts produced from inputs a lower-trust party controls? The CI half of this lives in references/agentic-ci.md; the rest in references/supply-chain.md (Release, signing, update and plugin integrity).",
};

/** Build the investigation worklist, grouped by attack-surface region. */
export function buildInvestigateWorklist(
  surface: AttackSurface,
  graph: Graph,
  assumptionLeads: { at: string; claim: string }[] = [],
  lens?: string,
  classHunts: InvestigateRegion[] = [],
): InvestigateRegion[] {
  // `surface.byFile` is the FULL ranked set. The previous version read
  // `entryPoints[].samples` and `sinks[].samples` — each already capped at 8 per
  // kind — and then sorted the survivors alphabetically, so a region's file list
  // was a sample of a sample in name order. On a monorepo that put
  // `targets/alert-cli/**` in all 8 slots of the `targets` region and left
  // `targets/frontend/**`, the only internet-facing component, entirely out of
  // the worklist. Rank by attack surface, then cap.
  const filesByRegion = new Map<string, string[]>();
  for (const fs of surface.byFile) {
    const arr = filesByRegion.get(fs.region) ?? filesByRegion.set(fs.region, []).get(fs.region)!;
    if (arr.length < MAX_FILES_PER_REGION) arr.push(fs.file);
  }

  const regions: InvestigateRegion[] = [];
  for (const t of surface.suggestedTargets) {
    const files = [...(filesByRegion.get(t.scope) ?? [])];
    const nb = new Set<string>();
    for (const f of files) {
      if (!graph.files.includes(f)) continue;
      for (const l of neighbors(graph, f, 1).links) nb.add(l.node);
    }
    for (const f of files) nb.delete(f);
    const leads = leadsForRegion(assumptionLeads, t.scope, files);
    regions.push({
      region: t.scope,
      score: t.score,
      sinks: t.sinks,
      sources: t.sources,
      files,
      neighbors: [...nb].sort(byStr).slice(0, MAX_NEIGHBORS_PER_REGION),
      prompt:
        "What the deterministic pass can't see: missing/incorrect authorization & IDOR, " +
        "business-logic flaws, multi-hop taint that crosses these files, and personal-data " +
        "handling (data leaving to a third-party processor, a control narrower than its name, " +
        "reversible pseudonymisation, absent retention). Cite resolvable [file:line]." +
        (lens && LENSES[lens] ? `\n\nLENS — ${lens}: ${LENSES[lens]}` : ""),
      ...(leads.length ? { leads } : {}),
    });
  }
  // Weakness-class hunts come after the regions: same worklist, same ingest,
  // same orchestration ids — one more kind of item, not a second pipeline.
  return [...capRegions(regions), ...classHunts];
}

/**
 * At most MAX_REGIONS regions: the best-ranked first MAX_REGIONS − 1 as they
 * are, the rest merged into one — files taken round-robin from each so every
 * small region keeps a representative, neighbours and leads pooled, the merged
 * names listed. A monorepo with forty packages otherwise got forty regions and
 * forty agents, most of them reading one file.
 */
function capRegions(regions: InvestigateRegion[]): InvestigateRegion[] {
  if (regions.length <= MAX_REGIONS) return regions;
  const head = regions.slice(0, MAX_REGIONS - 1);
  const tail = regions.slice(MAX_REGIONS - 1);
  // At least one file per merged region: the round-robin's first pass takes
  // each one's best file, so no region is reduced to a name in `merged`.
  const cap = Math.max(MAX_FILES_PER_REGION, tail.length);
  const files: string[] = [];
  for (let i = 0; files.length < cap; i++) {
    let added = false;
    for (const r of tail) {
      const f = r.files[i];
      if (f !== undefined && files.length < cap && !files.includes(f)) {
        files.push(f);
        added = true;
      }
    }
    if (!added && tail.every((r) => r.files.length <= i)) break;
  }
  const nb = new Set(tail.flatMap((r) => r.neighbors));
  for (const f of files) nb.delete(f);
  const leads = tail.flatMap((r) => r.leads ?? []);
  const merged: InvestigateRegion = {
    region: `${tail[0]!.region} +${tail.length - 1} smaller`,
    score: tail.reduce((n, r) => n + r.score, 0),
    sinks: tail.reduce((n, r) => n + r.sinks, 0),
    sources: tail.reduce((n, r) => n + r.sources, 0),
    files,
    neighbors: [...nb].sort(byStr).slice(0, MAX_NEIGHBORS_PER_REGION),
    prompt: tail[0]!.prompt,
    ...(leads.length ? { leads } : {}),
    merged: tail.map((r) => r.region),
  };
  return [...head, merged];
}

/**
 * The worklist as written: the hunt prompt every region shares, ONCE, then the
 * regions without it. Nine regions repeated the same 322-character prompt on
 * a real run, and a hunter fan-out handed each agent every copy. A region (or
 * a weakness-class hunt) whose prompt differs keeps its own.
 */
export interface InvestigateTodo {
  prompt: string;
  regions: (Omit<InvestigateRegion, "prompt"> & { prompt?: string })[];
}

export function investigateTodo(items: readonly InvestigateRegion[]): InvestigateTodo {
  const counts = new Map<string, number>();
  for (const r of items) counts.set(r.prompt, (counts.get(r.prompt) ?? 0) + 1);
  let prompt = "";
  for (const [p, n] of counts) if (n > (counts.get(prompt) ?? 0)) prompt = p;
  return { prompt, regions: items.map(({ prompt: own, ...rest }) => (own === prompt ? rest : { ...rest, prompt: own })) };
}

/** Read an INVESTIGATE.todo.json body — the `{prompt, regions}` shape, or the
 *  plain array an older run wrote — back into regions that each carry their
 *  prompt. Anything else is no regions. */
export function readInvestigateTodo(raw: unknown): InvestigateRegion[] {
  if (Array.isArray(raw)) return raw as InvestigateRegion[];
  if (raw !== null && typeof raw === "object" && Array.isArray((raw as InvestigateTodo).regions)) {
    const t = raw as InvestigateTodo;
    return t.regions.map((r) => ({ ...r, prompt: r.prompt ?? t.prompt ?? "" }));
  }
  return [];
}

export function renderInvestigateMd(items: InvestigateRegion[], context?: string): string {
  const regions = items.filter((r) => !r.hunt);
  const hunts = items.filter((r) => r.hunt);
  const L: string[] = [];
  L.push(
    `# ultrasec investigation worklist (${regions.length} region${regions.length === 1 ? "" : "s"}${hunts.length ? ` · ${hunts.length} weakness-class hunt${hunts.length === 1 ? "" : "s"}` : ""})`,
  );
  L.push("");
  L.push(`Investigate each region for issues the deterministic engine can't enumerate, and emit`);
  L.push(`grounded **Discovery[]** as INVESTIGATE.json (array of`);
  L.push(`{title, category, severity, cwe?, message, file, line, path?}). Then:`);
  L.push(`\`ultrasec investigate --apply INVESTIGATE.json --run <run>\`.`);
  L.push("");
  L.push(`> Every discovery is ingested as an \`${AI_TOOL}\` **open** candidate and must be verified`);
  L.push(`> like any other. Citations are checked: a [file:line] that doesn't resolve is **rejected**.`);
  L.push(`> A discovery at an existing finding's location folds into its \`sources\` (no duplicate).`);
  L.push("");
  if (context) {
    L.push(`## Project context`);
    L.push(`_From \`CONTEXT.md\`._`);
    L.push("");
    L.push(context);
    L.push("");
  }
  for (const r of regions) {
    L.push(`## \`${r.region}\` — ${r.sinks} sink(s), ${r.sources} entry point(s)`);
    if (r.files.length) L.push(`- files: ${r.files.map((f) => `\`${f}\``).join(", ")}`);
    if (r.neighbors.length) L.push(`- neighbours: ${r.neighbors.map((f) => `\`${f}\``).join(", ")}`);
    L.push(`- hunt: ${r.prompt}`);
    if (r.leads?.length) {
      L.push(`- **trusted but never enforced here** (from \`assumptions\`) — start with these:`);
      for (const l of r.leads) L.push(`  - ${l}`);
    }
    L.push("");
  }
  if (hunts.length) L.push(...renderHuntsMd(hunts));
  return L.join("\n") + "\n";
}

/** The weakness-class hunts: what no pack covers, and how to hand back what you find. */
function renderHuntsMd(hunts: InvestigateRegion[]): string[] {
  const L: string[] = [];
  L.push(`## Weakness-class hunts`);
  L.push("");
  L.push(`Each hunt is a weakness class on a framework no pack settles (no pack for it, or a version`);
  L.push(`outside the range the pack was validated on). Find how THIS repository writes the class and`);
  L.push(`return, in the same INVESTIGATE.json — \`{ "discoveries": [...], "idioms": [...], "hunted": [...] }\`:`);
  L.push(`- **discoveries** — every place the invariant breaks, with \`"hunt": "<hunt id>"\` (ingested like any discovery);`);
  L.push(`- **idioms** — each unsafe call and each guard you recognized: \`{hunt, class, framework, kind: "unsafe"|"guard", pattern,`);
  L.push(`  regex?, file, line, note}\`, citation checked, written to \`PACK-SUGGESTIONS.json\` (proposals — never applied);`);
  L.push(`- **hunted** — the hunt ids you worked, including those where you found nothing.`);
  L.push("");
  for (const r of hunts) {
    const h = r.hunt!;
    L.push(`### \`${h.id}\` — ${h.title} (${h.cwe}) on ${h.framework}${h.version ? ` ${h.version}` : ""}${h.dir ? ` in \`${h.dir}\`` : ""}`);
    L.push(`- why: ${h.reason}${h.packsApplied.length ? ` (rules already run as a floor: ${h.packsApplied.join(", ")})` : ""}`);
    L.push(`- invariant: ${h.invariant}`);
    L.push(`- a valid guard: ${h.guard}`);
    L.push(`- severity: ${h.rubric}`);
    if (r.files.length) L.push(`- start in: ${r.files.map((f) => `\`${f}\``).join(", ")}`);
    for (const e of h.examples) {
      L.push(`- example (${e.language}) — vulnerable: \`${e.vulnerable.replace(/\n/g, " ⏎ ")}\``);
      L.push(`  fixed: \`${e.fixed.replace(/\n/g, " ⏎ ")}\``);
    }
    L.push("");
  }
  return L;
}

/**
 * One agent-authored finding.
 *
 * Defined in `apply-parse.ts` beside the validator that enforces it, and
 * re-exported here because this is the stage that named it. `variants.ts`
 * imports it from here and gets the same shape — and, now, the same validation.
 */
export type Discovery = DiscoveryRow;

export interface IngestResult {
  findings: Finding[];
  ingested: number;
  folded: number;
  rejected: { discovery: Discovery; reason: string }[];
}

function locOf(f: Finding): string {
  if (f.sink) return `${f.sink.file}:${f.sink.line}`;
  const last = f.path?.[f.path.length - 1];
  if (last) return `${last.file}:${last.line}`;
  if (f.source) return `${f.source.file}:${f.source.line}`;
  return "";
}

/**
 * `ident` is tolerated as possibly-absent on purpose. Every caller now passes a
 * validated row, but this function is one `??` away from a crash that took a
 * whole audit's report down once already (`variants --apply` handed it a row
 * with neither `cwe` nor `title`). A dedup key derived from an empty ident is a
 * worse key; it is not a stack trace.
 */
function dedupKey(category: string, ident: string | undefined, where: string): string {
  return `${category}::${(ident ?? "").trim().toLowerCase()}::${where}`;
}

/** Reject a discovery whose primary or any path citation doesn't resolve in the
 *  repo — the SAME check the grounding gate applies, so `check` can't fail later.
 *  Exported for the class hunt's idioms, which are held to the same bar. */
export function citationProblem(repo: string, d: Pick<Discovery, "file" | "line" | "path">): string | null {
  const locs = [{ file: d.file, line: d.line }, ...(d.path ?? []).map((p) => ({ file: p.file, line: p.line }))];
  for (const loc of locs) {
    if (!insideRepo(repo, loc.file)) return `citation outside repo: ${loc.file}`;
    const lc = lineCount(repo, loc.file);
    if (lc === null) return `file not found: ${loc.file}`;
    if (loc.line < 1 || loc.line > lc) return `line out of range: ${loc.file}:${loc.line} (file has ${lc} lines)`;
  }
  return null;
}

/**
 * Ingest agent discoveries as `ultrasec-ai` open candidates. Dedups against the
 * existing dossier by (category, cwe|title, file:line): a match folds `ultrasec-ai`
 * into that finding's `sources` instead of adding a duplicate. Out-of-range
 * citations are rejected before folding. Stable, content-derived ids.
 *
 * `opts.context` is the run's CONTEXT.md, and it is what makes an ingested
 * finding RANKABLE. Every renderer sorts on `risk`, `makeToolFinding` does not
 * set one, and nothing scored these findings afterwards — so agent discoveries
 * sorted below every scanner hit in the run, including the ones that had already
 * been refuted. They now get the same `severity ⊕ exposure ⊕ criticality` score
 * the scan gives everything else. Omitting the context is still valid: the score
 * then falls back to severity alone, which is what a run with no CONTEXT.md gets.
 */
export function ingestDiscoveries(dossier: Dossier, discoveries: Discovery[], repo: string, opts: { context?: string } = {}): IngestResult {
  const deployment = deploymentFacts(opts.context);
  const result = new Map<string, Finding>();
  const idByKey = new Map<string, string>();
  for (const f of dossier.findings) {
    result.set(f.id, f);
    idByKey.set(dedupKey(f.category, f.cwe ?? f.title, locOf(f)), f.id);
  }

  let ingested = 0,
    folded = 0;
  const rejected: IngestResult["rejected"] = [];

  for (const d of discoveries) {
    const problem = citationProblem(repo, d);
    if (problem) {
      rejected.push({ discovery: d, reason: problem });
      continue;
    }
    const key = dedupKey(d.category, d.cwe ?? d.title, `${d.file}:${d.line}`);
    const existingId = idByKey.get(key);
    if (existingId) {
      const prev = result.get(existingId)!;
      const sources = [...new Set([...(prev.sources ?? [prev.tool]), AI_TOOL])].sort(byStr);
      result.set(existingId, { ...prev, sources });
      folded++;
      continue;
    }
    const f = makeToolFinding({
      tool: AI_TOOL,
      category: d.category,
      ident: `${d.category}:${d.title}:${d.file}:${d.line}`,
      title: d.title,
      severity: d.severity,
      // The hunter's own write-up, quoting what it found; a hard-coded key is
      // reported by quoting it. Same mask as every other authored note.
      message: redactSecrets(d.message),
      file: d.file,
      line: d.line,
      cwe: d.cwe,
      confidence: "low", // AI-discovered + unverified — recall-oriented, adjudicate it
    });
    if (d.path?.length) f.path = d.path.map((p) => ({ file: p.file, line: p.line, why: redactSecrets(p.why) }));
    // Keep the class the author named. `category` had to be folded to stay a
    // closed vocabulary; the fold should not also erase the answer.
    if (d.vulnClass) f.vulnClass = d.vulnClass;
    f.risk = scoreFinding(f, deployment);
    result.set(f.id, f);
    idByKey.set(key, f.id);
    ingested++;
  }

  const findings = [...result.values()].sort((a, b) => byStr(a.id, b.id));
  return { findings, ingested, folded, rejected };
}

/**
 * Parse an INVESTIGATE.json body into validated Discovery[]. Row-tolerant (drops
 * entries missing required fields or with an unknown category/severity) but
 * FAIL-CLOSED on the container: an unrecognized shape, or rows that ALL get
 * dropped, throws instead of silently ingesting nothing. An empty
 * {discoveries:[]} stays valid — a hunter finding nothing is a real outcome.
 */
export function parseDiscoveries(raw: string): ParseResult<Discovery> {
  const data = JSON.parse(raw) as unknown;
  // A payload carrying only weakness-class hunt results (`idioms`/`hunted`)
  // is a valid apply with no discovery in it.
  const arr = isHuntOnlyPayload(data) ? [] : coerceRows(data, ["discoveries"], "discoveries");
  const rows: Discovery[] = [];
  const dropped: DroppedRow[] = [];
  const normalized: NormalizedRow[] = [];
  const drop = (index: number, reason: string) => dropped.push({ index, reason });

  for (const [index, raw] of arr.entries()) {
    const parsed = parseDiscoveryRow(raw);
    if (!parsed.row) {
      drop(index, parsed.reason!);
      continue;
    }
    if (parsed.note) normalized.push({ index, note: parsed.note });
    rows.push(parsed.row);
  }

  return requireUsable(
    // Presence-gated: no fold ⇒ the result is shape-identical to before.
    { rows, dropped, ...(normalized.length ? { normalized } : {}) },
    arr.length,
    DISCOVERY_REQUIREMENT,
  );
}

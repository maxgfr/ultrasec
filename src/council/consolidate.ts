import type { Finding, Severity } from "../types.js";
import { SEVERITIES } from "../types.js";
import { byStr, shortHash } from "../util.js";
import type { Phase } from "./brief.js";
import type { Citation, Claim, ClaimSection } from "./claims.js";

// Grouping what several reviewers said into candidates for ONE orchestrator to
// verify.
//
// Two reviewers citing the same lines for the same kind of bug are one
// candidate with two sources. That count is a PRIOR — it orders the
// orchestrator's reading, it never decides anything. On the audit this came
// from, the run's only HIGH nobody else had seen was raised by a single
// reviewer, and two of the four false claims were made by two models at once.
//
// A candidate that lands on a finding the run already holds is not a new
// candidate: it is reported against that finding's id, as corroboration.

/** CWE → family, so "CWE-89" and "CWE-943" at the same line are one claim. */
const FAMILIES: Record<string, readonly number[]> = {
  injection: [74, 77, 78, 88, 89, 90, 91, 94, 95, 96, 564, 643, 652, 917, 943, 1336],
  xss: [79, 80, 83, 87, 116],
  path: [22, 23, 35, 36, 59, 73],
  ssrf: [918],
  "access-control": [269, 284, 285, 287, 288, 290, 306, 425, 566, 602, 639, 862, 863, 1220],
  crypto: [261, 310, 311, 319, 326, 327, 328, 329, 330, 331, 338, 347, 757, 759, 760, 916],
  exposure: [200, 201, 209, 259, 312, 313, 315, 321, 359, 497, 522, 532, 538, 798],
  redirect: [601],
  deserialization: [502],
  dos: [400, 405, 407, 674, 770, 834, 1333],
  csrf: [352],
  config: [16, 346, 524, 525, 614, 693, 942, 1004, 1021],
  upload: [434],
  xxe: [611, 776],
  race: [362, 367],
  "mass-assignment": [915],
  "auth-throttle": [204, 307],
};
const FAMILY_OF = new Map<number, string>(Object.entries(FAMILIES).flatMap(([fam, ids]) => ids.map((id) => [id, fam] as const)));

export function cweFamily(cwe: string | undefined): string {
  const n = Number(cwe?.match(/(\d+)/)?.[1]);
  if (!Number.isFinite(n) || !cwe) return "unknown";
  return FAMILY_OF.get(n) ?? `cwe-${n}`;
}

/** The category a family files under in the closed vocabulary (types.ts). */
export function familyCategory(family: string): "taint" | "authz" | "crypto" | "secret" | "config" | "other" {
  if (["injection", "xss", "path", "ssrf", "redirect", "deserialization", "xxe", "upload"].includes(family)) return "taint";
  if (["access-control", "csrf", "mass-assignment"].includes(family)) return "authz";
  if (family === "crypto") return "crypto";
  if (family === "exposure") return "secret";
  if (family === "config") return "config";
  return "other";
}

/** The ±3-line window two citations must share to be about the same code. */
export const WINDOW = 3;

interface Loc {
  file: string;
  line: number;
  endLine?: number;
}

function overlaps(a: Loc, b: Loc): boolean {
  return a.file === b.file && a.line - WINDOW <= (b.endLine ?? b.line) && b.line - WINDOW <= (a.endLine ?? a.line);
}

const okCites = (c: Claim): Citation[] => c.citations.filter((x) => x.citation === "ok");

export interface ClaimRef {
  reviewer: string;
  phase: Phase;
  section: ClaimSection;
  ref: string;
  title: string;
  severity?: Severity;
}

export interface Candidate {
  id: string;
  title: string;
  severity?: Severity;
  cwe?: string;
  family: string;
  /** Reviewers that raised it, sorted. */
  sources: string[];
  /** `sources.length` — a prior for reading order, never a verdict. */
  corroboration: number;
  claims: ClaimRef[];
  /** `at` is the resolved `path:line`; `raw` is how the reviewer wrote it, when that differs. */
  citations: { at: string; raw?: string; citation: Citation["citation"]; reason?: string }[];
  primary?: Loc;
  scenario?: string;
  fix?: string;
  excerpt: string;
  /** What the orchestrator must know before reading it. */
  flags: string[];
  cves?: string[];
  decision: null;
  reason: string;
}

export interface Corroboration {
  findingId: string;
  title: string;
  status: string;
  sources: string[];
  claims: ClaimRef[];
  via: "location" | "cve";
}

export interface Contest {
  id: string;
  /** Whether the contested id names a run finding, a council candidate, or nothing we hold. */
  known: "finding" | "candidate" | "unknown";
  reviewer: string;
  claim: string;
  proof: string;
  citations: { at: string; citation: Citation["citation"]; reason?: string }[];
}

export interface CouncilTodo {
  schema: 1;
  commit: string;
  candidates: Candidate[];
  corroborations: Corroboration[];
  contested: Contest[];
}

const sevRank = (s: Severity | undefined): number => (s ? SEVERITIES.indexOf(s) : SEVERITIES.length);
const at = (c: Loc): string => `${c.file}:${c.line}${c.endLine ? `-${c.endLine}` : ""}`;
const refOf = (c: Claim): ClaimRef => ({
  reviewer: c.reviewer,
  phase: c.phase,
  section: c.section,
  ref: c.ref,
  title: c.title,
  ...(c.severity ? { severity: c.severity } : {}),
});

/** Every location a finding cites, as file/line. */
function findingLocs(f: Finding): Loc[] {
  return [f.source, ...(f.path ?? []), f.sink, ...(f.locations ?? [])]
    .filter((l): l is { file: string; line: number } => !!l?.file && typeof l.line === "number" && l.line > 0)
    .map((l) => ({ file: l.file, line: l.line }));
}

/** Union-find over claims: same family + an overlapping cited window. */
function group(claims: Claim[]): Claim[][] {
  const parent = claims.map((_, i) => i);
  const find = (i: number): number => (parent[i] === i ? i : (parent[i] = find(parent[i]!)));
  const fam = claims.map((c) => cweFamily(c.cwe));
  for (let i = 0; i < claims.length; i++) {
    for (let j = i + 1; j < claims.length; j++) {
      if (fam[i] !== fam[j]) continue;
      if (okCites(claims[i]!).some((a) => okCites(claims[j]!).some((b) => overlaps(a, b)))) parent[find(i)] = find(j);
    }
  }
  const groups = new Map<number, Claim[]>();
  claims.forEach((c, i) => {
    const r = find(i);
    (groups.get(r) ?? groups.set(r, []).get(r)!).push(c);
  });
  return [...groups.values()];
}

const claimOrder = (a: Claim, b: Claim): number => byStr(a.reviewer, b.reviewer) || byStr(a.phase, b.phase) || byStr(a.ref, b.ref) || byStr(a.title, b.title);

function toCandidate(members: Claim[]): Candidate {
  const claims = [...members].sort(claimOrder);
  const first = claims[0]!;
  const family = cweFamily(first.cwe);
  const cites = new Map<string, Candidate["citations"][number]>();
  for (const c of claims) {
    for (const x of c.citations) {
      const key = x.citation === "ok" ? at(x) : x.raw;
      if (!cites.has(key))
        cites.set(key, { at: key, ...(x.raw !== key ? { raw: x.raw } : {}), citation: x.citation, ...(x.reason ? { reason: x.reason } : {}) });
    }
  }
  const p = claims.map((c) => okCites(c)[0]).find(Boolean);
  const primary = p ? { file: p.file, line: p.line, ...(p.endLine ? { endLine: p.endLine } : {}) } : undefined;
  const severity = claims.map((c) => c.severity).sort((a, b) => sevRank(a) - sevRank(b))[0];
  const sources = [...new Set(claims.map((c) => c.reviewer))].sort(byStr);
  const flags = new Set<string>();
  for (const c of claims) {
    for (const a of c.artefacts) flags.add(`mentions the masking placeholder ${a} — an artefact of how the code was shown, not a fact about it`);
    for (const v of c.verify) flags.add(v);
  }
  if (!primary) flags.add("no resolvable citation — give file/line in the decision, or reject");
  const severities = new Set(claims.map((c) => c.severity).filter(Boolean));
  if (severities.size > 1) flags.add(`reviewers disagree on severity (${[...severities].join(" / ")}) — recalibrate against CONTEXT.md`);
  const cves = [...new Set(claims.flatMap((c) => c.cves))].sort(byStr);
  const id = `C-${shortHash(primary ? `${family}:${primary.file}:${primary.line}` : claims.map((c) => `${c.reviewer}:${c.phase}:${c.ref}:${c.title}`).join("|"), 10)}`;
  return {
    id,
    title: first.title,
    ...(severity ? { severity } : {}),
    ...(first.cwe ? { cwe: first.cwe } : {}),
    family,
    sources,
    corroboration: sources.length,
    claims: claims.map(refOf),
    citations: [...cites.values()],
    ...(primary ? { primary } : {}),
    ...(first.scenario ? { scenario: first.scenario } : {}),
    ...(first.fix ? { fix: first.fix } : {}),
    excerpt: first.excerpt,
    flags: [...flags].sort(byStr),
    ...(cves.length ? { cves } : {}),
    decision: null,
    reason: "",
  };
}

/** The run finding this candidate lands on, if any: an overlapping location of the same family, or the same CVE. */
function existingFor(c: Candidate, findings: readonly Finding[]): { f: Finding; via: Corroboration["via"] } | undefined {
  if (c.cves?.length) {
    const hit = findings.find((f) => (f.cve && c.cves!.includes(f.cve.toUpperCase())) || (f.aliases ?? []).some((a) => c.cves!.includes(a.toUpperCase())));
    if (hit) return { f: hit, via: "cve" };
  }
  const locs = c.citations
    .filter((x) => x.citation === "ok")
    .map((x) => {
      const m = x.at.match(/^(.*):(\d+)(?:-(\d+))?$/)!;
      return { file: m[1]!, line: Number(m[2]), ...(m[3] ? { endLine: Number(m[3]) } : {}) };
    });
  let best: { f: Finding; d: number } | undefined;
  for (const f of findings) {
    if (cweFamily(f.cwe) !== c.family) continue;
    for (const fl of findingLocs(f)) {
      for (const l of locs) {
        if (!overlaps(l, fl)) continue;
        const d = Math.abs(l.line - fl.line);
        if (!best || d < best.d || (d === best.d && f.id < best.f.id)) best = { f, d };
      }
    }
  }
  return best ? { f: best.f, via: "location" } : undefined;
}

/**
 * Consolidate every reviewer's claims against the run's findings. Pure: the
 * same claims and findings always give the same todo, ids included.
 */
export function consolidate(claims: readonly Claim[], findings: readonly Finding[], commit: string): CouncilTodo {
  const proposals = claims.filter((c) => c.section !== "contest");
  const candidates: Candidate[] = [];
  const corroborations = new Map<string, Corroboration>();
  for (const members of group([...proposals])) {
    const cand = toCandidate(members);
    const hit = existingFor(cand, findings);
    if (!hit) {
      candidates.push(cand);
      continue;
    }
    const prev = corroborations.get(hit.f.id);
    const sources = [...new Set([...(prev?.sources ?? []), ...cand.sources])].sort(byStr);
    corroborations.set(hit.f.id, {
      findingId: hit.f.id,
      title: hit.f.title,
      status: hit.f.status,
      sources,
      claims: [...(prev?.claims ?? []), ...cand.claims],
      via: prev?.via ?? hit.via,
    });
  }
  candidates.sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || b.corroboration - a.corroboration || byStr(a.id, b.id));

  const findingIds = findings.map((f) => f.id);
  const candIds = new Set(candidates.map((c) => c.id));
  const contested: Contest[] = claims
    .filter((c) => c.section === "contest")
    .map((c) => {
      const raw = c.ref.replace(/[`*]/g, "").trim();
      const prefixHits = raw.length >= 6 ? findingIds.filter((id) => id.startsWith(raw)) : [];
      const id = findingIds.includes(raw) ? raw : prefixHits.length === 1 ? prefixHits[0]! : raw;
      const known: Contest["known"] = findingIds.includes(id) ? "finding" : candIds.has(id) ? "candidate" : "unknown";
      return {
        id,
        known,
        reviewer: c.reviewer,
        claim: c.title,
        proof: c.excerpt,
        citations: c.citations.map((x) => ({ at: x.citation === "ok" ? at(x) : x.raw, citation: x.citation, ...(x.reason ? { reason: x.reason } : {}) })),
      };
    })
    .sort((a, b) => byStr(a.id, b.id) || byStr(a.reviewer, b.reviewer));

  return {
    schema: 1,
    commit,
    candidates,
    corroborations: [...corroborations.values()].sort((a, b) => byStr(a.findingId, b.findingId)),
    contested,
  };
}

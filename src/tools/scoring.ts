import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { homedir } from "node:os";
import { join } from "node:path";
import { SEVERITIES, type Finding, type Severity } from "../types.js";

// Deterministic vulnerability-prioritization layer. ultrasec's scanners answer
// "is this CVE present?"; they do not answer "how urgent is it?". This folds two
// free, offline-cacheable signals onto every CVE-bearing finding:
//   • EPSS  — FIRST.org's exploitation-probability in the next 30 days (0–1).
//   • KEV   — CISA's Known-Exploited-Vulnerabilities catalog (exploited in the
//             wild → top tier, no debate).
// and derives a composite `risk` 0–100 used as the report's primary sort key.
//
// The math is 100% offline; only refreshing the feeds touches the network, and
// that is best-effort (a stale or missing cache degrades gracefully — risk still
// computes from severity alone). Nothing here needs an API key.

// ── Pure scoring ─────────────────────────────────────────────────────────────

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 1.0,
  high: 0.8,
  medium: 0.5,
  low: 0.25,
  info: 0.1,
};

/**
 * Deployment facts the score cannot infer from the code, read from `CONTEXT.md`
 * when the auditor wrote them.
 *
 * Two findings with identical CVSS and EPSS are not equally urgent: one is on an
 * internet-facing payment service, the other in a build-time dev dependency. The
 * technical severity is the same and the decision is not. Only the auditor knows
 * which is which, which is why this arrives as evidence rather than a guess.
 */
export const EXPOSURES = ["internet-facing", "internal", "build-time"] as const;
export type Exposure = (typeof EXPOSURES)[number];
const EXPOSURE_WEIGHT: Record<Exposure, number> = { "internet-facing": 1.0, internal: 0.6, "build-time": 0.3 };

export const CRITICALITIES = ["crown-jewel", "standard", "peripheral"] as const;
export type Criticality = (typeof CRITICALITIES)[number];
const CRITICALITY_WEIGHT: Record<Criticality, number> = { "crown-jewel": 1.0, standard: 0.6, peripheral: 0.3 };

export interface RiskInput {
  severity: Severity;
  epss?: number; // [0,1]
  kev?: boolean;
  exposure?: Exposure;
  criticality?: Criticality;
}

/**
 * Composite risk 0–100. Blends severity (60%) with EPSS exploit-likelihood
 * (40%); a KEV hit floors the score at 95 so in-the-wild-exploited issues always
 * surface first. Severity-only findings still get a stable, sensible score.
 *
 * When the auditor recorded exposure and/or asset criticality in `CONTEXT.md`,
 * they re-weight the blend: severity 40% · EPSS 25% · exposure 20% · criticality
 * 15%. WITHOUT them the arithmetic is bit-identical to before they existed —
 * every stored score, every calibration test and every report ordering is
 * unchanged on a run with no CONTEXT.md, which is the only way to add a factor
 * to a ranking people already trust.
 */
export function riskScore({ severity, epss, kev, exposure, criticality }: RiskInput): number {
  const e = Math.min(Math.max(epss ?? 0, 0), 1);
  const sev = SEVERITY_WEIGHT[severity];
  let base: number;
  if (exposure === undefined && criticality === undefined) {
    base = 0.6 * sev + 0.4 * e;
  } else {
    // A missing half stays neutral at its own mid-weight rather than at zero:
    // recording only one of the two must not silently demote everything.
    const x = exposure ? EXPOSURE_WEIGHT[exposure] : 0.6;
    const c = criticality ? CRITICALITY_WEIGHT[criticality] : 0.6;
    base = 0.4 * sev + 0.25 * e + 0.2 * x + 0.15 * c;
  }
  let score = Math.round(100 * base);
  if (kev) score = Math.max(score, 95);
  return Math.min(Math.max(score, 0), 100);
}

/** Read `Exposure:` / `Criticality:` out of the agent-authored CONTEXT.md. */
export function deploymentFacts(context?: string): { exposure?: Exposure; criticality?: Criticality } {
  if (!context) return {};
  const ex = /^\s*(?:[-*]\s*)?(?:\*\*)?Exposure(?:\*\*)?\s*:\s*`?([a-z-]+)`?/im.exec(context);
  const cr = /^\s*(?:[-*]\s*)?(?:\*\*)?Criticality(?:\*\*)?\s*:\s*`?([a-z-]+)`?/im.exec(context);
  const exposure = (EXPOSURES as readonly string[]).includes(ex?.[1] ?? "") ? (ex![1] as Exposure) : undefined;
  const criticality = (CRITICALITIES as readonly string[]).includes(cr?.[1] ?? "") ? (cr![1] as Criticality) : undefined;
  return { ...(exposure ? { exposure } : {}), ...(criticality ? { criticality } : {}) };
}

// ── Feed parsing (pure) ──────────────────────────────────────────────────────

export interface EpssEntry {
  epss: number;
  percentile?: number;
}
export interface Feeds {
  epss: Map<string, EpssEntry>;
  /** cve → KEV dateAdded (ISO). Presence in the map ⇒ in KEV. */
  kev: Map<string, string | undefined>;
}

/** Parse FIRST.org EPSS CSV ("#comment\ncve,epss,percentile\nCVE-…,0.004,0.7"). */
export function parseEpssCsv(csv: string): Map<string, EpssEntry> {
  const out = new Map<string, EpssEntry>();
  for (const line of csv.split("\n")) {
    const row = line.trim();
    if (!row || row.startsWith("#")) continue;
    const [cve, epss, pct] = row.split(",");
    if (!cve || !/^CVE-/i.test(cve)) continue; // skips the header row too
    const e = Number(epss);
    if (Number.isNaN(e)) continue;
    out.set(cve.toUpperCase(), { epss: e, percentile: pct !== undefined ? Number(pct) : undefined });
  }
  return out;
}

/** Parse CISA KEV JSON ({ vulnerabilities: [{ cveID, dateAdded }] }). */
export function parseKev(json: string): Map<string, string | undefined> {
  const out = new Map<string, string | undefined>();
  let data: any;
  try {
    data = JSON.parse(json || "{}");
  } catch {
    return out;
  }
  for (const v of data?.vulnerabilities ?? []) {
    if (v?.cveID) out.set(String(v.cveID).toUpperCase(), v.dateAdded);
  }
  return out;
}

// ── Apply (pure) ─────────────────────────────────────────────────────────────

/**
 * Attach epss/kev/kevDateAdded (for CVE-bearing findings) and a `risk` score (for
 * every finding) from already-loaded feeds. Returns new finding objects.
 */
export function applyEnrichment(findings: Finding[], feeds: Feeds, deployment: { exposure?: Exposure; criticality?: Criticality } = {}): Finding[] {
  return findings.map((f) => {
    const out: Finding = { ...f };
    const cve = f.cve?.toUpperCase();
    if (cve) {
      const e = feeds.epss.get(cve);
      if (e) out.epss = e.epss;
      if (feeds.kev.has(cve)) {
        out.kev = true;
        const d = feeds.kev.get(cve);
        if (d) out.kevDateAdded = d;
      }
    }
    out.risk = riskScore({ severity: out.severity, epss: out.epss, kev: out.kev, ...deployment });
    return out;
  });
}

// ── Feed loading (network + cache; best-effort) ──────────────────────────────

const EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const TTL_MS = 24 * 60 * 60 * 1000; // refresh feeds at most once a day
const FETCH_TIMEOUT_MS = 20_000;

export function cacheDir(): string {
  return process.env.ULTRASEC_CACHE_DIR || join(homedir(), ".cache", "ultrasec");
}

function fresh(path: string): boolean {
  try {
    return existsSync(path) && Date.now() - statSync(path).mtimeMs < TTL_MS;
  } catch {
    return false;
  }
}

async function fetchBuf(url: string): Promise<Buffer> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: ctrl.signal, redirect: "follow" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return Buffer.from(await res.arrayBuffer());
  } finally {
    clearTimeout(t);
  }
}

/**
 * Refresh one cached feed if stale, returning its text. Network failures fall
 * back to a stale cache, then to "" — never throw. `gz` gunzips the payload.
 */
async function loadCached(url: string, file: string, gz: boolean): Promise<string> {
  const dir = cacheDir();
  const path = join(dir, file);
  if (fresh(path)) {
    try {
      return readFileSync(path, "utf8");
    } catch {
      /* fall through to refetch */
    }
  }
  try {
    const buf = await fetchBuf(url);
    const text = (gz ? gunzipSync(buf) : buf).toString("utf8");
    try {
      mkdirSync(dir, { recursive: true });
      writeFileSync(path, text);
    } catch {
      /* cache write is best-effort */
    }
    return text;
  } catch {
    try {
      if (existsSync(path)) return readFileSync(path, "utf8"); // stale is better than nothing
    } catch {
      /* ignore */
    }
    return "";
  }
}

export async function loadFeeds(): Promise<Feeds> {
  const [epssCsv, kevJson] = await Promise.all([loadCached(EPSS_URL, "epss.csv", true), loadCached(KEV_URL, "kev.json", false)]);
  return { epss: parseEpssCsv(epssCsv), kev: parseKev(kevJson) };
}

export interface EnrichResult {
  findings: Finding[];
  note: string;
}

/**
 * Load EPSS + KEV (cached, network-tolerant) and enrich the findings. If a CVE
 * appears in either feed it is scored; risk is always computed. `enabled:false`
 * skips the feeds entirely but still derives risk from severity (deterministic,
 * offline). Never throws.
 */
export async function enrichFindings(findings: Finding[], opts: { enabled?: boolean; context?: string } = {}): Promise<EnrichResult> {
  const deployment = deploymentFacts(opts.context);
  if (opts.enabled === false) {
    return {
      findings: applyEnrichment(findings, { epss: new Map(), kev: new Map() }, deployment),
      note: `risk: severity-only (enrichment off)${deploymentNote(deployment)}`,
    };
  }
  let feeds: Feeds;
  try {
    feeds = await loadFeeds();
  } catch {
    feeds = { epss: new Map(), kev: new Map() };
  }
  const enriched = applyEnrichment(findings, feeds, deployment);
  const withCve = enriched.filter((f) => f.cve);
  const kevHits = enriched.filter((f) => f.kev).length;
  const note =
    feeds.epss.size || feeds.kev.size
      ? `risk: EPSS ${feeds.epss.size} CVEs · KEV ${feeds.kev.size} · ${withCve.length} finding(s) with CVE${kevHits ? ` · ${kevHits} in KEV` : ""}`
      : "risk: severity-only (feeds unavailable offline)";
  return { findings: enriched, note: note + deploymentNote(deployment) };
}

/** Say when deployment facts changed the ranking — a silent re-weighting of a
 *  score people already read would be indistinguishable from a bug. */
function deploymentNote(d: { exposure?: Exposure; criticality?: Criticality }): string {
  const parts = [d.exposure && `exposure ${d.exposure}`, d.criticality && `criticality ${d.criticality}`].filter(Boolean);
  return parts.length ? ` · weighted by CONTEXT.md (${parts.join(", ")})` : "";
}

// Severity ranking helper re-exported for renderers that sort by risk then sev.
export function sevRank(s: Severity): number {
  return SEVERITIES.indexOf(s);
}

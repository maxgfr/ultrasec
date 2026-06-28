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

export interface RiskInput {
  severity: Severity;
  epss?: number; // [0,1]
  kev?: boolean;
}

/**
 * Composite risk 0–100. Blends severity (60%) with EPSS exploit-likelihood
 * (40%); a KEV hit floors the score at 95 so in-the-wild-exploited issues always
 * surface first. Severity-only findings still get a stable, sensible score.
 */
export function riskScore({ severity, epss, kev }: RiskInput): number {
  const base = 0.6 * SEVERITY_WEIGHT[severity] + 0.4 * Math.min(Math.max(epss ?? 0, 0), 1);
  let score = Math.round(100 * base);
  if (kev) score = Math.max(score, 95);
  return Math.min(Math.max(score, 0), 100);
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
export function applyEnrichment(findings: Finding[], feeds: Feeds): Finding[] {
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
    out.risk = riskScore({ severity: out.severity, epss: out.epss, kev: out.kev });
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
export async function enrichFindings(findings: Finding[], opts: { enabled?: boolean } = {}): Promise<EnrichResult> {
  if (opts.enabled === false) {
    return { findings: applyEnrichment(findings, { epss: new Map(), kev: new Map() }), note: "risk: severity-only (enrichment off)" };
  }
  let feeds: Feeds;
  try {
    feeds = await loadFeeds();
  } catch {
    feeds = { epss: new Map(), kev: new Map() };
  }
  const enriched = applyEnrichment(findings, feeds);
  const withCve = enriched.filter((f) => f.cve);
  const kevHits = enriched.filter((f) => f.kev).length;
  const note =
    feeds.epss.size || feeds.kev.size
      ? `risk: EPSS ${feeds.epss.size} CVEs · KEV ${feeds.kev.size} · ${withCve.length} finding(s) with CVE${kevHits ? ` · ${kevHits} in KEV` : ""}`
      : "risk: severity-only (feeds unavailable offline)";
  return { findings: enriched, note };
}

// Severity ranking helper re-exported for renderers that sort by risk then sev.
export function sevRank(s: Severity): number {
  return SEVERITIES.indexOf(s);
}

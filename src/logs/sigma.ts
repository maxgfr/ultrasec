import { createHash } from "node:crypto";
import type { Severity } from "../types.js";
import { ATTACK_SIGNATURES, AUTH_EVENTS, FAMILY_CWE, SCANNER_UAS, type SignatureFamily } from "./patterns.js";

// Detection-engineering output for `ultrasec logs --sigma`: the blue-team mirror
// of `variants` (which emits a Semgrep rule for a confirmed code root cause).
// It renders a ready-to-deploy SIGMA pack from the SAME data-only catalogs the
// log forensics uses (patterns.ts), so the hunt signatures and the shipped
// detections can never drift. Reproducible + zero-dependency: a deterministic
// UUID per rule (no clock, no randomness), a hand-rolled YAML emitter, one
// multi-document file. It is a PACK for a SIEM to import, not a per-run artifact:
// a SOC wants every rule for the classes ultrasec hunts, not only the ones that
// happened to fire in the sample it was handed.

// Sigma severity vocabulary — ultrasec's `Severity` maps 1:1 except `info`.
const LEVEL: Record<Severity, string> = { critical: "critical", high: "high", medium: "medium", low: "low", info: "informational" };

// A stable UUIDv5-shaped id derived from a seed, so re-emitting the pack yields
// byte-identical ids (Sigma wants a UUID; SIEM dedup keys on it).
function sigmaId(seed: string): string {
  const h = createHash("sha1").update(`ultrasec-sigma:${seed}`).digest("hex");
  const c = h.slice(0, 32).split("");
  c[12] = "5"; // version 5
  c[16] = ["8", "9", "a", "b"][Number.parseInt(h[16] ?? "0", 16) % 4]!; // RFC 4122 variant
  const s = c.join("");
  return `${s.slice(0, 8)}-${s.slice(8, 12)}-${s.slice(12, 16)}-${s.slice(16, 20)}-${s.slice(20, 32)}`;
}

// A regex source ready for a Sigma `|re` field: prefix `(?i)` when the source
// pattern was case-insensitive (Sigma's `|re` is case-sensitive by default).
function reSource(re: RegExp): string {
  return re.ignoreCase ? `(?i)${re.source}` : re.source;
}

// Single-quoted YAML scalar: literal everything except a `'`, which doubles.
function yq(s: string): string {
  return `'${s.replaceAll("'", "''")}'`;
}

const CWE_TAG_FROM_FAMILY = (fam: SignatureFamily): string | undefined => {
  const cwe = FAMILY_CWE[fam];
  return cwe ? `cwe.${cwe.replace(/^CWE-/i, "")}` : undefined;
};

interface SigmaRule {
  title: string;
  seed: string; // stable id seed
  description: string;
  level: string;
  logsource: Record<string, string>;
  /** detection block lines, already indented under `detection:` */
  detection: string[];
  tags: string[];
  falsepositives: string[];
}

function renderRule(r: SigmaRule): string {
  const L: string[] = ["---"];
  L.push(`title: ${yq(r.title)}`);
  L.push(`id: ${sigmaId(r.seed)}`);
  L.push("status: experimental");
  L.push(`description: ${yq(r.description)}`);
  L.push("author: ultrasec");
  L.push("logsource:");
  for (const [k, v] of Object.entries(r.logsource)) L.push(`  ${k}: ${v}`);
  L.push("detection:");
  L.push(...r.detection.map((line) => `  ${line}`));
  L.push("falsepositives:");
  for (const fp of r.falsepositives) L.push(`  - ${yq(fp)}`);
  L.push(`level: ${r.level}`);
  if (r.tags.length) {
    L.push("tags:");
    for (const t of r.tags) L.push(`  - ${t}`);
  }
  return L.join("\n");
}

/**
 * Render the full Sigma detection pack from the log-forensics catalogs:
 *   - one webserver rule per ATTACK_SIGNATURE (matched on the request URI),
 *   - one webserver rule for every known scanner/attack-tool user-agent,
 *   - one authentication rule for repeated auth failures (brute force).
 * Deterministic; returns "" only if the catalogs are empty (they never are).
 */
export function renderSigmaRules(): string {
  const rules: SigmaRule[] = [];

  for (const sig of ATTACK_SIGNATURES) {
    const cweTag = CWE_TAG_FROM_FAMILY(sig.family);
    rules.push({
      title: `Web attack — ${sig.title}`,
      seed: `attack:${sig.id}`,
      description: sig.note,
      level: LEVEL[sig.severity],
      logsource: { category: "webserver" },
      detection: ["sel:", `  c-uri|re: ${yq(reSource(sig.re))}`, "condition: sel"],
      tags: ["attack.t1190", ...(cweTag ? [cweTag] : [])],
      falsepositives: ["Legitimate traffic that resembles the payload — triage the hit in context, it is a candidate not a verdict."],
    });
  }

  rules.push({
    title: "Security scanner / attack-tool user-agent",
    seed: "scanner-ua",
    description: `A request whose User-Agent identifies a known scanner or attack tool (${SCANNER_UAS.map((u) => u.name).join(", ")}).`,
    level: "medium",
    logsource: { category: "webserver" },
    detection: ["sel:", "  c-useragent|re:", ...SCANNER_UAS.map((u) => `    - ${yq(reSource(u.re))}`), "condition: sel"],
    tags: ["attack.t1595"],
    falsepositives: ["An authorized scan (your own pentest / monitoring) — correlate with the scan window."],
  });

  const failPatterns = AUTH_EVENTS.filter((e) => e.kind === "auth-fail").map((e) => reSource(e.re));
  rules.push({
    title: "Repeated authentication failures (brute force)",
    seed: "auth-brute-force",
    description:
      "Authentication-failure lines. Threshold by source over a window in your SIEM (e.g. >= 10 in 10m by src_ip) — a single failure is not a finding; the burst is. Pair with the success rule to catch a compromise (fails then a success from the same source).",
    level: "medium",
    logsource: { category: "authentication" },
    detection: ["keywords:", ...failPatterns.map((p) => `  - ${yq(p)}`), "condition: keywords"],
    tags: ["attack.t1110"],
    falsepositives: ["A user fat-fingering a password a few times — the threshold, not the single line, is the signal."],
  });

  return rules.length ? `${rules.map(renderRule).join("\n")}\n` : "";
}

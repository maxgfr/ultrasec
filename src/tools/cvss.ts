import type { Severity } from "../types.js";
import { normalizeSeverity } from "./normalize.js";

// Minimal CVSS v3.x base-score calculator. Several scanners (cargo-audit, osv)
// emit a CVSS *vector* rather than a severity label; this turns the vector into
// the standard base score so we can bucket it. Implements the CVSS v3.1 spec
// formula (also correct for v3.0 in practice).

// Null-prototype tables: a CVSS metric value from a tool-supplied vector could be
// an Object.prototype member name ("constructor"…); a plain object would return an
// inherited function and defeat the `=== undefined` validity check below.
const nullObj = <T>(o: Record<string, T>): Record<string, T> => Object.assign(Object.create(null) as Record<string, T>, o);
const AV = nullObj({ N: 0.85, A: 0.62, L: 0.55, P: 0.2 });
const AC = nullObj({ L: 0.77, H: 0.44 });
const UI = nullObj({ N: 0.85, R: 0.62 });
const CIA = nullObj({ H: 0.56, L: 0.22, N: 0 });
const PR_U = nullObj({ N: 0.85, L: 0.62, H: 0.27 });
const PR_C = nullObj({ N: 0.85, L: 0.68, H: 0.5 });

function roundup(x: number): number {
  return Math.ceil(x * 10) / 10;
}

/** Parse a CVSS vector ("CVSS:3.1/AV:N/AC:L/...") into a base score, or null. */
export function cvssBaseScore(vector: string | null | undefined): number | null {
  if (!vector || !/CVSS:3/i.test(vector)) return null;
  const m: Record<string, string> = {};
  for (const part of vector.split("/")) {
    const [k, v] = part.split(":");
    if (k && v) m[k] = v;
  }
  const scope = m.S; // U (unchanged) | C (changed)
  const av = AV[m.AV ?? ""];
  const ac = AC[m.AC ?? ""];
  const ui = UI[m.UI ?? ""];
  const pr = (scope === "C" ? PR_C : PR_U)[m.PR ?? ""];
  const c = CIA[m.C ?? ""];
  const in_ = CIA[m.I ?? ""];
  const a = CIA[m.A ?? ""];
  if ([av, ac, ui, pr, c, in_, a].some((x) => x === undefined)) return null;

  const iss = 1 - (1 - c!) * (1 - in_!) * (1 - a!);
  const impact = scope === "C" ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av! * ac! * pr! * ui!;
  const raw = scope === "C" ? 1.08 * (impact + exploitability) : impact + exploitability;
  return roundup(Math.min(raw, 10));
}

/** Map a numeric CVSS score (0–10) to ultrasec severity. */
export function scoreToSeverity(score: number | null | undefined): Severity {
  if (score == null) return "medium";
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score >= 0.1) return "low";
  return "info";
}

/** Accepts a numeric string ("7.2"), a vector, or a label; returns a severity. */
export function deriveSeverity(input: string | null | undefined, fallback: Severity = "medium"): Severity {
  if (!input) return fallback;
  const s = input.trim();
  const asNum = Number(s);
  if (!Number.isNaN(asNum) && s !== "") return scoreToSeverity(asNum);
  if (/CVSS:3/i.test(s)) return scoreToSeverity(cvssBaseScore(s));
  return normalizeSeverity(s, fallback); // a label like HIGH/MODERATE/LOW
}

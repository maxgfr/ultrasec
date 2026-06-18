import { CONFIDENCES, type Category, type Confidence, type Finding } from "../types.js";
import { firstCwe, makeToolFinding, normalizeSeverity } from "./normalize.js";

// deepsec interop bridge. vercel-labs/deepsec is an UPSTREAM producer, not a tool
// ultrasec runs: the user runs `deepsec export --format json` themselves (deepsec
// drives its own LLM / keys), and ultrasec INGESTS that file — mapping each
// ExportedFinding into the unified Finding model so it flows through the same
// correlate → EPSS/KEV risk-rank → [file:line] grounding gate → verify → render
// pipeline as every other source. This keeps ultrasec's no-keys / zero-dep core
// intact (we parse data; we never spawn deepsec) and makes ultrasec's grounding +
// conservative verify the deterministic referee over deepsec's non-deterministic
// agent output. This is a file PARSER, not a ToolAdapter.

/** One entry of `deepsec export --format json`'s ExportedFinding[] array. */
interface DeepsecMeta {
  filePath?: string;
  lineNumbers?: number[];
  severity?: string;
  vulnSlug?: string;
  confidence?: string;
  revalidation?: { verdict?: string; reasoning?: string };
  githubUrl?: string;
}
interface ExportedFinding {
  title?: string;
  description?: string;
  severity?: string;
  labels?: string[];
  metadata?: DeepsecMeta;
}

/**
 * Map a deepsec vulnSlug to an ultrasec Category. Defaults to "sast" (deepsec is
 * agent-reasoned, not dataflow-enumerated). NEVER returns "taint" — that category
 * is reserved for the engine's own source→sink chains, which carry a real path.
 */
function slugToCategory(slug: string): Category {
  const s = slug.toLowerCase();
  if (/(auth|idor|access[-_]?control|privilege|authz|ssrf)/.test(s)) {
    // SSRF is a sink class; everything else here is access-control / authorization.
    return /ssrf/.test(s) ? "sast" : "authz";
  }
  if (/(crypto|hash|cipher|weak[-_]?(rng|random)|tls|ssl)/.test(s)) return "crypto";
  if (/(secret|hardcoded|credential|api[-_]?key|token|password)/.test(s)) return "secret";
  if (/(dockerfile|terraform|gh[-_]?actions|github[-_]?actions|iac|misconfig|config)/.test(s)) return "config";
  if (/(dependency|outdated|vuln[-_]?dep|cve|\bsca\b)/.test(s)) return "dep";
  return "sast";
}

function mapConfidence(raw: string | undefined): Confidence {
  const c = String(raw ?? "").trim().toLowerCase();
  return (CONFIDENCES as readonly string[]).includes(c) ? (c as Confidence) : "medium";
}

/**
 * Parse a `deepsec export --format json` array into normalized Findings. Never
 * throws: malformed JSON, a non-array root, or entries lacking a usable location
 * yield `[]` / are skipped. ids are content-stable (idempotent re-import).
 */
export function importDeepsec(raw: string): Finding[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];

  const out: Finding[] = [];
  for (const entry of parsed as ExportedFinding[]) {
    if (!entry || typeof entry !== "object") continue;
    const md = entry.metadata;
    if (!md || typeof md !== "object" || !md.filePath) continue; // need a location to ground

    const slug = String(md.vulnSlug ?? "finding");
    const line = Array.isArray(md.lineNumbers) && md.lineNumbers.length && typeof md.lineNumbers[0] === "number" ? md.lineNumbers[0] : undefined;
    const reval = md.revalidation;
    const revalNote = reval && reval.reasoning ? ` — deepsec revalidation (${reval.verdict ?? "?"}): ${reval.reasoning}` : "";

    out.push(
      makeToolFinding({
        tool: "deepsec",
        category: slugToCategory(slug),
        // ident carries file:line so the content-hash id is stable across re-imports.
        ident: `${slug}:${md.filePath}:${line ?? ""}`,
        title: entry.title || slug,
        severity: normalizeSeverity(md.severity ?? entry.severity),
        message: `${entry.title || slug}${revalNote}`,
        file: md.filePath,
        line,
        cwe: firstCwe([entry.description ?? "", ...(entry.labels ?? [])].join(" ")),
        confidence: mapConfidence(md.confidence),
        references: md.githubUrl ? [md.githubUrl] : undefined,
      }),
    );
  }
  return out;
}

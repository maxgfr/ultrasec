import { appendFileSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, extname, join } from "node:path";

// Archivable command output.
//
// Everything an audit stage prints has, until now, existed only in the operator's
// scrollback: `render` produces artifacts, but only at the very END of the chain.
// The counters that matter most for coverage — how many verdicts folded, how many
// rows were refused, which tools were skipped — were unrecoverable an hour later.
//
// Two complementary mechanisms, both additive (stdout is never altered):
//   --report <path>  archive ONE command's output, format from the extension;
//   JOURNAL.md       an append-only log of every command run against a run dir.

/** What a command produced, as captured by the tee'ing output sink. */
export interface Transcript {
  /** The full command line, e.g. `ultrasec verify --apply verdicts.json`. */
  command: string;
  stdout: string;
  stderr: string;
  /** Process exit code. */
  code: number;
  /** ISO-8601, injected so the writer stays deterministic under test. */
  at: string;
}

/** Extensions --report accepts; the extension picks the writer. */
export const REPORT_FORMATS: readonly string[] = ["md", "html", "json", "txt", "log"];

export class UnknownReportFormat extends Error {
  constructor(ext: string) {
    super(`unsupported --report extension "${ext}" — use one of ${REPORT_FORMATS.map((f) => `.${f}`).join(", ")}`);
  }
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
}

function asMarkdown(t: Transcript): string {
  const L = [`# ${t.command}`, "", `_${t.at} · exit ${t.code}_`, ""];
  if (t.stdout.trim()) L.push("## Output", "", "```", t.stdout.trimEnd(), "```", "");
  if (t.stderr.trim()) L.push("## Diagnostics", "", "```", t.stderr.trimEnd(), "```", "");
  return `${L.join("\n")}\n`;
}

function asHtml(t: Transcript): string {
  const block = (title: string, body: string) => (body.trim() ? `<h2>${escapeHtml(title)}</h2><pre>${escapeHtml(body.trimEnd())}</pre>` : "");
  // Self-contained on purpose: a report is often mailed or attached, and a
  // stylesheet that only resolves on the author's machine is worse than none.
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(t.command)}</title>
<style>
  :root { color-scheme: light dark; --fg: #111; --bg: #fff; --muted: #666; --pre: #f6f6f6; }
  @media (prefers-color-scheme: dark) { :root { --fg: #e6e6e6; --bg: #121212; --muted: #9a9a9a; --pre: #1c1c1c; } }
  body { font: 15px/1.55 ui-sans-serif, system-ui, sans-serif; color: var(--fg); background: var(--bg); margin: 0 auto; padding: 2rem 1rem; max-width: 60rem; }
  h1 { font-size: 1.35rem; margin: 0 0 .25rem; }
  .meta { color: var(--muted); font-size: .875rem; margin-bottom: 1.5rem; }
  pre { background: var(--pre); padding: 1rem; border-radius: 6px; overflow-x: auto; white-space: pre-wrap; word-break: break-word; }
</style></head>
<body>
<h1>${escapeHtml(t.command)}</h1>
<p class="meta">${escapeHtml(t.at)} · exit ${t.code}</p>
${block("Output", t.stdout)}
${block("Diagnostics", t.stderr)}
</body></html>
`;
}

/**
 * Write a command's transcript to `path`. The format follows the extension;
 * an unknown one THROWS rather than writing a file whose contents contradict
 * its name.
 */
export function writeReport(path: string, t: Transcript): void {
  const ext = extname(path).replace(/^\./, "").toLowerCase();
  if (!REPORT_FORMATS.includes(ext)) throw new UnknownReportFormat(ext || "(none)");

  const body =
    ext === "md"
      ? asMarkdown(t)
      : ext === "html"
        ? asHtml(t)
        : ext === "json"
          ? `${JSON.stringify(t, null, 2)}\n`
          : `${t.command}\n${t.at} · exit ${t.code}\n\n${t.stdout}${t.stderr ? `\n${t.stderr}` : ""}`;

  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, body);
}

/** First non-empty line of a command's output — the summary line stages print. */
function headline(t: Transcript): string {
  const lines = [...t.stdout.split("\n"), ...t.stderr.split("\n")].map((l) => l.trim()).filter(Boolean);
  // Skip the "ultrasec <cmd> → <path>" banner: the journal already names the command.
  const meat = lines.find((l) => !l.startsWith("ultrasec ")) ?? lines[0];
  return meat ?? "(no output)";
}

export const JOURNAL_FILE = "JOURNAL.md";

/**
 * Append one entry to the run's JOURNAL.md, creating it on first use.
 *
 * Append-only and best-effort: the journal is a record OF the audit, never a
 * gate on it, so a write failure must not fail a command that otherwise
 * succeeded — the caller swallows the error.
 */
export function appendJournal(runDir: string, t: Transcript): void {
  mkdirSync(runDir, { recursive: true });
  const path = join(runDir, JOURNAL_FILE);
  if (!existsSync(path)) writeFileSync(path, JOURNAL_HEADER);
  // Keep the entry to the summary line plus anything that signals lost coverage —
  // a journal nobody reads is as useless as no journal.
  const summary = [headline(t), ...t.stdout.split("\n").filter((l) => l.includes("✗ dropped") || l.includes("✗ rejected"))];
  const entry = [`## ${t.at} · \`${t.command}\``, "", ...summary.map((s) => `- ${s.trim()}`), `- exit ${t.code}`, ""].join("\n");
  appendFileSync(path, `${entry}\n`);
}

/** The header a fresh journal opens with. */
export const JOURNAL_HEADER = ["# ultrasec run journal", "", "_Append-only record of every command run against this audit directory._", "", ""].join("\n");

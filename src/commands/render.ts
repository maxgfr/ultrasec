import { writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { flagStr, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier } from "../store.js";
import { renderSummary, renderReport, renderFull } from "../render/report.js";
import { renderHtml } from "../render/html.js";

// `ultrasec render --run <dir>` → SUMMARY.md / REPORT.md / FULL.md + index.html
export function runRender(args: ParsedArgs): number {
  const run = resolve(flagStr(args, "run") ?? ".ultrasec");
  let dossier;
  try {
    dossier = loadDossier(run);
  } catch (e) {
    eprintln(`ultrasec render: ${(e as Error).message}`);
    return 2;
  }

  const outputs: [string, string][] = [
    ["SUMMARY.md", renderSummary(dossier)],
    ["REPORT.md", renderReport(dossier)],
    ["FULL.md", renderFull(dossier)],
    ["index.html", renderHtml(dossier)],
  ];
  for (const [name, body] of outputs) writeFileSync(join(run, name), body);

  println(`ultrasec render → ${run}`);
  for (const [name] of outputs) println(`  ${join(run, name)}`);
  return 0;
}

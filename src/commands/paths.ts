import { resolve } from "node:path";
import { flagStr, flagBool, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier } from "../store.js";

// `ultrasec paths [--run .ultrasec] [--kind sql] [--severity high] [--json]`
// List the candidate cross-file source→sink chains from the dossier.
export function runPaths(args: ParsedArgs): number {
  const run = resolve(flagStr(args, "run") ?? ".ultrasec");
  const kind = flagStr(args, "kind");
  const sev = flagStr(args, "severity");

  let d: ReturnType<typeof loadDossier>;
  try {
    d = loadDossier(run);
  } catch (e) {
    eprintln(`ultrasec paths: ${(e as Error).message}`);
    return 2;
  }

  let findings = d.findings.filter((f) => f.path && f.path.length);
  if (kind) findings = findings.filter((f) => f.sink?.kind === kind);
  if (sev) findings = findings.filter((f) => f.severity === sev);

  if (flagBool(args, "json")) {
    println(
      JSON.stringify(
        findings.map((f) => ({ id: f.id, severity: f.severity, cwe: f.cwe, path: f.path })),
        null,
        2,
      ),
    );
    return 0;
  }

  if (!findings.length) {
    println("no candidate taint paths match.");
    return 0;
  }
  for (const f of findings) {
    println(`${f.id}  ${f.severity.padEnd(8)} ${f.cwe ?? ""}  ${f.title}`);
    println(`        ${f.path!.map((p) => `${p.file}:${p.line}`).join(" → ")}`);
  }
  return 0;
}

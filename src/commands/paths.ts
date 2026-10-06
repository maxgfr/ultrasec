import { resolve } from "node:path";
import { flagStr, flagBool, println, eprintln, type ParsedArgs } from "../util.js";
import { loadDossier } from "../store.js";
import { SURFACE_FILTERS, type SurfaceFilter } from "../orchestrate.js";
import { surfaceOf } from "../surface.js";
import { SEVERITIES, type Severity } from "../types.js";

const isSeverity = (s: string): s is Severity => (SEVERITIES as readonly string[]).includes(s);
const rank = (s: string): number => SEVERITIES.indexOf(s as Severity);

// `ultrasec paths [--run .ultrasec] [--kind sql] [--min-severity high | --severity high] [--surface code] [--json]`
// List the candidate cross-file source→sink chains from the dossier.
//
// `--min-severity` is a FLOOR (that severity and above), as on `check`.
// `--severity` is an EXACT match. On a real audit `--severity high` was read as
// "high and up", listed 83 chains and silently omitted the one critical — so an
// exact filter now names what it hid above it.
export function runPaths(args: ParsedArgs): number {
  const run = resolve(flagStr(args, "run") ?? ".ultrasec");
  const kind = flagStr(args, "kind");
  const sev = flagStr(args, "severity");
  const floor = flagStr(args, "min-severity");
  for (const [flag, value] of [
    ["severity", sev],
    ["min-severity", floor],
  ] as const) {
    if (value !== undefined && !isSeverity(value)) {
      eprintln(`ultrasec paths: unknown --${flag} '${value}' (expected ${SEVERITIES.join("|")}).`);
      return 2;
    }
  }
  // Fail closed on a typo rather than silently widening back to everything.
  const surfaceFlag = flagStr(args, "surface");
  if (surfaceFlag !== undefined && !(SURFACE_FILTERS as readonly string[]).includes(surfaceFlag)) {
    eprintln(`ultrasec paths: unknown --surface "${surfaceFlag}" — expected one of: ${SURFACE_FILTERS.join(", ")}.`);
    return 2;
  }
  const surface = (surfaceFlag ?? "all") as SurfaceFilter;

  let d: ReturnType<typeof loadDossier>;
  try {
    d = loadDossier(run);
  } catch (e) {
    eprintln(`ultrasec paths: ${(e as Error).message}`);
    return 2;
  }

  const chained = d.findings.filter((f) => f.path && f.path.length);
  let findings = chained;
  if (surface !== "all") findings = findings.filter((f) => surfaceOf(f) === surface);
  if (kind) findings = findings.filter((f) => f.sink?.kind === kind);
  // Chains an exact `--severity` leaves out ABOVE itself — the ones a reader
  // most needs to know were not listed.
  const hiddenAbove = sev && !floor ? findings.filter((f) => rank(f.severity) < rank(sev)) : [];
  if (floor) findings = findings.filter((f) => rank(f.severity) <= rank(floor));
  if (sev) findings = findings.filter((f) => f.severity === sev);
  const aboveNote = (): void => {
    if (!hiddenAbove.length || !sev) return;
    const bySev = SEVERITIES.filter((s) => rank(s) < rank(sev))
      .map((s) => [s, hiddenAbove.filter((f) => f.severity === s).length] as const)
      .filter(([, n]) => n > 0)
      .map(([s, n]) => `${n} ${s}`)
      .join(", ");
    eprintln(`  note: --severity is an exact match — ${bySev} chain(s) above this severity are not listed (use --min-severity ${sev} for "${sev} and above").`);
  };

  // What this command drops, and why saying so matters.
  //
  // `paths` lists CHAINS — findings with a proven source→sink walk. A dangerous
  // callee the walk could not connect to a source (an orphan sink) has no path
  // and never appears here. So `paths --kind X` printing nothing means "no
  // chain of kind X", and it reads as "no X" — which is the exact silence this
  // tool exists to break. Several classes live almost entirely as orphan sinks:
  // an `algodos` call behind a service boundary, an `errleak` line in a handler
  // the graph did not reach.
  const pathlessOfKind = kind ? d.findings.filter((f) => !(f.path && f.path.length) && f.sink?.kind === kind).length : 0;

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
    aboveNote();
    if (pathlessOfKind) {
      println(
        `  but ${pathlessOfKind} \`${kind}\` finding(s) exist WITHOUT a proven source path (orphan sinks) — this command lists chains only. See DOSSIER.md, or \`--json\` on findings.json.`,
      );
    }
    return 0;
  }
  for (const f of findings) {
    println(`${f.id}  ${f.severity.padEnd(8)} ${f.cwe ?? ""}  ${f.title}`);
    println(`        ${f.path!.map((p) => `${p.file}:${p.line}`).join(" → ")}`);
  }
  if (pathlessOfKind) {
    println(`  (+${pathlessOfKind} \`${kind}\` finding(s) with no proven source path — not chains, so not listed here.)`);
  }
  aboveNote();
  return 0;
}

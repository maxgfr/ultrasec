import { flagBool, println, type ParsedArgs } from "../util.js";
import { toolStatuses, type ToolStatus } from "../tools/registry.js";

// `ultrasec tools` — show the external scanner catalog with live presence and
// install hints. ultrasec degrades gracefully: it runs whatever is installed and
// tells you how to get the rest. The graph + AI taint reasoning always work.

function bestInstallHint(t: ToolStatus): string {
  const i = t.install;
  return i.brew ?? i.pip ?? i.go ?? i.cargo ?? i.npx ?? i.docker ?? i.url ?? "";
}

export function runTools(args: ParsedArgs): number {
  const statuses = toolStatuses();

  if (flagBool(args, "json")) {
    println(JSON.stringify(statuses, null, 2));
    return 0;
  }

  const installed = statuses.filter((t) => t.installed);
  const missing = statuses.filter((t) => !t.installed);

  println(`ultrasec external scanners — ${installed.length}/${statuses.length} installed\n`);

  const row = (t: ToolStatus): string => {
    const mark = t.installed ? "✓" : "·";
    const star = t.primary ? "*" : " ";
    const ver = t.version ? `  (${t.version})` : "";
    return `  ${mark}${star} ${t.name.padEnd(14)} ${t.category.padEnd(7)} ${t.description}${ver}`;
  };

  if (installed.length) {
    println("INSTALLED");
    for (const t of installed) println(row(t));
    println("");
  }

  println("AVAILABLE TO INSTALL");
  for (const t of missing) {
    println(row(t));
    const hint = bestInstallHint(t);
    if (hint) println(`        → ${hint}`);
  }

  println("\n  * = primary tool for its category. ✓ = on PATH.");
  println("  ultrasec runs the installed tools and normalizes their output; none are required.");
  return 0;
}

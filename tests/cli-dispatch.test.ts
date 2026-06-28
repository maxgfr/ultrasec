import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { COMMAND_HANDLERS, dispatch, HELP } from "../src/cli.js";
import { VERSION } from "../src/types.js";
import { parseArgs } from "../src/util.js";

// Command names as advertised in the HELP COMMANDS block: lines indented by
// exactly two spaces (continuation lines are indented further).
function helpCommands(): string[] {
  const body = HELP.split("\nCOMMANDS\n")[1]?.split("\nGLOBAL")[0] ?? "";
  const names: string[] = [];
  for (const line of body.split("\n")) {
    const m = line.match(/^ {2}([a-z]+)\b/);
    if (m) names.push(m[1]!);
  }
  return names;
}

describe("CLI dispatch table", () => {
  it("every command in HELP maps to a real handler (and vice-versa)", () => {
    const advertised = new Set(helpCommands());
    const wired = new Set(Object.keys(COMMAND_HANDLERS));
    expect(advertised.size).toBeGreaterThan(0);
    // No help entry without a handler…
    for (const cmd of advertised) expect(wired.has(cmd), `HELP lists \`${cmd}\` but no handler is wired`).toBe(true);
    // …and no handler left undocumented.
    for (const cmd of wired) expect(advertised.has(cmd), `\`${cmd}\` dispatches but HELP never documents it`).toBe(true);
  });

  it("an unknown command exits 2 without running anything", async () => {
    const err = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const code = await dispatch("definitely-not-a-command", parseArgs(["definitely-not-a-command"]));
    err.mockRestore();
    expect(code).toBe(2);
  });

  it("help / undefined print the help and exit 0", async () => {
    const out = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    expect(await dispatch(undefined, parseArgs([]))).toBe(0);
    expect(await dispatch("help", parseArgs(["help"]))).toBe(0);
    out.mockRestore();
  });

  it("version prints the version and exits 0", async () => {
    let printed = "";
    const out = vi.spyOn(process.stdout, "write").mockImplementation((c: any) => {
      printed += String(c);
      return true;
    });
    const code = await dispatch("version", parseArgs(["version"]));
    out.mockRestore();
    expect(code).toBe(0);
    expect(printed).toContain(VERSION);
  });
});

// End-to-end against the committed/built bundle: proves the entrypoint guard
// still auto-runs main() and that the global flags short-circuit correctly.
describe("CLI bundle entrypoint", () => {
  const bundle = join(import.meta.dirname, "..", "scripts", "ultrasec.mjs");
  const run = (args: string[]) => {
    try {
      return { code: 0, out: execFileSync(process.execPath, [bundle, ...args], { encoding: "utf8" }) };
    } catch (e: any) {
      return { code: e.status as number, out: String(e.stdout ?? "") + String(e.stderr ?? "") };
    }
  };

  it.runIf(existsSync(bundle))("--help prints the command list and exits 0", () => {
    const { code, out } = run(["--help"]);
    expect(code).toBe(0);
    expect(out).toContain("COMMANDS");
    expect(out).toContain("USAGE");
  });

  it.runIf(existsSync(bundle))("--version prints the version and exits 0", () => {
    const { code, out } = run(["--version"]);
    expect(code).toBe(0);
    expect(out.trim()).toContain(VERSION);
  });

  it.runIf(existsSync(bundle))("an unknown command exits 2", () => {
    const { code } = run(["definitely-not-a-command"]);
    expect(code).toBe(2);
  });
});

import { describe, it, expect } from "vitest";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanRepo } from "../src/scan.js";
import { buildGraph } from "../src/graph.js";
import { enumerateTaint } from "../src/taint.js";

// Treating the environment as attacker-controlled models configuration
// injection, which is a real class — but it presumes the operator of the
// deployment is a threat actor, and most trust models say otherwise. On one real
// audit those candidates were 100 of the 138 refutations, crowding out the flows
// rooted in actual user input.
//
// So: opt-in, never a default change. These tests pin both halves — the flag
// removes exactly the env-rooted flows, and nothing else.

function repo(): string {
  const root = mkdtempSync(join(tmpdir(), "ultrasec-env-"));
  mkdirSync(join(root, "src"), { recursive: true });
  // One flow from an HTTP request (genuinely untrusted) …
  writeFileSync(
    join(root, "src", "http.js"),
    `const { exec } = require("child_process");
function handler(req, res) {
  const name = req.query.name;
  exec("ls " + name);
}
module.exports = { handler };
`,
  );
  // … and one from the environment (deployment configuration).
  writeFileSync(
    join(root, "src", "env.js"),
    `const { exec } = require("child_process");
function backup() {
  const dir = process.env.BACKUP_DIR;
  exec("tar -cf out.tar " + dir);
}
module.exports = { backup };
`,
  );
  return root;
}

function kinds(root: string, excludeEnvSources: boolean): string[] {
  const scan = scanRepo(root);
  const taint = enumerateTaint(scan, buildGraph(scan), { excludeEnvSources });
  return taint.findings.map((f) => f.source?.kind ?? "?").sort();
}

describe("--no-env-sources", () => {
  it("by default enumerates both the http- and the env-rooted flow", () => {
    const found = kinds(repo(), false);
    expect(found).toContain("http");
    expect(found).toContain("env");
  });

  it("removes the env-rooted flow and leaves the http one intact", () => {
    const found = kinds(repo(), true);
    expect(found).toContain("http");
    expect(found).not.toContain("env");
  });

  it("is off by default, so the candidate set is unchanged without the flag", () => {
    const root = repo();
    const scan = scanRepo(root);
    const graph = buildGraph(scan);
    expect(enumerateTaint(scan, graph, {}).findings.length).toBe(enumerateTaint(scan, graph).findings.length);
  });
});

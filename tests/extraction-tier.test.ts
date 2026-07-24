import { execFile } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import { extractionTier } from "../src/scan.js";
import type { Manifest } from "../src/types.js";

const BUNDLE = fileURLToPath(new URL("../scripts/ultrasec.mjs", import.meta.url));

const allTmp: string[] = [];
afterAll(() => {
  for (const d of allTmp) rmSync(d, { recursive: true, force: true });
});
function mk(prefix: string): string {
  const d = mkdtempSync(join(tmpdir(), prefix));
  allTmp.push(d);
  return d;
}

function run(args: string[], env: NodeJS.ProcessEnv): Promise<{ stdout: string; stderr: string; status: number }> {
  return new Promise((res) => {
    execFile(process.execPath, [BUNDLE, ...args], { encoding: "utf8", env }, (err, stdout, stderr) => {
      const status = err ? (typeof (err as { code?: unknown }).code === "number" ? (err as { code: number }).code : 1) : 0;
      res({ stdout: stdout ?? "", stderr: stderr ?? "", status });
    });
  });
}

// A cache home with no grammars + no pull ⇒ the regex tier, deterministically
// and without touching the network. This is the shape CI runs in.
function offlineEnv(): NodeJS.ProcessEnv {
  return {
    ...process.env,
    CODEINDEX_GRAMMAR_DIR: "",
    ULTRAINDEX_GRAMMAR_DIR: "",
    CODEINDEX_GRAMMARS_DIR: "",
    XDG_CACHE_HOME: mk("ultrasec-tier-cache-"),
    CODEINDEX_NO_GRAMMARS_PULL: "1",
  };
}

function miniRepo(): string {
  const repo = mk("ultrasec-tier-repo-");
  mkdirSync(join(repo, "src"), { recursive: true });
  writeFileSync(join(repo, "src", "a.js"), "export function a(){ return query(req.query.x); }\n");
  return repo;
}

describe("extraction tier is recorded, never assumed", () => {
  it("extractionTier() reports the tier and whether AST is live", () => {
    const t = extractionTier();
    expect(["adjacent", "env", "cache", "none"]).toContain(t.tier);
    expect(typeof t.ast).toBe("boolean");
    // A resolvable dir is not the same as a loaded grammar: `ast` must reflect
    // grammarReady (post warm-up), not merely that some dir exists.
    if (t.tier === "none") expect(t.ast).toBe(false);
  });

  it("`scan` records the tier in the manifest, so a regex-tier run cannot pass for an AST one", async () => {
    const out = mk("ultrasec-tier-out-");
    const { status } = await run(["scan", "--repo", miniRepo(), "--out", out, "--offline"], offlineEnv());
    expect(status).toBe(0); // a regex-tier run is a SUCCESSFUL run
    const manifest = JSON.parse(readFileSync(join(out, "manifest.json"), "utf8")) as Manifest;
    expect(manifest.extraction).toEqual({ tier: "none", ast: false });
  });

  it("announces the downgrade on stderr rather than degrading silently", async () => {
    const out = mk("ultrasec-tier-out2-");
    const { stderr } = await run(["scan", "--repo", miniRepo(), "--out", out, "--offline"], offlineEnv());
    expect(stderr).toContain("ultrasec:");
    expect(stderr).toMatch(/regex tier/);
    expect(stderr).toMatch(/grammars pull/);
  });

  // The warm-up may download ~22 MB on a cold machine. A command that only
  // re-reads an existing dossier must never trigger that.
  it("read-only commands never warm (no pull, no wasm load)", async () => {
    const env = { ...offlineEnv(), CODEINDEX_NO_GRAMMARS_PULL: "", CODEINDEX_GRAMMARS_URL: "http://127.0.0.1:1/never" };
    for (const args of [["--help"], ["version"], ["check", "--run", mk("ultrasec-tier-empty-")]]) {
      const { stderr } = await run(args, env);
      expect(stderr, `\`${args[0]}\` must not touch the grammars`).not.toMatch(/grammars/i);
    }
  });

  it("the bundle ships no adjacent grammars — the cache tier is the intended supplier", () => {
    expect(existsSync(join(BUNDLE, "..", "grammars"))).toBe(false);
  });
});

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { connect, createServer } from "node:net";
import type { AddressInfo } from "node:net";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { resolveScriptSource, scriptPath, packageChecker } from "../src/tools/package-checker.js";
import { PACKAGE_CHECKER_TAG } from "../src/vendor/package-checker-script.js";

// resolveScriptSource() (src/tools/package-checker.ts) picks between the
// vendored, sha256-pinned package-checker.sh and an upstream "latest" release
// fetched (via `curl`, short-timeout) at scan time. It is deliberately
// SYNCHRONOUS (the ToolAdapter.command() contract requires it), which is why
// these tests spawn the fixture HTTP server as a genuinely SEPARATE OS process
// (`python3 -m http.server`) rather than an in-process Node http.Server: a
// same-process server would deadlock the moment the synchronous
// execFileSync("curl", …) call blocks this test's own event loop — the server
// callback would never get a turn to answer it.

/** A free ephemeral TCP port, grabbed and released before curl ever runs (this
 *  probe itself is async, so it can't deadlock the way a same-process
 *  in-request-handler server would). */
function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address() as AddressInfo;
      srv.close(() => resolve(port));
    });
  });
}

/** Poll (async, non-blocking) until something accepts TCP connections on `port`. */
function waitForPort(port: number, triesLeft = 50): Promise<void> {
  return new Promise((resolve, reject) => {
    const sock = connect({ port, host: "127.0.0.1" }, () => {
      sock.end();
      resolve();
    });
    sock.on("error", () => {
      sock.destroy();
      if (triesLeft <= 0) {
        reject(new Error("fixture server never became ready"));
        return;
      }
      setTimeout(() => waitForPort(port, triesLeft - 1).then(resolve, reject), 40);
    });
  });
}

/** Write a file tree so each key's PATH (relative, no leading "/") becomes a
 *  URL path servable by `python3 -m http.server --directory <root>` — e.g.
 *  "repos/x/releases/latest" -> GET /repos/x/releases/latest. */
function writeFixtureTree(root: string, files: Record<string, string>): void {
  for (const [rel, content] of Object.entries(files)) {
    const full = join(root, rel);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
}

/** Spin up a real, separate-process HTTP server serving `files` (see
 *  writeFixtureTree) and return its base URL once it's actually accepting
 *  connections. Paths with no matching file 404, matching resolveScriptSource's
 *  "download/lookup failed" branches for free. */
async function startFixtureServer(files: Record<string, string>): Promise<{ proc: ChildProcess; base: string; root: string }> {
  const root = mkdtempSync(join(tmpdir(), "ultrasec-pc-fixture-"));
  writeFixtureTree(root, files);
  const port = await getFreePort();
  const proc = spawn("python3", ["-m", "http.server", String(port), "--bind", "127.0.0.1", "--directory", root], { stdio: "ignore" });
  await waitForPort(port);
  return { proc, base: `http://127.0.0.1:${port}`, root };
}

function stopFixtureServer(fx: { proc: ChildProcess; root: string } | undefined): void {
  if (!fx) return;
  fx.proc.kill();
  rmSync(fx.root, { recursive: true, force: true });
}

describe("resolveScriptSource — runtime latest-with-fallback", () => {
  let dir: string;
  let fx: { proc: ChildProcess; base: string; root: string } | undefined;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "ultrasec-package-checker-resolve-"));
    process.env.ULTRASEC_CACHE_DIR = dir;
    delete process.env.ULTRASEC_PACKAGE_CHECKER_PINNED;
    delete process.env.ULTRASEC_PACKAGE_CHECKER_API;
    delete process.env.ULTRASEC_PACKAGE_CHECKER_RAW;
    delete process.env.ULTRASEC_PACKAGE_CHECKER_DEBUG;
  });

  afterEach(() => {
    delete process.env.ULTRASEC_CACHE_DIR;
    delete process.env.ULTRASEC_PACKAGE_CHECKER_PINNED;
    delete process.env.ULTRASEC_PACKAGE_CHECKER_API;
    delete process.env.ULTRASEC_PACKAGE_CHECKER_RAW;
    delete process.env.ULTRASEC_PACKAGE_CHECKER_DEBUG;
    rmSync(dir, { recursive: true, force: true });
    stopFixtureServer(fx);
    fx = undefined;
  });

  it("ULTRASEC_PACKAGE_CHECKER_PINNED=1 forces the vendored copy without touching the network", () => {
    // Point at a port nothing listens on — if this branch made ANY network call
    // it would fail (loudly or after a timeout); the pinned escape hatch must
    // short-circuit before ever reaching fetchLatestTag().
    process.env.ULTRASEC_PACKAGE_CHECKER_PINNED = "1";
    process.env.ULTRASEC_PACKAGE_CHECKER_API = "http://127.0.0.1:1";
    const { cmd, note } = resolveScriptSource();
    expect(cmd).toEqual(["bash", scriptPath()]);
    expect(note).toContain(PACKAGE_CHECKER_TAG);
    expect(note).toContain("pinned");
  });

  it("upstream tag equal to the vendored pin: uses the vendored copy, no download", async () => {
    fx = await startFixtureServer({
      "repos/maxgfr/package-checker.sh/releases/latest": JSON.stringify({ tag_name: PACKAGE_CHECKER_TAG }),
    });
    process.env.ULTRASEC_PACKAGE_CHECKER_API = fx.base;
    process.env.ULTRASEC_PACKAGE_CHECKER_RAW = fx.base;
    const { cmd, note } = resolveScriptSource();
    expect(cmd).toEqual(["bash", scriptPath()]);
    expect(note).toContain("already latest");
  });

  it("newer upstream tag: downloads script.sh, caches it content-addressed by tag, and runs it", async () => {
    const newTag = "v99.0.0";
    const body = "#!/usr/bin/env bash\necho fixture\n";
    fx = await startFixtureServer({
      "repos/maxgfr/package-checker.sh/releases/latest": JSON.stringify({ tag_name: newTag }),
      [`maxgfr/package-checker.sh/${newTag}/script.sh`]: body,
    });
    process.env.ULTRASEC_PACKAGE_CHECKER_API = fx.base;
    process.env.ULTRASEC_PACKAGE_CHECKER_RAW = fx.base;
    const { cmd, note } = resolveScriptSource();
    expect(cmd[0]).toBe("bash");
    expect(cmd[1]).toMatch(/script-v99\.0\.0-[0-9a-f]{12}\.sh$/);
    expect(readFileSync(cmd[1]!, "utf8")).toBe(body);
    expect(note).toBe(`${newTag} (latest)`);

    // A second resolution with the same tag reuses the cached file (no error,
    // same path) rather than re-downloading.
    const again = resolveScriptSource();
    expect(again.cmd).toEqual(cmd);
  });

  it("latest-tag lookup returns malformed JSON: falls back to the vendored copy", async () => {
    fx = await startFixtureServer({ "repos/maxgfr/package-checker.sh/releases/latest": "{not json" });
    process.env.ULTRASEC_PACKAGE_CHECKER_API = fx.base;
    const { cmd, note } = resolveScriptSource();
    expect(cmd).toEqual(["bash", scriptPath()]);
    expect(note).toContain("vendored fallback");
    expect(note).toContain("lookup failed");
  });

  it("a newer tag resolves but its script.sh 404s: falls back to the vendored copy", async () => {
    const newTag = "v99.0.0";
    fx = await startFixtureServer({
      "repos/maxgfr/package-checker.sh/releases/latest": JSON.stringify({ tag_name: newTag }),
      // deliberately no script.sh file for newTag -> 404
    });
    process.env.ULTRASEC_PACKAGE_CHECKER_API = fx.base;
    process.env.ULTRASEC_PACKAGE_CHECKER_RAW = fx.base;
    const { cmd, note } = resolveScriptSource();
    expect(cmd).toEqual(["bash", scriptPath()]);
    expect(note).toContain("vendored fallback");
    expect(note).toContain(`download of ${newTag} failed`);
  });

  it("an unreachable API host: falls back to the vendored copy, never throws", () => {
    process.env.ULTRASEC_PACKAGE_CHECKER_API = "http://127.0.0.1:1"; // nothing listens here
    const { cmd, note } = resolveScriptSource();
    expect(cmd).toEqual(["bash", scriptPath()]);
    expect(note).toContain("vendored fallback");
  });

  it("ULTRASEC_PACKAGE_CHECKER_DEBUG=1 prints the resolution note to stderr (run.ts's generic note can't carry it)", () => {
    process.env.ULTRASEC_PACKAGE_CHECKER_PINNED = "1";
    process.env.ULTRASEC_PACKAGE_CHECKER_DEBUG = "1";
    const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    try {
      const cmd = packageChecker.command!();
      expect(cmd).toEqual(["bash", scriptPath()]);
      expect(stderr).toHaveBeenCalledWith(expect.stringContaining(`package-checker: ${PACKAGE_CHECKER_TAG} (vendored, pinned)`));
    } finally {
      stderr.mockRestore();
    }
  });

  it("without ULTRASEC_PACKAGE_CHECKER_DEBUG, command() stays silent on stderr", () => {
    process.env.ULTRASEC_PACKAGE_CHECKER_PINNED = "1";
    const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    try {
      packageChecker.command!();
      expect(stderr).not.toHaveBeenCalled();
    } finally {
      stderr.mockRestore();
    }
  });

  it("packageChecker.command() end-to-end: resolves through the same logic and returns a runnable cmd", async () => {
    const newTag = "v99.0.0";
    const body = "#!/usr/bin/env bash\necho fixture\n";
    fx = await startFixtureServer({
      "repos/maxgfr/package-checker.sh/releases/latest": JSON.stringify({ tag_name: newTag }),
      [`maxgfr/package-checker.sh/${newTag}/script.sh`]: body,
    });
    process.env.ULTRASEC_PACKAGE_CHECKER_API = fx.base;
    process.env.ULTRASEC_PACKAGE_CHECKER_RAW = fx.base;
    const cmd = packageChecker.command!();
    expect(cmd).not.toBeNull();
    expect(cmd![0]).toBe("bash");
    expect(cmd![1]).toMatch(/script-v99\.0\.0-[0-9a-f]{12}\.sh$/);
  });
});

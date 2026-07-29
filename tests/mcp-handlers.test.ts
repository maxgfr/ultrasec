import { cpSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer, type JsonRpcMessage } from "../src/mcp/server.js";
import { callTool, ToolError } from "../src/mcp/handlers.js";
import { captureOutput, println, eprintln } from "../src/util.js";

// The handlers driven through the JSON-RPC core, in-process, against a real
// audit of a real vulnerable fixture. Nothing here mocks the engine: the point
// is that a tool name reaches the same command the CLI runs.
//
// Every scan is `offline`, so no test here touches the network.

const FIXTURE = resolve("tests/fixtures/vuln-express");
let REPO: string;
const temps: string[] = [];

beforeAll(async () => {
  REPO = mkdtempSync(join(tmpdir(), "usec-mcp-"));
  temps.push(REPO);
  cpSync(FIXTURE, REPO, { recursive: true });
  // Build the run the read tools need. Going through callTool also proves the
  // allowWrite gate lets a write tool through.
  await callTool("ultrasec_scan", { repo: REPO, offline: true, budget: "quick" }, { allowWrite: true });
}, 300_000);

afterAll(() => {
  for (const d of temps) rmSync(d, { recursive: true, force: true });
});

const server = createServer();

async function rpc(msg: Omit<JsonRpcMessage, "jsonrpc">): Promise<JsonRpcMessage | undefined> {
  let out: JsonRpcMessage | undefined;
  await server.handle({ jsonrpc: "2.0", ...msg }, (m) => {
    out = m;
  });
  return out;
}

async function call(name: string, args: Record<string, unknown>): Promise<JsonRpcMessage> {
  return (await rpc({ id: 1, method: "tools/call", params: { name, arguments: args } }))!;
}

async function ok(name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
  const res = await call(name, args);
  const result = res.result as { content: { text: string }[]; isError?: boolean } | undefined;
  expect(res.error, `unexpected JSON-RPC error: ${JSON.stringify(res.error)}`).toBeUndefined();
  expect(result?.isError, `unexpected isError: ${result?.content?.[0]?.text}`).toBeFalsy();
  return JSON.parse(result!.content[0]!.text);
}

async function errorText(name: string, args: Record<string, unknown>): Promise<string> {
  const res = await call(name, args);
  const result = res.result as { content: { text: string }[]; isError?: boolean } | undefined;
  expect(result?.isError, "expected an isError tool result").toBe(true);
  return result!.content[0]!.text;
}

describe("the output sink", () => {
  // The property this whole server rests on: a command's printed output must be
  // collected, not written, because stdout carries JSON-RPC frames.
  it("collects what a command prints instead of writing it", async () => {
    const captured = await captureOutput(() => {
      println("to stdout");
      eprintln("to stderr");
      return 0;
    });
    expect(captured.result).toBe(0);
    expect(captured.stdout).toBe("to stdout");
    expect(captured.stderr).toBe("to stderr");
  });

  it("keeps two interleaved captures separate", async () => {
    // A module-level sink would fail this. AsyncLocalStorage follows the async
    // context, so each capture collects exactly its own output.
    const [a, b] = await Promise.all([
      captureOutput(async () => {
        println("a1");
        await new Promise((r) => setTimeout(r, 10));
        println("a2");
        return "a";
      }),
      captureOutput(async () => {
        await new Promise((r) => setTimeout(r, 5));
        println("b1");
        return "b";
      }),
    ]);
    expect(a.stdout).toBe("a1\na2");
    expect(b.stdout).toBe("b1");
  });
});

describe("lifecycle methods", () => {
  it("negotiates a protocol version and advertises all three primitives", async () => {
    const res = await rpc({ id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } });
    const r = res!.result as { protocolVersion: string; serverInfo: { name: string }; capabilities: unknown };
    expect(r.serverInfo.name).toBe("ultrasec");
    expect(r.capabilities).toEqual({
      tools: { listChanged: false },
      resources: { subscribe: false, listChanged: false },
      prompts: { listChanged: false },
    });
  });

  it("rejects an unknown method, an unknown tool and bad arguments as protocol errors", async () => {
    expect((await rpc({ id: 1, method: "resources/subscribe" }))!.error).toMatchObject({ code: -32601 });
    expect((await call("ultrasec_nope", {})).error).toMatchObject({ code: -32602 });
    expect((await call("ultrasec_dossier", { repo: REPO })).error).toMatchObject({ code: -32602 });
  });
});

describe("the audit tools", () => {
  it("lists candidate paths from the run the scan wrote", async () => {
    const res = await ok("ultrasec_paths", { repo: REPO });
    expect(res.ok).toBe(true);
    expect(res.exit_code).toBe(0);
  });

  it("maps the attack surface", async () => {
    const res = await ok("ultrasec_map", { repo: REPO });
    expect(res.ok).toBe(true);
  });

  it("reports which external scanners are installed, with no repo at all", async () => {
    const res = await ok("ultrasec_tools", {});
    expect(res.ok).toBe(true);
  });

  it("emits the triage and verify worklists", async () => {
    expect((await ok("ultrasec_triage", { repo: REPO })).ok).toBe(true);
    expect((await ok("ultrasec_verify", { repo: REPO })).ok).toBe(true);
  });

  it("gates citations with check", async () => {
    const res = await ok("ultrasec_check", { repo: REPO });
    // ok:false would be a verdict, not an error — either way it comes back as a
    // normal result carrying its exit code.
    expect(res.exit_code).toBeTypeOf("number");
    expect(res.ok).toBe(res.exit_code === 0);
  });
});

describe("read", () => {
  it("returns a line window and reports the real total", async () => {
    const res = await ok("ultrasec_read", { repo: REPO, path: "package.json", start_line: 1, end_line: 3 });
    expect(res.start_line).toBe(1);
    expect(String(res.content).split("\n").length).toBeLessThanOrEqual(3);
  });

  it("refuses a path outside the repo and its run", async () => {
    // Containment is the whole point: this server can be reached over HTTP.
    expect(await errorText("ultrasec_read", { repo: REPO, path: "/etc/passwd" })).toMatch(/outside the repo/);
  });
});

describe("guardrails", () => {
  it("refuses a write tool unless the server allows writes", async () => {
    await expect(callTool("ultrasec_scan", { repo: REPO })).rejects.toThrow(ToolError);
    await expect(callTool("ultrasec_clean", { repo: REPO })).rejects.toThrow(/--allow-write/);
  });

  it("refuses a repo that is not a directory, rather than reporting a clean audit", async () => {
    // The most dangerous possible silent failure for a security tool: a typo'd
    // path walking zero files and exiting 0 with "0 findings".
    const msg = await errorText("ultrasec_map", { repo: "/nope/not/here" });
    expect(msg).toMatch(/not a directory/);
    expect(msg).toMatch(/must not report a clean audit/);
  });

  it("names the missing STEP when there is no run", async () => {
    const bare = mkdtempSync(join(tmpdir(), "usec-bare-"));
    temps.push(bare);
    const msg = await errorText("ultrasec_paths", { repo: bare });
    expect(msg).toMatch(/no audit run/);
    expect(msg).toMatch(/ultrasec_scan/);
  });

  it("rejects a shard outside its shard count", async () => {
    expect(await errorText("ultrasec_verify", { repo: REPO, shards: 2, shard: 5 })).toMatch(/`shard` must be between 0 and 1/);
  });

  it("uses the server's default repo when the caller omits one", async () => {
    const withDefault = createServer({ defaultRun: REPO });
    let out: JsonRpcMessage | undefined;
    await withDefault.handle({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "ultrasec_paths", arguments: {} } }, (m) => {
      out = m;
    });
    const result = out!.result as { content: { text: string }[]; isError?: boolean };
    expect(result.isError).toBeFalsy();
    expect(JSON.parse(result.content[0]!.text).ok).toBe(true);
  });
});

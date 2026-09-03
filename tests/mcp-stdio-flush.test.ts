import { Readable, Writable } from "node:stream";
import { describe, expect, it } from "vitest";
import { runStdioServer } from "../src/mcp/stdio.js";

describe("MCP stdio output", () => {
  it("waits for a backpressured response to flush before the server exits", async () => {
    const input = Readable.from([
      `${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } })}\n`,
      `${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" })}\n`,
    ]);
    let output = "";
    const slowOutput = new Writable({
      highWaterMark: 1,
      write(chunk, _encoding, callback) {
        setTimeout(() => {
          output += chunk.toString();
          callback();
        }, 5);
      },
    });

    await runStdioServer({ input, output: slowOutput, captureStdout: true });

    const frames = output
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    expect(frames).toHaveLength(2);
    expect(frames[1].result.tools.length).toBeGreaterThan(10);
  });
});

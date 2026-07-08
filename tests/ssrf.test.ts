import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { findSinks } from "../src/catalog.js";
import { langForFile } from "../src/lang.js";
import { scanRepo } from "../src/scan.js";
import { buildGraph } from "../src/graph.js";
import { enumerateTaint } from "../src/taint.js";

// Eval P0.2: the SSRF rule keyed on the CALLEE only, so bare `fetch(u)`/`axios(u)`
// fired but the dominant real-world forms `axios.get(u)` / `http.get(u)` /
// `requests.get(u)` (callee `get`, receiver `axios`) matched nothing. A new
// receiver-gated rule recognises the member-call forms without flagging a bare
// `get(u)` (which would explode false positives on generic getters).

const js = langForFile("app.js")!;

describe("SSRF member-call sinks (CWE-918)", () => {
  it("recognises axios.get / http.get / session.post as SSRF", () => {
    expect(findSinks(js, [{ callee: "get", receiver: "axios", line: 1 }]).some((h) => h.kind === "ssrf" && h.cwe === "CWE-918")).toBe(true);
    expect(findSinks(js, [{ callee: "get", receiver: "http", line: 1 }]).some((h) => h.kind === "ssrf")).toBe(true);
    expect(findSinks(js, [{ callee: "post", receiver: "session", line: 1 }]).some((h) => h.kind === "ssrf")).toBe(true);
  });

  it("recognises Python requests.get / httpx.post as SSRF", () => {
    const py = langForFile("app.py")!;
    expect(findSinks(py, [{ callee: "get", receiver: "requests", line: 1 }]).some((h) => h.kind === "ssrf")).toBe(true);
    expect(findSinks(py, [{ callee: "post", receiver: "httpx", line: 1 }]).some((h) => h.kind === "ssrf")).toBe(true);
  });

  it("still recognises the bare forms (fetch, axios, got)", () => {
    expect(findSinks(js, [{ callee: "fetch", line: 1 }]).some((h) => h.kind === "ssrf")).toBe(true);
    expect(findSinks(js, [{ callee: "axios", line: 1 }]).some((h) => h.kind === "ssrf")).toBe(true);
    expect(findSinks(js, [{ callee: "got", line: 1 }]).some((h) => h.kind === "ssrf")).toBe(true);
  });

  it("does NOT flag a bare get(u) with no receiver (avoids generic-getter FPs)", () => {
    expect(findSinks(js, [{ callee: "get", line: 1 }]).some((h) => h.kind === "ssrf")).toBe(false);
  });

  it("does NOT flag a member call on an unrelated receiver (map.get, cache.get)", () => {
    expect(findSinks(js, [{ callee: "get", receiver: "map", line: 1 }]).some((h) => h.kind === "ssrf")).toBe(false);
    expect(findSinks(js, [{ callee: "get", receiver: "cache", line: 1 }]).some((h) => h.kind === "ssrf")).toBe(false);
  });

  it("enumerates a cross-file axios.get SSRF flow end-to-end", () => {
    const repo = mkdtempSync(join(tmpdir(), "ultrasec-ssrf-"));
    mkdirSync(join(repo, "src"), { recursive: true });
    writeFileSync(
      join(repo, "src", "server.js"),
      [
        "const { fetchUrl } = require('./http-client');",
        "function handler(req) {",
        "  const target = req.query.url;",
        "  return fetchUrl(target);",
        "}",
        "module.exports = { handler };",
        "",
      ].join("\n"),
    );
    writeFileSync(
      join(repo, "src", "http-client.js"),
      ["const axios = require('axios');", "function fetchUrl(u) {", "  return axios.get(u);", "}", "module.exports = { fetchUrl };", ""].join("\n"),
    );
    const scan = scanRepo(repo);
    const { findings } = enumerateTaint(scan, buildGraph(scan), { maxDepth: 8, maxCandidates: 1000 });
    const ssrf = findings.find((f) => f.cwe === "CWE-918");
    expect(ssrf, "expected a CWE-918 candidate").toBeDefined();
    // Cross-file: source in server.js, sink in http-client.js.
    const files = new Set((ssrf!.path ?? []).map((p) => p.file));
    expect(files.size).toBeGreaterThan(1);
  });
});

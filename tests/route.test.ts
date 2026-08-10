import { describe, it, expect, vi } from "vitest";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { classifyTarget, ROUTE_TABLE, runRoute } from "../src/commands/route.js";
import { parseArgs } from "../src/util.js";

// WS-C: the `route` triage desk for out-of-scope targets. Advisory only — it
// classifies a filename/URL string and prints methodology + tools; it never
// executes anything, touches the network, or reads the target. In scope it
// routes back to `scan` / `probe`.

describe("classifyTarget", () => {
  it("routes out-of-scope file shapes to their toolkit", () => {
    expect(classifyTarget("app.apk")).toMatchObject({ kind: "external", entry: { id: "android-apk" } });
    expect(classifyTarget("./libs/native.so")).toMatchObject({ kind: "external", entry: { id: "native-binary" } });
    expect(classifyTarget("capture.pcap")).toMatchObject({ kind: "external", entry: { id: "network-capture" } });
    expect(classifyTarget("ext.crx")).toMatchObject({ kind: "external", entry: { id: "browser-extension" } });
    expect(classifyTarget("firmware.img")).toMatchObject({ kind: "external", entry: { id: "firmware" } });
  });

  it("routes a live host to probe and source/dir to scan (in scope)", () => {
    expect(classifyTarget("https://app.example.com")).toMatchObject({ kind: "probe" });
    expect(classifyTarget("http://10.0.0.1:8080/x")).toMatchObject({ kind: "probe" });
    expect(classifyTarget("src/index.ts")).toEqual({ kind: "scan" });
    expect(classifyTarget("./my-repo")).toEqual({ kind: "scan" }); // no extension → a directory
    expect(classifyTarget("app.py")).toEqual({ kind: "scan" });
  });

  it("treats IaC/config as in-scope — the cloud & web-config detectors read them", () => {
    // Measured on kubernetes-goat / terragoat: routing a k8s manifest or a .tf to
    // an external toolkit would send the user away from the tool that covers it.
    for (const t of ["deployment.yaml", "k8s/pod.yml", "main.tf", "vars.tfvars", "policy.json", "Dockerfile", "./svc/Dockerfile"]) {
      expect(classifyTarget(t), t).toEqual({ kind: "scan" });
    }
  });

  it("falls back to a general guide for an unrecognized extension", () => {
    expect(classifyTarget("mystery.zzz")).toMatchObject({ kind: "unknown", ext: "zzz" });
  });

  it("every ROUTE_TABLE entry has tools with a name and a url", () => {
    for (const e of ROUTE_TABLE) {
      expect(e.tools.length).toBeGreaterThan(0);
      for (const t of e.tools) expect(t.name && typeof t.url === "string").toBeTruthy();
    }
  });
});

describe("runRoute", () => {
  const capture = () => {
    const out: string[] = [];
    const so = vi.spyOn(process.stdout, "write").mockImplementation((s: unknown) => (out.push(String(s)), true));
    const se = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    return { text: () => out.join(""), restore: () => (so.mockRestore(), se.mockRestore()) };
  };

  it("exits 2 with usage when no target is given", () => {
    const c = capture();
    expect(runRoute(parseArgs(["route"]))).toBe(2);
    c.restore();
  });

  it("prints methodology + external tools for an out-of-scope target", () => {
    const c = capture();
    expect(runRoute(parseArgs(["route", "app.apk"]))).toBe(0);
    const t = c.text();
    c.restore();
    expect(t).toMatch(/out of scope/);
    expect(t).toMatch(/jadx/);
    expect(t).toMatch(/runs nothing|advisory|does NOT run/i);
  });

  it("routes a live URL back to `ultrasec probe`", () => {
    const c = capture();
    runRoute(parseArgs(["route", "https://app.example.com"]));
    const t = c.text();
    c.restore();
    expect(t).toMatch(/ultrasec probe https:\/\/app\.example\.com --i-own-this/);
  });

  it("routes source/a repo back to `ultrasec scan`", () => {
    const c = capture();
    runRoute(parseArgs(["route", "./my-repo"]));
    const t = c.text();
    c.restore();
    expect(t).toMatch(/ultrasec scan --repo \.\/my-repo/);
  });

  it("--json emits a structured, out-of-scope result", () => {
    const c = capture();
    runRoute(parseArgs(["route", "bin.so", "--json"]));
    const t = c.text();
    c.restore();
    const j = JSON.parse(t) as { type: string; inScope: boolean; tools: unknown[] };
    expect(j.inScope).toBe(false);
    expect(j.tools.length).toBeGreaterThan(0);
  });

  it("--write emits ROUTE.md into --out and nothing elsewhere", () => {
    const out = mkdtempSync(join(tmpdir(), "ultrasec-route-"));
    const c = capture();
    expect(runRoute(parseArgs(["route", "app.apk", "--write", "--out", out]))).toBe(0);
    c.restore();
    const p = join(out, "ROUTE.md");
    expect(existsSync(p)).toBe(true);
    expect(readFileSync(p, "utf8")).toMatch(/# ultrasec route — app\.apk/);
    // advisory: it must never write a findings.json / dossier
    expect(existsSync(join(out, "findings.json"))).toBe(false);
  });
});

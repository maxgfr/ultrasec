import { describe, it, expect } from "vitest";
import { trufflehog } from "../src/tools/trufflehog.js";
import { guarddog } from "../src/tools/guarddog.js";
import { cppcheck } from "../src/tools/cppcheck.js";
import { ADAPTERS } from "../src/tools/index.js";
import { TOOLS } from "../src/tools/registry.js";

describe("trufflehog — verification is the point", () => {
  const raw = [
    '{"SourceMetadata":{"Data":{"Filesystem":{"file":"src/config.js","line":11}}},"DetectorName":"AWS","Verified":true,"Raw":"AKIA…"}',
    "2:04PM INF scanning...",
    '{"SourceMetadata":{"Data":{"Filesystem":{"file":"src/x.py","line":0}}},"DetectorName":"Slack","Verified":true}',
  ].join("\n");

  it("parses JSON Lines and ignores the log lines sharing the stream", () => {
    expect(trufflehog.parse(raw, "/repo")).toHaveLength(2);
  });

  it("rates a VERIFIED credential critical — it is an active exposure, not a lint", () => {
    const [f] = trufflehog.parse(raw, "/repo");
    expect(f!.severity).toBe("critical");
    expect(f!.verified).toBe(true);
  });

  it("converts TruffleHog's 0-based filesystem line to a 1-based citation", () => {
    // Off by one here means every citation fails the grounding gate.
    const fs = trufflehog.parse(raw, "/repo");
    expect(fs[0]!.sink?.line).toBe(12);
    expect(fs[1]!.sink?.line).toBe(1);
  });

  it("needs the network, so --offline skips it rather than reporting a clean run", () => {
    expect(trufflehog.network).toBe(true);
  });

  it("returns nothing on empty input instead of throwing", () => {
    expect(trufflehog.parse("", "/repo")).toEqual([]);
  });
});

describe("guarddog — the class no CVE scanner sees", () => {
  const raw = JSON.stringify({
    package: "reqeusts",
    version: "1.0.0",
    severity: "high",
    results: { "code-execution": ["setup.py calls os.system"], typosquatting: "similar to requests", "empty-information": [] },
  });

  it("emits one finding per matched rule, skipping rules with no match", () => {
    const fs = guarddog.parse(raw, "/repo");
    expect(fs).toHaveLength(2);
    expect(fs.map((f) => f.title).join(" ")).toMatch(/typosquatting/);
  });

  it("files them as CWE-506 with LOW confidence — these are behavioural heuristics", () => {
    const fs = guarddog.parse(raw, "/repo");
    expect(fs.every((f) => f.cwe === "CWE-506")).toBe(true);
    expect(fs.every((f) => f.confidence === "low")).toBe(true);
  });

  it("carries the package identity so the correlator can merge it", () => {
    expect(guarddog.parse(raw, "/repo")[0]!.pkg).toBe("reqeusts");
  });

  it("survives malformed output", () => {
    expect(guarddog.parse("not json", "/repo")).toEqual([]);
    expect(guarddog.parse("", "/repo")).toEqual([]);
  });
});

describe("cppcheck — diagnostics arrive on stderr", () => {
  const raw = [
    "src/buf.c\t42\t9\terror\tbufferAccessOutOfBounds\tBuffer is accessed out of bounds: buf",
    "Checking src/buf.c ...",
    "src/m.c\t7\t1\twarning\tmemleak\tMemory leak: p",
  ].join("\n");

  it("declares the stderr capture, without which it reports a clean run on buggy code", () => {
    // The silent-false-negative case: parse stdout and get "".
    expect(cppcheck.stderr).toBe(true);
  });

  it("parses the tab template and skips progress lines", () => {
    expect(cppcheck.parse(raw, "/repo")).toHaveLength(2);
  });

  it("maps ids to CWEs so the report groups them with the taint findings", () => {
    const fs = cppcheck.parse(raw, "/repo");
    expect(fs[0]!.cwe).toBe("CWE-125");
    expect(fs[1]!.cwe).toBe("CWE-401");
  });

  it("maps cppcheck severities onto the ultrasec scale", () => {
    const fs = cppcheck.parse(raw, "/repo");
    expect(fs[0]!.severity).toBe("high");
    expect(fs[1]!.severity).toBe("medium");
  });
});

describe("belt registration", () => {
  it("registers each new adapter and documents it", () => {
    for (const name of ["trufflehog", "guarddog", "cppcheck"]) {
      expect(
        ADAPTERS.some((a) => a.name === name),
        `${name} adapter`,
      ).toBe(true);
      expect(
        TOOLS.some((t) => t.name === name),
        `${name} registry entry`,
      ).toBe(true);
    }
  });
});

describe("guarddog — invocation shape", () => {
  it("puts the ecosystem FIRST, which is where its CLI expects it", () => {
    // `guarddog verify <path> … npm` is a usage error, and a usage error exiting
    // non-zero is indistinguishable from "tool not installed" in the tool status.
    const argv = guarddog.argv(process.cwd());
    expect(argv[1]).toBe("verify");
    expect(["npm", "pypi", "go", "github_action"]).toContain(argv[0]);
  });

  it("is native-only, so docker cannot silently audit the wrong ecosystem", () => {
    expect(guarddog.dockerImage).toBeUndefined();
  });
});

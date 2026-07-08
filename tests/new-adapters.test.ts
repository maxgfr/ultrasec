import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { bandit } from "../src/tools/bandit.js";
import { gosec } from "../src/tools/gosec.js";
import { checkov } from "../src/tools/checkov.js";
import { hadolint } from "../src/tools/hadolint.js";
import { kingfisher } from "../src/tools/kingfisher.js";
import { check } from "../src/check.js";
import type { Dossier } from "../src/store.js";

const fix = (name: string) => readFileSync(join(import.meta.dirname, "fixtures", "tool-output", name), "utf8");

describe("bandit adapter", () => {
  const f = bandit.parse(fix("bandit.json"), "/repo");
  it("maps a HIGH Python idiom with CWE and confidence", () => {
    expect(f).toHaveLength(1);
    expect(f[0]!.category).toBe("sast");
    expect(f[0]!.severity).toBe("high");
    expect(f[0]!.confidence).toBe("high");
    expect(f[0]!.cwe).toBe("CWE-78");
    expect(f[0]!.sink).toEqual({ file: "app/run.py", line: 12 });
    expect(f[0]!.tool).toBe("bandit");
  });
  it("tolerates empty / missing results", () => {
    expect(bandit.parse("{}", "/repo")).toEqual([]);
    expect(bandit.parse("", "/repo")).toEqual([]);
  });
});

describe("gosec adapter", () => {
  const f = gosec.parse(fix("gosec.json"), "/repo");
  it("parses string line/cwe, sets severity and location", () => {
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe("high");
    expect(f[0]!.cwe).toBe("CWE-78");
    expect(f[0]!.sink).toEqual({ file: "cmd/main.go", line: 27 });
    expect(f[0]!.title).toContain("G204");
  });
});

describe("checkov adapter", () => {
  const f = checkov.parse(fix("checkov.json"), "/repo");
  it("strips the leading slash, defaults null severity to medium, keeps guideline", () => {
    expect(f).toHaveLength(1);
    expect(f[0]!.category).toBe("config");
    expect(f[0]!.severity).toBe("medium");
    expect(f[0]!.sink).toEqual({ file: "main.tf", line: 1 });
    expect(f[0]!.references).toContain(
      "https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/s3-policies/s3-1-acl-read-permissions-everyone",
    );
  });
  it("tolerates an array of framework blocks and empty input", () => {
    const arr = `[${fix("checkov.json")}]`;
    expect(checkov.parse(arr, "/repo")).toHaveLength(1);
    expect(checkov.parse("{}", "/repo")).toEqual([]);
  });

  // Eval P1.4: a whole-file/config check normalizes to file_line_range [0,0].
  // The parser keeps line 0 (a file-scoped citation) and the grounding gate
  // accepts it — a fresh --docker scan must not fail its own gate on config findings.
  it("keeps line 0 for a whole-file config finding, and the grounding gate accepts it", () => {
    const raw = JSON.stringify({
      results: {
        failed_checks: [{ check_id: "CKV_DOCKER_2", check_name: "Ensure HEALTHCHECK", file_path: "/Dockerfile", file_line_range: [0, 0], severity: null }],
      },
    });
    const parsed = checkov.parse(raw, "/repo");
    expect(parsed[0]!.sink).toEqual({ file: "Dockerfile", line: 0 });

    const repo = join(import.meta.dirname, "fixtures", "vuln-express");
    // Cite an existing file at line 0 (file-scoped) — the gate passes on existence.
    const finding = { ...parsed[0]!, status: "confirmed" as const, sink: { file: "package.json", line: 0 } };
    const d: Dossier = {
      manifest: {
        version: "0",
        schemaVersion: 5,
        repo,
        generatedNote: "",
        languages: [],
        toolsRun: [],
        counts: { findings: 1, bySeverity: { critical: 0, high: 0, medium: 1, low: 0, info: 0 } },
      },
      findings: [finding],
      graph: { files: [], edges: [], symbolDefs: {} },
    };
    expect(check(d, { repo }).ok).toBe(true);
  });
});

describe("hadolint adapter", () => {
  const f = hadolint.parse(fix("hadolint.json"), "/repo");
  it("maps levels to severity and links DL rules to the wiki", () => {
    expect(f).toHaveLength(3);
    const err = f.find((x) => x.title.startsWith("DL3002"))!;
    expect(err.severity).toBe("high"); // error
    expect(err.references).toContain("https://github.com/hadolint/hadolint/wiki/DL3002");
    const warn = f.find((x) => x.title.startsWith("DL3008"))!;
    expect(warn.severity).toBe("medium"); // warning
    const sc = f.find((x) => x.title.startsWith("SC2086"))!;
    expect(sc.severity).toBe("low"); // info
    expect(sc.references).toBeUndefined(); // not a DL rule → no wiki link
    expect(err.category).toBe("config");
  });
  it("enumerate() finds Dockerfiles by convention", () => {
    const names = hadolint.enumerate!(join(import.meta.dirname, "fixtures")); // no Dockerfiles under fixtures
    expect(Array.isArray(names)).toBe(true);
  });
});

describe("kingfisher adapter (SARIF)", () => {
  const f = kingfisher.parse(fix("kingfisher.sarif"), "/repo");
  it("maps a secret with default CWE-798 and high severity", () => {
    expect(f).toHaveLength(1);
    expect(f[0]!.category).toBe("secret");
    expect(f[0]!.severity).toBe("high");
    expect(f[0]!.cwe).toBe("CWE-798");
    expect(f[0]!.sink).toEqual({ file: "config/prod.env", line: 4 });
    expect(f[0]!.tool).toBe("kingfisher");
  });
});

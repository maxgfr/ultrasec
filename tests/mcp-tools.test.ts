import { describe, it, expect } from "vitest";
import { TOOLS, WRITE_TOOLS, TOOL_META, annotationsFor, toolsFor } from "../src/mcp/tools.js";
import { validateArgs } from "../src/mcp/protocol.js";
import { COMMAND_HANDLERS } from "../src/commands/registry.js";
import { SEVERITIES } from "../src/types.js";

const ALL = [...TOOLS, ...WRITE_TOOLS];

describe("tool declarations", () => {
  it("names every tool consistently and uniquely", () => {
    const names = ALL.map((t) => t.name);
    expect(new Set(names).size).toBe(names.length);
    for (const n of names) expect(n).toMatch(/^ultrasec_[a-z_]+$/);
  });

  it("declares a well-formed object schema whose required properties exist", () => {
    for (const t of ALL) {
      expect(t.inputSchema.type, t.name).toBe("object");
      expect(Array.isArray(t.inputSchema.required), t.name).toBe(true);
      for (const r of t.inputSchema.required) {
        expect(Object.keys(t.inputSchema.properties), `${t.name}.required lists "${r}"`).toContain(r);
      }
      for (const [key, spec] of Object.entries(t.inputSchema.properties)) {
        expect(spec.description, `${t.name}.${key} has no description`).toBeTruthy();
      }
    }
  });

  it("gives every tool a description that says what it is for", () => {
    for (const t of ALL) {
      expect(t.description.length, t.name).toBeGreaterThan(80);
      expect(t.title, t.name).toBeTruthy();
    }
  });

  it("keeps the severity enum in sync with what the engine accepts", () => {
    const paths = TOOLS.find((t) => t.name === "ultrasec_paths")!;
    expect([...paths.inputSchema.properties.severity!.enum!].sort()).toEqual([...SEVERITIES].sort());
  });

  it("says out loud, on every adjudication tool, that the engine only finds candidates", () => {
    // The single most important sentence in this server. A model that misses it
    // reports a candidate list as a findings list, which is the worst thing a
    // security tool can produce.
    for (const name of ["ultrasec_paths", "ultrasec_triage", "ultrasec_scan"]) {
      const t = ALL.find((x) => x.name === name)!;
      expect(t.description, name).toMatch(/CANDIDATES/);
    }
  });

  it("warns about wall-clock and defaults the scan budget down", () => {
    // An MCP client times out long before a thorough scan finishes.
    const scan = WRITE_TOOLS.find((t) => t.name === "ultrasec_scan")!;
    expect(scan.description).toMatch(/SLOW/);
    expect(scan.description).toMatch(/quick.*default/i);
    expect(scan.inputSchema.properties.budget!.enum).toEqual(["quick", "standard", "thorough"]);
  });

  it("declares an outputSchema only where the result shape is small and stable", () => {
    expect(ALL.filter((t) => t.outputSchema).map((t) => t.name)).toEqual(["ultrasec_read"]);
  });
});

describe("annotations", () => {
  // Asserted tool by tool: a new tool with no expected row fails here rather
  // than sliding in unannotated.
  const EXPECTED: Record<string, { readOnlyHint: boolean; openWorldHint: boolean; destructiveHint?: boolean; idempotentHint?: boolean }> = {
    ultrasec_map: { readOnlyHint: true, openWorldHint: false },
    ultrasec_paths: { readOnlyHint: true, openWorldHint: false },
    ultrasec_dossier: { readOnlyHint: true, openWorldHint: false },
    ultrasec_graph: { readOnlyHint: true, openWorldHint: false },
    ultrasec_triage: { readOnlyHint: true, openWorldHint: false },
    ultrasec_guards: { readOnlyHint: true, openWorldHint: false },
    ultrasec_verify: { readOnlyHint: true, openWorldHint: false },
    ultrasec_investigate: { readOnlyHint: true, openWorldHint: false },
    ultrasec_revalidate: { readOnlyHint: true, openWorldHint: false },
    ultrasec_check: { readOnlyHint: true, openWorldHint: false },
    ultrasec_render: { readOnlyHint: true, openWorldHint: false },
    ultrasec_tools: { readOnlyHint: true, openWorldHint: false },
    ultrasec_read: { readOnlyHint: true, openWorldHint: false },
    ultrasec_scan: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    ultrasec_clean: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
  };

  it("annotates every declared tool, and only declared tools", () => {
    expect(Object.keys(TOOL_META).sort()).toEqual(ALL.map((t) => t.name).sort());
    expect(Object.keys(EXPECTED).sort()).toEqual(ALL.map((t) => t.name).sort());
  });

  it("matches the expected hint matrix", () => {
    for (const [name, want] of Object.entries(EXPECTED)) {
      expect(annotationsFor(name), name).toEqual(want);
    }
  });

  it("marks exactly one tool destructive, and it is the one that deletes", () => {
    expect(ALL.filter((t) => TOOL_META[t.name]!.destructive).map((t) => t.name)).toEqual(["ultrasec_clean"]);
  });
});

describe("toolsFor", () => {
  it("hides the write tools unless the server was started with --allow-write", () => {
    const readOnly = toolsFor("2025-06-18").map((t) => t.name);
    expect(readOnly).not.toContain("ultrasec_scan");
    expect(readOnly).not.toContain("ultrasec_clean");
    expect(toolsFor("2025-06-18", { allowWrite: true }).map((t) => t.name)).toContain("ultrasec_scan");
  });

  it("gates rich fields and annotations on the negotiated protocol version", () => {
    const old = toolsFor("2024-11-05").find((t) => t.name === "ultrasec_read")!;
    expect(old.annotations).toBeUndefined();
    expect(old.title).toBeUndefined();

    const now = toolsFor("2025-06-18").find((t) => t.name === "ultrasec_read")!;
    expect(now.annotations).toBeTruthy();
    expect(now.outputSchema).toBeTruthy();
  });

  it("makes `repo` optional when the server has a default — but never for the destructive tool", () => {
    const withDefault = toolsFor("2025-06-18", { defaultRun: "/srv/app", allowWrite: true });
    for (const t of withDefault) {
      if (t.name === "ultrasec_clean") continue;
      if (!t.inputSchema.properties.repo) continue;
      expect(t.inputSchema.required, t.name).not.toContain("repo");
    }
    // A delete never inherits a repo the caller didn't name.
    expect(withDefault.find((t) => t.name === "ultrasec_clean")!.inputSchema.required).toContain("repo");
  });
});

describe("every tool maps to a command that exists", () => {
  it("names only real commands", () => {
    // The MCP surface is a subset of the CLI's twenty commands. This catches a
    // tool wired to a command that was renamed or removed.
    const expected: Record<string, string> = {
      ultrasec_map: "map",
      ultrasec_paths: "paths",
      ultrasec_dossier: "dossier",
      ultrasec_graph: "graph",
      ultrasec_triage: "triage",
      ultrasec_guards: "guards",
      ultrasec_verify: "verify",
      ultrasec_investigate: "investigate",
      ultrasec_revalidate: "revalidate",
      ultrasec_check: "check",
      ultrasec_render: "render",
      ultrasec_tools: "tools",
      ultrasec_read: "", // served directly, not by a command
      ultrasec_scan: "scan",
      ultrasec_clean: "clean",
    };
    expect(Object.keys(expected).sort()).toEqual(ALL.map((t) => t.name).sort());
    for (const cmd of Object.values(expected)) {
      if (!cmd) continue;
      expect(COMMAND_HANDLERS[cmd], `command "${cmd}" is gone`).toBeTypeOf("function");
    }
  });
});

describe("declared schemas accept what the handlers expect", () => {
  it("validates a representative call per tool", () => {
    const sample: Record<string, Record<string, unknown>> = {
      ultrasec_map: { repo: "/r", scope: ["src"], max_files: 100 },
      ultrasec_paths: { repo: "/r", kind: "sql", severity: "high" },
      ultrasec_dossier: { repo: "/r", id: "F-1" },
      ultrasec_graph: { repo: "/r", target: "src/a.ts", depth: 2 },
      ultrasec_triage: { repo: "/r" },
      ultrasec_guards: { repo: "/r" },
      ultrasec_verify: { repo: "/r", shards: 2, shard: 0 },
      ultrasec_investigate: { repo: "/r" },
      ultrasec_revalidate: { repo: "/r" },
      ultrasec_check: { repo: "/r", semantic: true, min_severity: "high" },
      ultrasec_render: { repo: "/r", narrative: "/r/.ultrasec/NARRATIVE.json" },
      ultrasec_tools: {},
      ultrasec_read: { repo: "/r", path: "src/a.ts", start_line: 1, end_line: 20 },
      ultrasec_scan: { repo: "/r", budget: "quick", offline: true, scope: ["src"] },
      ultrasec_clean: { repo: "/r", all: true },
    };
    for (const t of ALL) {
      expect(validateArgs(t.inputSchema, sample[t.name]!), t.name).toBeUndefined();
    }
  });

  it("rejects a missing required argument and an out-of-enum value", () => {
    const dossier = TOOLS.find((t) => t.name === "ultrasec_dossier")!;
    expect(validateArgs(dossier.inputSchema, { repo: "/r" })).toMatch(/`id` is required/);
    const paths = TOOLS.find((t) => t.name === "ultrasec_paths")!;
    expect(validateArgs(paths.inputSchema, { repo: "/r", severity: "catastrophic" })).toMatch(/severity/);
  });
});

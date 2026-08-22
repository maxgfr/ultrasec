import { SEVERITIES } from "../types.js";
import { ANNOTATIONS_SINCE, RICH_TOOLS_SINCE, type JsonSchema, type JsonSchemaProp, type ProtocolVersion } from "./protocol.js";

// What the server advertises. Pure data — nothing here imports the audit
// pipeline, so the declarations can be asserted in a test without scanning
// anything. handlers.ts is where these names become work.

export interface ToolDecl {
  name: string;
  description: string;
  inputSchema: JsonSchema;
  title?: string;
  outputSchema?: JsonSchema;
  annotations?: Record<string, boolean>;
}

const SEVERITY_ENUM = [...SEVERITIES];

const repoProp: JsonSchemaProp = { type: "string", description: "Absolute path to the repository root." };
const runProp: JsonSchemaProp = { type: "string", description: "The audit run directory (default: <repo>/.ultrasec)." };
const scopeProps: Record<string, JsonSchemaProp> = {
  scope: { type: "array", items: { type: "string" }, description: "Restrict the walk to these subtrees." },
  include: { type: "array", items: { type: "string" }, description: "Glob(s) to include." },
  exclude: { type: "array", items: { type: "string" }, description: "Glob(s) to skip." },
};

// The line every adjudication tool carries. It is the whole thesis of the
// skill, and a model that misses it treats a candidate list as a findings list.
const JUDGMENT_NOTE = "The engine finds CANDIDATES; you decide whether each is really reachable and exploitable.";
const RUN_NOTE = "Requires a run: scan the repo once with ultrasec_scan first.";

export const TOOLS: ToolDecl[] = [
  {
    name: "ultrasec_map",
    title: "Map the attack surface, cheaply",
    description:
      "Recon without a full audit: the repo's entry points, the untrusted-input sources and the dangerous sinks, with no network and no taint analysis. " +
      "Start here on a large repo — it is the fast way to see what is worth scanning before paying for ultrasec_scan.",
    inputSchema: {
      type: "object",
      properties: { repo: repoProp, out: runProp, ...scopeProps, max_files: { type: "number", description: "Stop after this many files." } },
      required: ["repo"],
    },
  },
  {
    name: "ultrasec_paths",
    title: "List the candidate source→sink chains",
    description:
      "The taint paths the scan found: each a chain from an untrusted input to a dangerous sink, across files. This is the audit's work-queue — read it in " +
      "severity order and adjudicate each one. " +
      JUDGMENT_NOTE +
      " " +
      RUN_NOTE,
    inputSchema: {
      type: "object",
      properties: {
        repo: repoProp,
        run: runProp,
        kind: { type: "string", description: "Keep only this sink kind (e.g. sql, command, path, ssrf, xss)." },
        severity: { type: "string", enum: SEVERITY_ENUM, description: "Keep only findings at this severity." },
      },
      required: ["repo"],
    },
  },
  {
    name: "ultrasec_dossier",
    title: "Grounding packet for one finding",
    description:
      "Everything you need to judge ONE finding: the real code along its taint path, the surrounding call graph, and what the engine believes about it. " +
      "Read this before calling a finding real or noise — the path alone is not evidence of exploitability. " +
      RUN_NOTE,
    inputSchema: {
      type: "object",
      properties: { repo: repoProp, run: runProp, id: { type: "string", description: "The finding id, from ultrasec_paths." } },
      required: ["repo", "id"],
    },
  },
  {
    name: "ultrasec_graph",
    title: "Call-graph neighbours of a file or symbol",
    description:
      "What links to and from a file or symbol. Use it when a dossier's taint path stops short and you need to see whether the data really reaches the sink " +
      "— or where else it goes. " +
      RUN_NOTE,
    inputSchema: {
      type: "object",
      properties: {
        repo: repoProp,
        run: runProp,
        target: { type: "string", description: "A repo-relative file path or a symbol name." },
        depth: { type: "number", description: "How many hops to follow (default 1)." },
      },
      required: ["repo", "target"],
    },
  },
  {
    name: "ultrasec_triage",
    title: "Build a noise/keep worklist",
    description:
      "Emit the candidate findings as a worklist for you to mark noise or keep, before spending real effort on them. The first pass of any audit: a scan " +
      "returns candidates, and most of them are not bugs. " +
      JUDGMENT_NOTE +
      " " +
      RUN_NOTE,
    inputSchema: { type: "object", properties: { repo: repoProp, run: runProp }, required: ["repo"] },
  },
  {
    name: "ultrasec_guards",
    title: "Find the request handlers nothing checks",
    description:
      "Cross every handler that reads request data against the markers visible in its scope, and list the ones with none. " +
      "This is the vulnerability that is an ABSENCE: a missing check has no line to point at, so no taint path and no scanner can reach it — " +
      "and it is where the worst findings of a real audit lived. `lens: auth` (the default) looks for authentication/authorization; " +
      "`lens: throttle` looks for rate limiting, and flags the handlers that authenticate, where the absence is credential stuffing and account enumeration. " +
      "When NO marker of the chosen kind appears anywhere in the tree, that is reported as ONE architectural fact rather than one finding per handler. " +
      "A marker in scope is a CANDIDATE, never a proof: read the handler and confirm the check runs before the object is touched. " +
      JUDGMENT_NOTE +
      " " +
      RUN_NOTE,
    inputSchema: {
      type: "object",
      properties: {
        repo: repoProp,
        run: runProp,
        lens: { type: "string", enum: ["auth", "throttle"], description: "Which absence to enumerate: authorization (default) or rate limiting." },
      },
      required: ["repo"],
    },
  },
  {
    name: "ultrasec_verify",
    title: "Build a claim-support worklist",
    description:
      "Go past 'the finding exists' to 'the evidence supports it'. Emits a claim-by-evidence worklist for you to adjudicate each as supported / partial / " +
      "refuted / unsupported. This is the adversarial pass — try to REFUTE each finding, and keep the ones that survive. " +
      RUN_NOTE,
    inputSchema: {
      type: "object",
      properties: {
        repo: repoProp,
        run: runProp,
        shards: { type: "number", description: "Split the worklist into this many shards, to adjudicate in parallel." },
        shard: { type: "number", description: "Which shard to emit, 0-based." },
      },
      required: ["repo"],
    },
  },
  {
    name: "ultrasec_investigate",
    title: "Worklist for the bugs no scanner finds",
    description:
      "The attack-surface regions worth reading by hand, for the vulnerability classes taint analysis cannot see: broken authorization and IDOR, business " +
      "logic, auth and JWT handling, crypto misuse, races. The engine cannot find these — it can only tell you where to look. " +
      RUN_NOTE,
    inputSchema: { type: "object", properties: { repo: repoProp, run: runProp }, required: ["repo"] },
  },
  {
    name: "ultrasec_revalidate",
    title: "Re-check findings against current code",
    description:
      "Emit a worklist to decide, per finding, whether it is still valid, already fixed, a false positive, or uncertain — by comparing the cited line " +
      "against what the code says now. Use it on a run that is no longer fresh. " +
      RUN_NOTE,
    inputSchema: { type: "object", properties: { repo: repoProp, run: runProp }, required: ["repo"] },
  },
  {
    name: "ultrasec_check",
    title: "The anti-hallucination gate",
    description:
      "Prove every [file:line] in the run resolves to a real line of the repository. A finding that cites a line that does not exist is an invented " +
      "finding, and this is what catches it. A result with ok:false is a real verdict, not a tool failure. " +
      RUN_NOTE,
    inputSchema: {
      type: "object",
      properties: {
        repo: repoProp,
        run: runProp,
        semantic: { type: "boolean", description: "Also fail when candidates remain unadjudicated." },
        min_severity: { type: "string", enum: SEVERITY_ENUM, description: "Only gate on findings at or above this severity." },
      },
      required: ["repo"],
    },
  },
  {
    name: "ultrasec_render",
    title: "Render the audit report",
    description:
      "Turn the run plus the narrative you wrote into SUMMARY.md, REPORT.md and a self-contained index.html. Run it after ultrasec_check passes — " +
      "rendering an unvalidated run just makes an ungrounded report look finished. " +
      RUN_NOTE,
    inputSchema: {
      type: "object",
      properties: { repo: repoProp, run: runProp, narrative: { type: "string", description: "Absolute path to the NARRATIVE.json you authored." } },
      required: ["repo"],
    },
  },
  {
    name: "ultrasec_tools",
    title: "Which external scanners are available",
    description:
      "Report which of the external scanners (Trivy, Semgrep, gitleaks, grype, osv-scanner, Syft…) are installed on this machine. A scan degrades " +
      "honestly without them rather than failing — this is how you find out what a given run could actually see. Reads nothing but the PATH.",
    inputSchema: { type: "object", properties: {}, required: [] },
  },
  {
    name: "ultrasec_read",
    title: "Read a file from the repo or the run",
    description:
      "Read a file, or a line range of one, from the audited repository or its run directory. Use it to widen the code around a finding, or to read a " +
      "worklist the audit wrote. Reads are confined to the repo and the run; anything else is your own file tool's job.",
    inputSchema: {
      type: "object",
      properties: {
        repo: repoProp,
        run: runProp,
        path: { type: "string", description: "Repo-relative path, or an absolute path inside the repo or its run directory." },
        start_line: { type: "number", description: "First line to return, 1-based (default 1)." },
        end_line: { type: "number", description: "Last line to return, inclusive (default: end of file, capped)." },
      },
      required: ["repo", "path"],
    },
    outputSchema: {
      type: "object",
      properties: {
        path: { type: "string" },
        start_line: { type: "number" },
        end_line: { type: "number" },
        total_lines: { type: "number" },
        truncated: { type: "boolean" },
        content: { type: "string" },
      },
      required: ["path", "start_line", "end_line", "total_lines", "truncated", "content"],
    },
  },
];

// Registered only when the server is started with --allow-write. Both of these
// write into the USER'S repository, which is where the read-only line is drawn.
export const WRITE_TOOLS: ToolDecl[] = [
  {
    name: "ultrasec_scan",
    title: "Run the cross-file security scan",
    description:
      "SLOW and WRITES TO THE REPO: walks the repository, builds the cross-file link graph, enumerates source→sink taint paths, runs whatever external " +
      "scanners are installed, and writes the run to <repo>/.ultrasec. Budget 'quick' is the default here (3 hops / 200 candidates) because 'standard' and " +
      "'thorough' take minutes and an MCP client will time out; raise it when you mean to wait. " +
      JUDGMENT_NOTE,
    inputSchema: {
      type: "object",
      properties: {
        repo: repoProp,
        out: runProp,
        budget: {
          type: "string",
          enum: ["quick", "standard", "thorough"],
          description: "quick (3 hops/200 candidates, the default here), standard (6/1000), thorough (8/5000). Higher budgets take minutes.",
        },
        ...scopeProps,
        max_files: { type: "number", description: "Stop after this many files." },
        max_candidates: { type: "number", description: "Cap taint candidates, overriding the budget." },
        max_depth: { type: "number", description: "Cap call-graph depth, overriding the budget." },
        offline: { type: "boolean", description: "Skip network enrichment (EPSS/KEV/CVE lookups)." },
        diff: { type: "string", description: "Scan only what changed since this git ref, plus its reverse dependents." },
        merge: { type: "boolean", description: "Fold this scan into the existing run instead of replacing it." },
      },
      required: ["repo"],
    },
  },
  {
    name: "ultrasec_clean",
    title: "Delete audit intermediates",
    description:
      "DESTRUCTIVE: removes the run's intermediate files from disk. With all:true it removes the whole run directory, including any worklist you have " +
      "not yet folded back in. There is no undo — re-scanning is the only way back.",
    inputSchema: {
      type: "object",
      properties: {
        repo: repoProp,
        run: runProp,
        all: { type: "boolean", description: "Remove the entire run directory, not just intermediates." },
        keep_output: { type: "boolean", description: "Keep the rendered report." },
      },
      required: ["repo"],
    },
  },
];

// Behavioural hints clients use to decide what needs a confirmation prompt.
//
// The read-only line is drawn at the USER'S repository. Every tool in TOOLS
// reads an existing run and writes nothing; `scan` creates files in the user's
// tree and `clean` removes them.
export const TOOL_META: Record<string, { write?: boolean; destructive?: boolean; idempotent?: boolean; openWorld?: boolean }> = {
  ultrasec_map: { openWorld: false },
  ultrasec_paths: { openWorld: false },
  ultrasec_dossier: { openWorld: false },
  ultrasec_graph: { openWorld: false },
  ultrasec_triage: { openWorld: false },
  ultrasec_guards: { openWorld: false },
  ultrasec_verify: { openWorld: false },
  ultrasec_investigate: { openWorld: false },
  ultrasec_revalidate: { openWorld: false },
  ultrasec_check: { openWorld: false },
  ultrasec_render: { openWorld: false },
  ultrasec_tools: { openWorld: false },
  ultrasec_read: { openWorld: false },
  // Reaches the network for CVE/EPSS/KEV enrichment unless `offline` is set,
  // and shells out to whatever scanners are installed.
  ultrasec_scan: { write: true, destructive: false, idempotent: false, openWorld: true },
  ultrasec_clean: { write: true, destructive: true, idempotent: true, openWorld: false },
};

export function annotationsFor(name: string): Record<string, boolean> | undefined {
  const meta = TOOL_META[name];
  if (!meta) return undefined;
  return {
    readOnlyHint: !meta.write,
    ...(meta.write ? { destructiveHint: meta.destructive === true, idempotentHint: meta.idempotent === true } : {}),
    openWorldHint: meta.openWorld === true,
  };
}

export interface ToolsForOptions {
  defaultRun?: string;
  allowWrite?: boolean;
}

// The tool list as one client should see it: gated on what the server was
// started with, and on how new the negotiated protocol is.
export function toolsFor(protocolVersion: ProtocolVersion, opts: ToolsForOptions = {}): ToolDecl[] {
  const base = opts.allowWrite ? [...TOOLS, ...WRITE_TOOLS] : TOOLS;
  const withAnnotations = protocolVersion >= ANNOTATIONS_SINCE;
  const withRich = protocolVersion >= RICH_TOOLS_SINCE;

  return base.map((t) => {
    const decl: ToolDecl = {
      name: t.name,
      description: t.description,
      // A destructive delete never inherits a repo the caller didn't name.
      inputSchema: t.name === "ultrasec_clean" ? t.inputSchema : applyDefaultRepo(t.inputSchema, opts.defaultRun),
    };
    if (withRich && t.title) decl.title = t.title;
    if (withRich && t.outputSchema) decl.outputSchema = t.outputSchema;
    if (withAnnotations) {
      const a = annotationsFor(t.name);
      if (a) decl.annotations = a;
    }
    return decl;
  });
}

// With a server-level default repo, `repo` stops being required and its
// description names the default — so a client can call every tool with no repo
// argument at all.
function applyDefaultRepo(schema: JsonSchema, defaultRepo?: string): JsonSchema {
  const existing = schema.properties.repo;
  if (!defaultRepo || !existing) return schema;
  return {
    type: "object",
    properties: {
      ...schema.properties,
      repo: { ...existing, description: `${existing.description} Optional — defaults to ${defaultRepo}.` },
    },
    required: schema.required.filter((r) => r !== "repo"),
  };
}

import type { Finding, Severity } from "../types.js";
import type { ToolAdapter } from "./run.js";
import { makeToolFinding } from "./normalize.js";
import { walk } from "../walk.js";

// cppcheck → C/C++ memory safety.
//
// The catalog's `buffer` rule (CWE-120) is explicitly a best-effort scaffold: it
// matches a handful of unbounded copy functions and cannot reason about lengths,
// lifetimes or ownership. On a real C codebase that is a thin slice of the class.
// cppcheck does the analysis the taint walk structurally cannot — use-after-free,
// off-by-one on an indexed write, an uninitialized read, a leak on an error path.
//
// It writes diagnostics to STDERR, which is why the adapter contract grew a
// `stderr` flag: parsing stdout here would return nothing and report a clean run
// on a codebase full of memory bugs.
//
// `--template` gives a stable, tab-separated line that survives version drift far
// better than the XML schema does.
const TEMPLATE = "{file}\t{line}\t{column}\t{severity}\t{id}\t{message}";

const SEV: Record<string, Severity> = {
  error: "high",
  warning: "medium",
  portability: "low",
  performance: "info",
  style: "info",
  information: "info",
};

/** The classes worth a CWE, so the report can group them with the taint findings. */
const CWE_BY_ID: Record<string, string> = {
  bufferAccessOutOfBounds: "CWE-125",
  arrayIndexOutOfBounds: "CWE-125",
  arrayIndexOutOfBoundsCond: "CWE-125",
  bufferOverflow: "CWE-120",
  strcpyOverrun: "CWE-120",
  sprintfOverlappingData: "CWE-628",
  doubleFree: "CWE-415",
  deallocuse: "CWE-416",
  useAfterFree: "CWE-416",
  uninitvar: "CWE-457",
  uninitdata: "CWE-457",
  memleak: "CWE-401",
  resourceLeak: "CWE-772",
  nullPointer: "CWE-476",
  nullPointerRedundantCheck: "CWE-476",
  integerOverflow: "CWE-190",
  invalidScanfFormatWidth: "CWE-787",
};

const C_EXT = /\.(?:c|cc|cpp|cxx|c\+\+|h|hh|hpp|hxx)$/i;

export const cppcheck: ToolAdapter = {
  name: "cppcheck",
  cacheable: true,
  category: "sast",
  stderr: true,
  applicable: (repo) => (walk(repo).some((f) => C_EXT.test(f.rel)) ? null : "no C/C++ sources"),
  argv: (target) => [
    "--quiet",
    "--enable=warning,portability",
    // Without this cppcheck emits an `information` diagnostic per unresolved
    // include on any non-trivial project, which drowns the real findings.
    "--suppress=missingInclude",
    "--suppress=missingIncludeSystem",
    "--inline-suppr",
    `--template=${TEMPLATE}`,
    target,
  ],
  parse(raw): Finding[] {
    const out: Finding[] = [];
    for (const line of (raw || "").split("\n")) {
      const t = line.trim();
      if (!t) continue;
      const [file, lineNo, , sev, id, ...rest] = t.split("\t");
      // Progress and summary lines have no tabs — skip anything that isn't a
      // diagnostic rather than inventing a finding out of it.
      if (!file || !id || rest.length === 0) continue;
      const message = rest.join("\t");
      out.push(
        makeToolFinding({
          tool: "cppcheck",
          category: "sast",
          ident: `${id}:${file}:${lineNo}`,
          title: `${id}: ${message}`.slice(0, 140),
          severity: SEV[String(sev).toLowerCase()] ?? "low",
          message: `cppcheck (${sev}/${id}): ${message}`,
          file,
          line: Number(lineNo) || 0,
          cwe: CWE_BY_ID[id!],
        }),
      );
    }
    return out;
  },
};

#!/usr/bin/env node

// src/types.ts
var VERSION = "0.0.0-development";

// src/util.ts
import { createHash } from "crypto";
function parseArgs(argv) {
  const _ = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i];
    if (tok.startsWith("--")) {
      const body = tok.slice(2);
      const eq = body.indexOf("=");
      if (eq >= 0) {
        flags[body.slice(0, eq)] = body.slice(eq + 1);
        continue;
      }
      const next = argv[i + 1];
      if (next !== void 0 && !next.startsWith("--")) {
        flags[body] = next;
        i++;
      } else {
        flags[body] = true;
      }
    } else {
      _.push(tok);
    }
  }
  return { _, flags };
}
function flagStr(args, name) {
  const v = args.flags[name];
  return typeof v === "string" ? v : void 0;
}
function flagBool(args, name) {
  const v = args.flags[name];
  return v === true || v === "true";
}
function byStr(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}
function eprintln(msg) {
  process.stderr.write(msg + "\n");
}
function println(msg) {
  process.stdout.write(msg + "\n");
}

// src/tools/registry.ts
import { execFileSync } from "child_process";
var TOOLS = [
  {
    name: "trivy",
    category: "dep",
    description: "All-in-one scanner: dependency CVEs (SCA), secrets, IaC/misconfig, licenses \u2014 across most ecosystems.",
    languages: ["*"],
    install: { brew: "brew install trivy", docker: "aquasec/trivy", url: "https://aquasecurity.github.io/trivy/" },
    runHint: "trivy fs --quiet --format json --scanners vuln,secret,misconfig <repo>",
    primary: true
  },
  {
    name: "osv-scanner",
    category: "dep",
    description: "Google OSV.dev dependency vulnerability scanner driven by lockfiles.",
    languages: ["*"],
    install: { brew: "brew install osv-scanner", go: "go install github.com/google/osv-scanner/cmd/osv-scanner@latest", url: "https://google.github.io/osv-scanner/" },
    runHint: "osv-scanner --format json -r <repo>"
  },
  {
    name: "grype",
    category: "dep",
    description: "Anchore SBOM-based vulnerability scanner (pairs with syft).",
    languages: ["*"],
    install: { brew: "brew install grype", url: "https://github.com/anchore/grype" },
    runHint: "grype dir:<repo> -o json"
  },
  {
    name: "opengrep",
    category: "sast",
    description: "Free fork of Semgrep with cross-function taint restored \u2014 pattern + dataflow SAST.",
    languages: ["*"],
    install: { url: "https://github.com/opengrep/opengrep", docker: "ghcr.io/opengrep/opengrep" },
    runHint: "opengrep scan --json --config auto <repo>",
    primary: true
  },
  {
    name: "semgrep",
    category: "sast",
    description: "Pattern + dataflow SAST (cross-file taint is a paid Pro feature).",
    languages: ["*"],
    install: { brew: "brew install semgrep", pip: "pipx install semgrep", url: "https://semgrep.dev/" },
    runHint: "semgrep scan --json --config auto <repo>"
  },
  {
    name: "gitleaks",
    category: "secret",
    description: "Hardcoded-secret detector (git history + working tree).",
    languages: ["*"],
    install: { brew: "brew install gitleaks", url: "https://github.com/gitleaks/gitleaks" },
    runHint: "gitleaks detect --report-format json --no-banner --source <repo>",
    primary: true
  },
  {
    name: "cargo-audit",
    category: "dep",
    description: "RustSec advisory scanner for Cargo.lock.",
    languages: ["rust"],
    install: { cargo: "cargo install cargo-audit", url: "https://rustsec.org/" },
    runHint: "cargo audit --json"
  },
  {
    name: "govulncheck",
    category: "dep",
    description: "Go vulnerability database scanner (reachability-aware).",
    languages: ["go"],
    install: { go: "go install golang.org/x/vuln/cmd/govulncheck@latest", url: "https://go.dev/security/vuln/" },
    runHint: "govulncheck -json ./..."
  },
  {
    name: "pip-audit",
    category: "dep",
    description: "PyPI advisory scanner for Python requirements/lockfiles.",
    languages: ["python"],
    install: { pip: "pipx install pip-audit", url: "https://pypi.org/project/pip-audit/" },
    runHint: "pip-audit -f json"
  },
  {
    name: "osv-scalibr",
    category: "dep",
    description: "Library scanner / SBOM extractor backing osv-scanner v2.",
    languages: ["*"],
    install: { url: "https://github.com/google/osv-scalibr" },
    runHint: "scalibr --result=json <repo>"
  },
  {
    name: "checkov",
    category: "config",
    description: "IaC/misconfig scanner (Terraform, k8s, Dockerfile, CloudFormation\u2026).",
    languages: ["*"],
    install: { pip: "pipx install checkov", url: "https://www.checkov.io/" },
    runHint: "checkov -d <repo> -o json"
  }
];
function detect(name) {
  try {
    const out = execFileSync(name, ["--version"], {
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 5e3
    }).toString().split("\n")[0]?.trim();
    return { installed: true, version: out || void 0 };
  } catch {
    try {
      execFileSync(process.platform === "win32" ? "where" : "which", [name], {
        stdio: ["ignore", "ignore", "ignore"],
        timeout: 5e3
      });
      return { installed: true };
    } catch {
      return { installed: false };
    }
  }
}
function toolStatuses() {
  return TOOLS.map((t) => ({ ...t, ...detect(t.name) })).sort((a, b) => byStr(a.name, b.name));
}

// src/commands/tools.ts
function bestInstallHint(t) {
  const i = t.install;
  return i.brew ?? i.pip ?? i.go ?? i.cargo ?? i.npx ?? i.docker ?? i.url ?? "";
}
function runTools(args) {
  const statuses = toolStatuses();
  if (flagBool(args, "json")) {
    println(JSON.stringify(statuses, null, 2));
    return 0;
  }
  const installed = statuses.filter((t) => t.installed);
  const missing = statuses.filter((t) => !t.installed);
  println(`ultrasec external scanners \u2014 ${installed.length}/${statuses.length} installed
`);
  const row = (t) => {
    const mark = t.installed ? "\u2713" : "\xB7";
    const star = t.primary ? "*" : " ";
    const ver = t.version ? `  (${t.version})` : "";
    return `  ${mark}${star} ${t.name.padEnd(14)} ${t.category.padEnd(7)} ${t.description}${ver}`;
  };
  if (installed.length) {
    println("INSTALLED");
    for (const t of installed) println(row(t));
    println("");
  }
  println("AVAILABLE TO INSTALL");
  for (const t of missing) {
    println(row(t));
    const hint = bestInstallHint(t);
    if (hint) println(`        \u2192 ${hint}`);
  }
  println("\n  * = primary tool for its category. \u2713 = on PATH.");
  println("  ultrasec runs the installed tools and normalizes their output; none are required.");
  return 0;
}

// src/walk.ts
import { readFileSync, readdirSync, statSync } from "fs";
import { join, relative, sep } from "path";
var DEFAULT_IGNORE_DIRS = /* @__PURE__ */ new Set([
  ".git",
  "node_modules",
  "vendor",
  "dist",
  "build",
  "out",
  "target",
  ".next",
  ".nuxt",
  "coverage",
  ".venv",
  "venv",
  "__pycache__",
  ".gradle",
  ".idea",
  ".vscode",
  ".ultrasec"
]);
var MAX_FILE_BYTES = 15e5;
function walk(root, opts = {}) {
  const ignore = opts.ignoreDirs ?? DEFAULT_IGNORE_DIRS;
  const maxBytes = opts.maxBytes ?? MAX_FILE_BYTES;
  const out = [];
  const visit = (dir) => {
    let entries;
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of entries.sort(byStr)) {
      const abs = join(dir, name);
      let st;
      try {
        st = statSync(abs);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (ignore.has(name)) continue;
        visit(abs);
      } else if (st.isFile()) {
        if (st.size > maxBytes) continue;
        const rel = relative(root, abs).split(sep).join("/");
        out.push({ rel, abs, bytes: st.size });
      }
    }
  };
  visit(root);
  return out.sort((a, b) => byStr(a.rel, b.rel));
}
function readText(abs) {
  try {
    return readFileSync(abs, "utf8");
  } catch {
    return "";
  }
}

// src/lang.ts
var SHARED_KEYWORDS = /* @__PURE__ */ new Set([
  "if",
  "for",
  "while",
  "switch",
  "catch",
  "return",
  "function",
  "await",
  "typeof",
  "instanceof",
  "new",
  "delete",
  "void",
  "in",
  "of",
  "do",
  "else",
  "case",
  "throw",
  "with",
  "super",
  "this",
  "and",
  "or",
  "not",
  "is"
]);
var ID = "[A-Za-z_$][\\w$]*";
var LANGS = [
  {
    id: "javascript",
    extensions: ["js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts"],
    defs: [
      { kind: "function", re: new RegExp(`(?:export\\s+)?(?:default\\s+)?(?:async\\s+)?function\\s*\\*?\\s+(${ID})`) },
      { kind: "function", re: new RegExp(`(?:export\\s+)?(?:const|let|var)\\s+(${ID})\\s*=\\s*(?:async\\s*)?(?:function\\b|\\([^)]*\\)\\s*=>|${ID}\\s*=>)`) },
      { kind: "class", re: new RegExp(`(?:export\\s+)?(?:default\\s+)?(?:abstract\\s+)?class\\s+(${ID})`) }
    ],
    imports: [
      /import\s+(?:[^'"]+\s+from\s+)?['"]([^'"]+)['"]/,
      /require\(\s*['"]([^'"]+)['"]\s*\)/,
      /import\(\s*['"]([^'"]+)['"]\s*\)/
    ],
    exportRule: "js"
  },
  {
    id: "python",
    extensions: ["py", "pyi"],
    defs: [
      { kind: "function", re: /^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)/ },
      { kind: "class", re: /^\s*class\s+([A-Za-z_]\w*)/ }
    ],
    imports: [/^\s*import\s+([\w.]+)/, /^\s*from\s+([\w.]+)\s+import/],
    exportRule: "leadingUnderscore",
    keywords: ["def", "class", "lambda", "elif", "except", "raise", "yield", "assert", "pass", "global", "nonlocal", "print"]
  },
  {
    id: "go",
    extensions: ["go"],
    defs: [
      { kind: "function", re: /^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)/ },
      { kind: "struct", re: /^\s*type\s+([A-Za-z_]\w*)\s+struct/ }
    ],
    imports: [/^\s*"([^"]+)"\s*$/, /import\s+(?:[\w.]+\s+)?"([^"]+)"/],
    exportRule: "capitalized",
    keywords: ["func", "go", "defer", "select", "range", "var", "const", "type", "package", "map", "make", "chan"]
  },
  {
    id: "java",
    extensions: ["java"],
    defs: [
      { kind: "class", re: /(?:class|interface|enum|record)\s+([A-Za-z_]\w*)/ },
      { kind: "method", re: /(?:public|private|protected)\s+(?:static\s+|final\s+|abstract\s+|synchronized\s+|native\s+)*[\w<>\[\].,?\s]+?\s+([A-Za-z_]\w*)\s*\([^;{]*\)\s*(?:throws[\w,.\s]+)?\{/ }
    ],
    imports: [/^\s*import\s+(?:static\s+)?([\w.]+)\s*;/],
    exportRule: "always",
    keywords: ["new", "class", "interface", "enum", "extends", "implements", "synchronized", "assert"]
  },
  {
    id: "ruby",
    extensions: ["rb"],
    defs: [
      { kind: "method", re: /^\s*def\s+(?:self\.)?([A-Za-z_]\w*[!?]?)/ },
      { kind: "class", re: /^\s*(?:class|module)\s+([A-Za-z_]\w*)/ }
    ],
    imports: [/require(?:_relative)?\s+['"]([^'"]+)['"]/],
    exportRule: "always",
    keywords: ["def", "end", "unless", "elsif", "begin", "rescue", "ensure", "yield", "module", "require", "puts", "raise"]
  },
  {
    id: "php",
    extensions: ["php"],
    defs: [
      { kind: "function", re: /function\s+([A-Za-z_]\w*)\s*\(/ },
      { kind: "class", re: /(?:class|trait|interface)\s+([A-Za-z_]\w*)/ }
    ],
    imports: [/(?:require|include)(?:_once)?\s*\(?\s*['"]([^'"]+)['"]/, /^\s*use\s+([\w\\]+)/],
    exportRule: "always",
    keywords: ["function", "class", "elseif", "foreach", "endif", "endforeach", "echo", "print", "isset", "empty", "array", "use", "namespace"]
  },
  {
    id: "rust",
    extensions: ["rs"],
    defs: [
      { kind: "function", re: /(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)/ },
      { kind: "struct", re: /(?:pub\s+)?(?:struct|enum|trait)\s+([A-Za-z_]\w*)/ }
    ],
    imports: [/^\s*use\s+([\w:]+)/],
    exportRule: "always",
    keywords: ["fn", "let", "match", "impl", "loop", "mut", "pub", "use", "mod", "struct", "enum", "trait", "unsafe", "move", "as", "ref"]
  },
  {
    id: "c_cpp",
    extensions: ["c", "h", "cc", "cpp", "cxx", "hpp", "hh", "hxx"],
    defs: [
      { kind: "function", re: /^[\w\s\*&:<>,]+?\s+\*?([A-Za-z_]\w*)\s*\([^;]*\)\s*\{/ },
      { kind: "struct", re: /^\s*(?:typedef\s+)?(?:struct|class|enum|union)\s+([A-Za-z_]\w*)/ }
    ],
    imports: [/^\s*#\s*include\s*[<"]([^>"]+)[>"]/],
    exportRule: "always",
    keywords: ["if", "for", "while", "switch", "return", "sizeof", "struct", "union", "enum", "static", "const", "typedef"]
  },
  {
    id: "csharp",
    extensions: ["cs"],
    defs: [
      { kind: "class", re: /(?:class|interface|struct|record|enum)\s+([A-Za-z_]\w*)/ },
      { kind: "method", re: /(?:public|private|protected|internal)\s+(?:static\s+|virtual\s+|override\s+|async\s+|sealed\s+)*[\w<>\[\].,?\s]+?\s+([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{/ }
    ],
    imports: [/^\s*using\s+(?:static\s+)?([\w.]+)\s*;/],
    exportRule: "always",
    keywords: ["new", "class", "interface", "struct", "using", "namespace", "async", "await", "var"]
  },
  {
    id: "kotlin",
    extensions: ["kt", "kts"],
    defs: [
      { kind: "function", re: /fun\s+(?:<[^>]+>\s+)?(?:[A-Za-z_][\w.]*\.)?([A-Za-z_]\w*)\s*\(/ },
      { kind: "class", re: /(?:class|interface|object|enum class)\s+([A-Za-z_]\w*)/ }
    ],
    imports: [/^\s*import\s+([\w.]+)/],
    exportRule: "always",
    keywords: ["fun", "val", "var", "when", "class", "object", "import", "package", "is", "as", "in"]
  },
  {
    id: "swift",
    extensions: ["swift"],
    defs: [
      { kind: "function", re: /func\s+([A-Za-z_]\w*)\s*[(<]/ },
      { kind: "class", re: /(?:class|struct|enum|protocol|actor)\s+([A-Za-z_]\w*)/ }
    ],
    imports: [/^\s*import\s+([\w.]+)/],
    exportRule: "always",
    keywords: ["func", "let", "var", "guard", "switch", "class", "struct", "enum", "import", "as", "is", "in", "case"]
  },
  {
    id: "scala",
    extensions: ["scala", "sc"],
    defs: [
      { kind: "function", re: /def\s+([A-Za-z_]\w*)/ },
      { kind: "class", re: /(?:class|trait|object|case class)\s+([A-Za-z_]\w*)/ }
    ],
    imports: [/^\s*import\s+([\w.]+)/],
    exportRule: "always",
    keywords: ["def", "val", "var", "match", "class", "trait", "object", "import", "case", "yield", "implicit"]
  },
  {
    id: "shell",
    extensions: ["sh", "bash", "zsh"],
    defs: [
      { kind: "function", re: /^\s*(?:function\s+)?([A-Za-z_]\w*)\s*\(\s*\)\s*\{/ }
    ],
    imports: [/^\s*(?:source|\.)\s+([^\s;]+)/],
    exportRule: "always",
    keywords: ["if", "then", "fi", "for", "do", "done", "while", "case", "esac", "echo", "function", "return", "local", "export"]
  },
  {
    id: "lua",
    extensions: ["lua"],
    defs: [
      { kind: "function", re: /function\s+(?:[A-Za-z_][\w.:]*\.)?([A-Za-z_]\w*)\s*\(/ },
      { kind: "function", re: /(?:local\s+)?([A-Za-z_]\w*)\s*=\s*function\s*\(/ }
    ],
    imports: [/require\s*\(?\s*['"]([^'"]+)['"]/],
    exportRule: "always",
    keywords: ["function", "local", "end", "then", "elseif", "repeat", "until", "do", "nil", "and", "or", "not", "print"]
  },
  {
    id: "elixir",
    extensions: ["ex", "exs"],
    defs: [
      { kind: "function", re: /^\s*def(?:p)?\s+([A-Za-z_]\w*[!?]?)/ },
      { kind: "class", re: /^\s*defmodule\s+([A-Za-z_][\w.]*)/ }
    ],
    imports: [/^\s*(?:import|alias|require|use)\s+([\w.]+)/],
    exportRule: "always",
    keywords: ["def", "defp", "defmodule", "do", "end", "fn", "case", "cond", "when", "import", "alias", "require", "use"]
  }
];
var byExt = /* @__PURE__ */ new Map();
for (const l of LANGS) for (const ext of l.extensions) byExt.set(ext, l);
function langForFile(rel) {
  const dot = rel.lastIndexOf(".");
  if (dot < 0) return void 0;
  return byExt.get(rel.slice(dot + 1).toLowerCase());
}
function isExported(rule, name, defLine, content) {
  switch (rule) {
    case "always":
      return true;
    case "leadingUnderscore":
      return !name.startsWith("_");
    case "capitalized":
      return /^[A-Z]/.test(name);
    case "js":
      if (/\bexport\b/.test(defLine)) return true;
      const reExports = new RegExp(`\\b(?:module\\.)?exports\\b[^\\n]*\\b${name}\\b`);
      return reExports.test(content);
  }
}
var callRe = /(?:([A-Za-z_$][\w$]*)\s*\.\s*)?([A-Za-z_$][\w$]*)\s*\(/g;
function extract(spec, content) {
  const lines = content.split(/\r?\n/);
  const symbols = [];
  const imports = [];
  const calls = [];
  const kw = /* @__PURE__ */ new Set([...SHARED_KEYWORDS, ...spec.keywords ?? []]);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const ln = i + 1;
    for (const d of spec.defs) {
      const m = d.re.exec(line);
      if (m && m[1]) {
        symbols.push({ name: m[1], kind: d.kind, line: ln, exported: isExported(spec.exportRule, m[1], line, content) });
      }
    }
    for (const re of spec.imports) {
      const m = re.exec(line);
      if (m && m[1]) imports.push({ spec: m[1], line: ln });
    }
    callRe.lastIndex = 0;
    let cm;
    while (cm = callRe.exec(line)) {
      const receiver = cm[1];
      const callee = cm[2];
      if (kw.has(callee)) continue;
      calls.push(receiver ? { callee, receiver, line: ln } : { callee, line: ln });
    }
  }
  const seen = /* @__PURE__ */ new Set();
  const uniqSyms = symbols.filter((s) => {
    const k = `${s.name}@${s.line}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  return { symbols: uniqSyms, imports, calls };
}

// src/scan.ts
function scanRepo(repo, opts = {}) {
  const files = [];
  for (const wf of walk(repo, { maxBytes: opts.maxBytes })) {
    const spec = langForFile(wf.rel);
    if (!spec) continue;
    const { symbols, imports, calls } = extract(spec, readText(wf.abs));
    files.push({ rel: wf.rel, lang: spec.id, symbols, imports, calls });
  }
  files.sort((a, b) => byStr(a.rel, b.rel));
  return { repo, files };
}

// src/resolve.ts
var CODE_EXTS = [
  "js",
  "jsx",
  "mjs",
  "cjs",
  "ts",
  "tsx",
  "mts",
  "cts",
  "py",
  "go",
  "java",
  "rb",
  "php",
  "rs",
  "c",
  "h",
  "cc",
  "cpp",
  "hpp",
  "cs",
  "kt",
  "kts",
  "swift",
  "scala",
  "sh",
  "lua",
  "ex",
  "exs"
];
var INDEX_BASENAMES = ["index", "__init__", "mod", "main"];
function dirOf(rel) {
  const i = rel.lastIndexOf("/");
  return i < 0 ? "" : rel.slice(0, i);
}
function normalize(path) {
  const parts = [];
  for (const seg of path.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") parts.pop();
    else parts.push(seg);
  }
  return parts.join("/");
}
function candidates(fromRel, spec) {
  const out = [];
  let base;
  if (spec.startsWith(".")) {
    base = normalize(`${dirOf(fromRel)}/${spec}`);
  } else if (spec.startsWith("/")) {
    base = normalize(spec);
  } else {
    base = spec.replace(/[.\\]/g, "/").replace(/^@/, "");
  }
  out.push(base);
  for (const ext of CODE_EXTS) out.push(`${base}.${ext}`);
  for (const idx of INDEX_BASENAMES) for (const ext of CODE_EXTS) out.push(`${base}/${idx}.${ext}`);
  return out;
}
function resolveImport(fromRel, spec, fileSet) {
  for (const c of candidates(fromRel, spec)) {
    if (fileSet.has(c)) return c;
  }
  return void 0;
}

// src/graph.ts
var keyOf = (e) => `${e.from}\0${e.to}\0${e.kind}\0${e.toSymbol ?? ""}`;
function add(map, e) {
  const k = keyOf(e);
  const prev = map.get(k);
  if (prev) prev.weight += e.weight;
  else map.set(k, { ...e });
}
function enclosingSymbol(symbols, line) {
  let best;
  for (const s of symbols) {
    if (s.line <= line && (!best || s.line > best.line)) best = s;
  }
  return best?.name;
}
function buildGraph(scan) {
  const fileSet = new Set(scan.files.map((f) => f.rel));
  const defs = /* @__PURE__ */ new Map();
  for (const f of scan.files) {
    for (const s of f.symbols) {
      if (!s.exported) continue;
      let set = defs.get(s.name);
      if (!set) defs.set(s.name, set = /* @__PURE__ */ new Set());
      set.add(f.rel);
    }
  }
  const symbolDefs = {};
  for (const [name, files] of defs) symbolDefs[name] = [...files].sort(byStr);
  const edgeMap = /* @__PURE__ */ new Map();
  for (const f of scan.files) {
    for (const imp of f.imports) {
      const to = resolveImport(f.rel, imp.spec, fileSet);
      if (to && to !== f.rel) add(edgeMap, { from: f.rel, to, kind: "import", weight: 1 });
    }
    for (const c of f.calls) {
      const targets = defs.get(c.callee);
      if (!targets || targets.size !== 1) continue;
      const to = [...targets][0];
      if (to === f.rel) continue;
      add(edgeMap, {
        from: f.rel,
        to,
        kind: "call",
        weight: 1,
        fromSymbol: enclosingSymbol(f.symbols, c.line),
        toSymbol: c.callee
      });
    }
  }
  const edges = [...edgeMap.values()].sort(
    (a, b) => byStr(a.from, b.from) || byStr(a.to, b.to) || byStr(a.kind, b.kind) || byStr(a.toSymbol ?? "", b.toSymbol ?? "")
  );
  return { files: [...fileSet].sort(byStr), edges, symbolDefs };
}

// src/neighbors.ts
function neighbors(graph, target, depth = 1) {
  const out = /* @__PURE__ */ new Map();
  const inn = /* @__PURE__ */ new Map();
  for (const e of graph.edges) {
    (out.get(e.from) ?? out.set(e.from, []).get(e.from)).push(e);
    (inn.get(e.to) ?? inn.set(e.to, []).get(e.to)).push(e);
  }
  const seen = /* @__PURE__ */ new Set([target]);
  const links = [];
  let frontier = [target];
  for (let d = 1; d <= depth; d++) {
    const next = [];
    for (const node of frontier) {
      for (const e of (out.get(node) ?? []).slice().sort((a, b) => byStr(a.to, b.to))) {
        if (seen.has(e.to)) continue;
        links.push({ node: e.to, direction: "out", kind: e.kind, weight: e.weight, depth: d, symbol: e.toSymbol });
        seen.add(e.to);
        next.push(e.to);
      }
      for (const e of (inn.get(node) ?? []).slice().sort((a, b) => byStr(a.from, b.from))) {
        if (seen.has(e.from)) continue;
        links.push({ node: e.from, direction: "in", kind: e.kind, weight: e.weight, depth: d, symbol: e.toSymbol });
        seen.add(e.from);
        next.push(e.from);
      }
    }
    frontier = next;
  }
  return { target, links };
}

// src/commands/graph.ts
function runGraph(args) {
  const repo = flagStr(args, "repo") ?? ".";
  const target = args._[1];
  const depth = Number(flagStr(args, "depth") ?? "1") || 1;
  if (!target) {
    eprintln("ultrasec graph: need a <file|symbol> argument. e.g. `graph src/db.js`");
    return 2;
  }
  const graph = buildGraph(scanRepo(repo));
  let node = target;
  if (!graph.files.includes(target)) {
    const defs = graph.symbolDefs[target];
    if (defs && defs.length === 1) node = defs[0];
    else if (defs && defs.length > 1) {
      eprintln(`ultrasec graph: symbol "${target}" is defined in ${defs.length} files: ${defs.join(", ")}`);
      return 2;
    } else {
      eprintln(`ultrasec graph: "${target}" is not a file node nor a known exported symbol.`);
      return 2;
    }
  }
  const result = neighbors(graph, node, depth);
  if (flagBool(args, "json")) {
    println(JSON.stringify(result, null, 2));
    return 0;
  }
  println(`${node}  (depth ${depth})`);
  if (!result.links.length) {
    println("  (no links)");
    return 0;
  }
  for (const l of result.links) {
    const arrow = l.direction === "out" ? "\u2192" : "\u2190";
    const sym = l.symbol ? ` [${l.symbol}]` : "";
    println(`  ${arrow} ${l.kind.padEnd(6)} ${l.node}${sym}  (d${l.depth})`);
  }
  return 0;
}

// src/cli.ts
var HELP = `ultrasec ${VERSION} \u2014 cross-file security audit (taint + AI + tool orchestration)

A deterministic, zero-dependency engine builds a cross-file/function link-graph,
enumerates candidate source\u2192sink taint paths, orchestrates best-in-class OSS
scanners, and prepares evidence packets; the AI does the security reasoning and
adversarially verifies each finding into a cited, tiered report.

USAGE
  ultrasec <command> [options]

COMMANDS
  scan       Scan a repo: detect stack, run available tools, build the link-graph,
             enumerate candidate taint paths, write the audit dossier.
  tools      List known external scanners, which are installed, and how to get them.
  graph      Show the links into/out of a file or symbol.
  paths      List candidate cross-file source\u2192sink chains.
  dossier    Print the grounding packet for one finding (real code + neighbours).
  verify     Emit / apply the adversarial finding\u2194evidence worklist.
  render     Render SUMMARY/REPORT/FULL.md + a self-contained index.html.
  check      Gate: every finding must cite resolvable [file:line] (anti-hallucination);
             --semantic also folds in the verify verdicts.

GLOBAL
  --help, -h     Show this help.
  --version, -v  Print the version.
  --json         Machine-readable output (where supported).

Run \`ultrasec <command> --help\` for command-specific options.
`;
var NOT_YET = {
  scan: "M2/M3",
  paths: "M3",
  dossier: "M3",
  verify: "M5",
  render: "M5",
  check: "M5"
};
async function dispatch(cmd, args) {
  switch (cmd) {
    case void 0:
    case "help":
      println(HELP);
      return 0;
    case "version":
      println(VERSION);
      return 0;
    case "tools":
      return runTools(args);
    case "graph":
      return runGraph(args);
    default:
      if (cmd in NOT_YET) {
        eprintln(`ultrasec: \`${cmd}\` is not implemented yet (planned in ${NOT_YET[cmd]}).`);
        return 2;
      }
      eprintln(`ultrasec: unknown command \`${cmd}\`. Run \`ultrasec --help\`.`);
      return 2;
  }
}
async function main() {
  const argv = process.argv.slice(2);
  const args = parseArgs(argv);
  if (flagBool(args, "help") || args.flags.h === true) {
    println(HELP);
    process.exit(0);
  }
  if (flagBool(args, "version") || args.flags.v === true) {
    println(VERSION);
    process.exit(0);
  }
  const code = await dispatch(args._[0], args);
  process.exit(code);
}
main().catch((err) => {
  eprintln(`ultrasec: ${err instanceof Error ? err.stack || err.message : String(err)}`);
  process.exit(1);
});

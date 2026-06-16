#!/usr/bin/env node

// src/types.ts
var VERSION = "0.0.0-development";
var SCHEMA_VERSION = 1;
var SEVERITIES = ["critical", "high", "medium", "low", "info"];

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
function shortHash(input, len = 12) {
  return createHash("sha256").update(input).digest("hex").slice(0, len);
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
    const definedHere = /* @__PURE__ */ new Set();
    for (const d of spec.defs) {
      const m = d.re.exec(line);
      if (m && m[1]) {
        definedHere.add(m[1]);
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
      if (!receiver && definedHere.has(callee)) continue;
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

// src/commands/scan.ts
import { resolve } from "path";

// src/taint.ts
import { join as join2 } from "path";

// src/catalog.ts
function appliesTo(languages, langId) {
  return languages.includes("*") || languages.includes(langId);
}
function cweUrl(cwe) {
  const n = cwe.replace(/\D/g, "");
  return `https://cwe.mitre.org/data/definitions/${n}.html`;
}
var SINKS = [
  {
    kind: "sql",
    cwe: "CWE-89",
    severity: "high",
    languages: ["javascript", "python", "go", "java", "php", "ruby", "rust", "csharp", "kotlin", "scala"],
    callees: ["query", "execute", "executeQuery", "executemany", "raw", "queryRaw", "unsafe", "exec_query"],
    title: "SQL injection",
    note: "Tainted data concatenated into a SQL statement. Verify it isn't a parameterized/prepared query."
  },
  {
    kind: "command",
    cwe: "CWE-78",
    severity: "critical",
    languages: ["*"],
    callees: ["exec", "execSync", "spawn", "spawnSync", "system", "popen", "Popen", "shell_exec", "passthru", "proc_open", "check_output", "check_call", "call", "run"],
    receivers: ["child_process", "subprocess", "os", "Runtime", "shell"],
    title: "OS command injection",
    note: "Tainted data in a shell command. Prefer argv-array exec (execFile/execve) over a shell string; verify no shell metacharacters reach a shell."
  },
  {
    kind: "code",
    cwe: "CWE-94",
    severity: "high",
    languages: ["*"],
    callees: ["eval", "Function", "runInThisContext", "runInContext", "compile", "execfile"],
    title: "Code injection / eval",
    note: "Tainted data evaluated as code. Almost never safe; verify the argument is a constant."
  },
  {
    kind: "path",
    cwe: "CWE-22",
    severity: "high",
    languages: ["*"],
    callees: ["readFile", "readFileSync", "writeFile", "writeFileSync", "createReadStream", "createWriteStream", "sendFile", "unlink", "open", "readdir", "appendFile"],
    title: "Path traversal",
    note: "Tainted data used as a filesystem path. Verify it's confined (basename/realpath + allow-list under a base dir)."
  },
  {
    kind: "ssrf",
    cwe: "CWE-918",
    severity: "high",
    languages: ["*"],
    callees: ["fetch", "request", "urlopen", "urlretrieve", "got", "axios", "openConnection"],
    title: "Server-side request forgery (SSRF)",
    note: "Tainted data used as a request URL/host. Verify the destination is allow-listed (no internal/metadata endpoints)."
  },
  {
    kind: "xss",
    cwe: "CWE-79",
    severity: "medium",
    languages: ["javascript", "python", "php", "ruby"],
    callees: ["send", "write", "end", "html", "render_template_string", "writeHead"],
    receivers: ["res", "response", "resp", "w"],
    title: "Cross-site scripting (reflected)",
    note: "Tainted data written to an HTML response. Verify it is contextually escaped before reaching the browser."
  },
  {
    kind: "deserialize",
    cwe: "CWE-502",
    severity: "high",
    languages: ["*"],
    callees: ["loads", "load", "unserialize", "deserialize", "readObject", "load_yaml", "full_load"],
    receivers: ["pickle", "yaml", "marshal", "cPickle", "ObjectInputStream"],
    title: "Insecure deserialization",
    note: "Tainted data deserialized into objects. Use a safe loader (yaml.safe_load, JSON) and never unpickle untrusted input."
  },
  {
    kind: "crypto",
    cwe: "CWE-327",
    severity: "medium",
    languages: ["*"],
    callees: ["md5", "sha1", "createCipher", "DES", "RC4"],
    title: "Weak cryptography",
    note: "Broken/weak primitive. Use SHA-256+/bcrypt/argon2 and authenticated encryption (AES-GCM)."
  },
  {
    kind: "redirect",
    cwe: "CWE-601",
    severity: "medium",
    languages: ["javascript", "python", "php", "ruby"],
    callees: ["redirect"],
    receivers: ["res", "response", "resp"],
    title: "Open redirect",
    note: "Tainted data used as a redirect target. Allow-list the destination or only permit relative paths."
  }
];
function findSinks(lang, calls) {
  const out = [];
  for (const c of calls) {
    for (const rule of SINKS) {
      if (!appliesTo(rule.languages, lang.id)) continue;
      if (!rule.callees.includes(c.callee)) continue;
      if (rule.receivers && c.receiver && !rule.receivers.includes(c.receiver)) {
        if (rule.kind !== "sql") continue;
      }
      out.push({
        line: c.line,
        callee: c.callee,
        receiver: c.receiver,
        kind: rule.kind,
        cwe: rule.cwe,
        severity: rule.severity,
        title: rule.title,
        note: rule.note
      });
      break;
    }
  }
  return out;
}
var SOURCES = [
  { kind: "http", languages: ["javascript"], re: /\breq(?:uest)?\s*\.\s*(?:query|body|params|headers|cookies|url|originalUrl|hostname|ip)\b/, title: "HTTP request input" },
  { kind: "http", languages: ["javascript"], re: /\bctx\s*\.\s*(?:request|query|params|body)\b/, title: "Koa/HTTP context input" },
  { kind: "http", languages: ["python"], re: /\brequest\s*\.\s*(?:args|form|values|json|data|files|cookies|headers|GET|POST)\b/, title: "HTTP request input" },
  { kind: "http", languages: ["php"], re: /\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b/, title: "HTTP superglobal input" },
  { kind: "http", languages: ["java", "kotlin", "scala"], re: /\.get(?:Parameter|Header|QueryString)\s*\(/, title: "Servlet request input" },
  { kind: "http", languages: ["ruby"], re: /\bparams\s*\[/, title: "Rails params input" },
  { kind: "http", languages: ["go"], re: /\br\s*\.\s*(?:URL|FormValue|PostFormValue|Header)\b/, title: "net/http request input" },
  { kind: "cli", languages: ["javascript"], re: /\bprocess\.argv\b/, title: "CLI argument" },
  { kind: "cli", languages: ["python"], re: /\bsys\.argv\b/, title: "CLI argument" },
  { kind: "cli", languages: ["go"], re: /\bos\.Args\b/, title: "CLI argument" },
  { kind: "env", languages: ["javascript"], re: /\bprocess\.env\b/, title: "Environment variable" },
  { kind: "env", languages: ["python"], re: /\bos\.(?:environ|getenv)\b/, title: "Environment variable" },
  { kind: "env", languages: ["*"], re: /\bgetenv\s*\(/, title: "Environment variable" },
  { kind: "stdin", languages: ["python"], re: /\binput\s*\(/, title: "Interactive/stdin input" }
];
function findSources(lang, content) {
  const out = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const rule of SOURCES) {
      if (!appliesTo(rule.languages, lang.id)) continue;
      const m = rule.re.exec(line);
      if (m) out.push({ line: i + 1, kind: rule.kind, match: m[0], title: rule.title });
    }
  }
  return out;
}
var SANITIZERS = [
  { kind: "sql", languages: ["*"], re: /\?|\$\d+|:\w+|%s|@\w+/, note: "looks parameterized (placeholder present)" },
  { kind: "command", languages: ["*"], re: /\bexecFile\b|\bexecvp?\b|shlex\.quote|escapeshellarg|\.split\(/, note: "argv-array / quoting present" },
  { kind: "path", languages: ["*"], re: /\bbasename\b|\brealpath\b|secure_filename|path\.resolve|startsWith\(/, note: "path-confinement helper present" },
  { kind: "xss", languages: ["*"], re: /\bescape(?:Html)?\b|sanitize|DOMPurify|bleach|markupsafe|escapeHTML/, note: "escaping/sanitizer present" },
  { kind: "deserialize", languages: ["*"], re: /safe_load|safeLoad|JSON\.parse/, note: "safe loader present" },
  { kind: "*", languages: ["*"], re: /\bparseInt\b|\bNumber\(|\bInteger\.parse|validator\.|\bz\.|Joi\.|\bisInt\b|\bUUID\b/, note: "type-coercion/validation present" }
];
function findSanitizers(lang, line, sinkKind) {
  const hints = [];
  for (const rule of SANITIZERS) {
    if (!appliesTo(rule.languages, lang.id)) continue;
    if (rule.kind !== "*" && rule.kind !== sinkKind) continue;
    if (rule.re.test(line)) hints.push(rule.note);
  }
  return hints;
}

// src/taint.ts
var MAX_DEPTH = 6;
var MAX_FINDINGS = 1e3;
function severityRank(s) {
  return SEVERITIES.indexOf(s);
}
function enclosingSymbol2(file, line) {
  let best;
  for (const s of file.symbols) {
    if (s.line <= line && (!best || s.line > best.line)) best = s;
  }
  return best?.name;
}
function truncate(s, n = 60) {
  return s.length > n ? s.slice(0, n - 1) + "\u2026" : s;
}
function enumerateTaint(scan, graph) {
  const byRel = new Map(scan.files.map((f) => [f.rel, f]));
  const contentCache = /* @__PURE__ */ new Map();
  const sourceCache = /* @__PURE__ */ new Map();
  const lineCache = /* @__PURE__ */ new Map();
  const content = (rel) => {
    let c = contentCache.get(rel);
    if (c === void 0) contentCache.set(rel, c = readText(join2(scan.repo, rel)));
    return c;
  };
  const lines = (rel) => {
    let l = lineCache.get(rel);
    if (!l) lineCache.set(rel, l = content(rel).split(/\r?\n/));
    return l;
  };
  const sourcesOf = (rel) => {
    let s = sourceCache.get(rel);
    if (!s) {
      const lang = langForFile(rel);
      s = lang ? findSources(lang, content(rel)) : [];
      sourceCache.set(rel, s);
    }
    return s;
  };
  const findings = [];
  const emitted = /* @__PURE__ */ new Set();
  const emit = (sink, sinkFile, sinkSym, srcHit, srcFile, hops) => {
    const id = shortHash(`${srcFile}:${srcHit.line}->${sinkFile}:${sink.line}:${sink.kind}`);
    if (emitted.has(id)) return;
    emitted.add(id);
    const srcStep = {
      file: srcFile,
      line: srcHit.line,
      symbol: enclosingSymbol2(byRel.get(srcFile), srcHit.line),
      why: `untrusted input (${srcHit.kind}): ${truncate(srcHit.match)}`
    };
    const path = [srcStep, ...hops];
    const sinkLine = lines(sinkFile)[sink.line - 1] ?? "";
    const lang = langForFile(sinkFile);
    const sanitizers = findSanitizers(lang, sinkLine, sink.kind);
    const crossFile = new Set(path.map((p) => p.file)).size > 1;
    const confidence = sanitizers.length ? "low" : "low";
    const note = sanitizers.length ? ` Possible sanitizer on the sink line (${sanitizers.join("; ")}) \u2014 confirm it actually neutralizes this flow.` : "";
    findings.push({
      id,
      category: "taint",
      cwe: sink.cwe,
      title: `${sink.title}: untrusted input reaches ${sink.callee}()`,
      severity: sink.severity,
      confidence,
      source: { file: srcStep.file, line: srcStep.line, kind: srcHit.kind },
      sink: { file: sinkFile, line: sink.line, kind: sink.kind, symbol: sinkSym },
      path,
      message: `${crossFile ? "Cross-file" : "Intra-file"} candidate: ${srcHit.kind} input at ${srcStep.file}:${srcStep.line} may reach the ${sink.kind} sink ${sink.callee}() at ${sinkFile}:${sink.line} through ${path.length - 1} hop(s). ${sink.note}${note} Heuristic \u2014 verify the data actually reaches the sink unsanitized before trusting it.`,
      tool: "ultrasec",
      references: [cweUrl(sink.cwe)],
      status: "open"
    });
  };
  for (const file of scan.files) {
    if (findings.length >= MAX_FINDINGS) break;
    const lang = langForFile(file.rel);
    if (!lang) continue;
    for (const sink of findSinks(lang, file.calls)) {
      const sinkSym = enclosingSymbol2(file, sink.line);
      const sinkStep = {
        file: file.rel,
        line: sink.line,
        symbol: sinkSym,
        why: `${sink.kind} sink: ${sink.callee}()`
      };
      const start = { file: file.rel, sym: sinkSym, entryLine: sink.line, hops: [sinkStep], depth: 0 };
      const queue = [start];
      const visited = /* @__PURE__ */ new Set([`${file.rel}#${sinkSym ?? sink.line}`]);
      while (queue.length) {
        const fr = queue.shift();
        const above = sourcesOf(fr.file).filter((s) => s.line <= fr.entryLine);
        if (above.length) {
          const nearest = above.reduce((a, b) => b.line > a.line ? b : a);
          emit(sink, file.rel, sinkSym, nearest, fr.file, fr.hops);
        }
        if (fr.depth >= MAX_DEPTH || !fr.sym) continue;
        const defs = graph.symbolDefs[fr.sym];
        if (!defs || defs.length !== 1 || defs[0] !== fr.file) continue;
        for (const caller of scan.files) {
          if (caller.rel === fr.file) continue;
          for (const c of caller.calls) {
            if (c.callee !== fr.sym) continue;
            const callerSym = enclosingSymbol2(caller, c.line);
            const key = `${caller.rel}#${callerSym ?? c.line}`;
            if (visited.has(key)) continue;
            visited.add(key);
            const hop = { file: caller.rel, line: c.line, symbol: callerSym, why: `calls ${fr.sym}()` };
            queue.push({ file: caller.rel, sym: callerSym, entryLine: c.line, hops: [hop, ...fr.hops], depth: fr.depth + 1 });
          }
        }
      }
    }
  }
  return findings.sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || byStr(a.id, b.id));
}

// src/tools/run.ts
import { execFileSync as execFileSync2 } from "child_process";
var TIMEOUT_MS = 18e4;
var MAX_BUFFER = 64 * 1024 * 1024;
function exec(name, args, cwd) {
  try {
    const stdout = execFileSync2(name, args, {
      cwd,
      encoding: "utf8",
      timeout: TIMEOUT_MS,
      maxBuffer: MAX_BUFFER,
      stdio: ["ignore", "pipe", "ignore"]
    });
    return { stdout, failed: false };
  } catch (e) {
    const err = e;
    const stdout = err.stdout ? err.stdout.toString() : "";
    if (stdout.trim()) return { stdout, failed: false };
    return { stdout: "", failed: true, err: err.message };
  }
}
function runAdapter(adapter, repo) {
  if (!detect(adapter.name).installed) {
    return { name: adapter.name, ran: false, ok: false, findings: [], note: "not installed" };
  }
  const { stdout, failed, err } = exec(adapter.name, adapter.argv(repo), repo);
  if (failed) return { name: adapter.name, ran: true, ok: false, findings: [], note: `run failed: ${err ?? "no output"}` };
  try {
    const findings = adapter.parse(stdout, repo);
    return { name: adapter.name, ran: true, ok: true, findings, note: `${findings.length} finding(s)` };
  } catch (e) {
    return { name: adapter.name, ran: true, ok: false, findings: [], note: `parse failed: ${e.message}` };
  }
}
function orchestrate(adapters, repo, which) {
  const selected = which && which.length ? adapters.filter((a) => which.includes(a.name)) : adapters;
  const results = [];
  const merged = /* @__PURE__ */ new Map();
  for (const a of selected) {
    const r = runAdapter(a, repo);
    results.push(r);
    for (const f of r.findings) if (!merged.has(f.id)) merged.set(f.id, f);
  }
  const findings = [...merged.values()].sort((a, b) => byStr(a.id, b.id));
  const toolsRun = results.filter((r) => r.ran && r.ok).map((r) => r.name);
  return { findings, toolsRun, results };
}

// src/tools/normalize.ts
var SEVERITY_ALIASES = {
  critical: "critical",
  high: "high",
  error: "high",
  moderate: "medium",
  medium: "medium",
  warning: "medium",
  low: "low",
  minor: "low",
  note: "low",
  info: "info",
  informational: "info",
  unknown: "info",
  none: "info"
};
function normalizeSeverity(raw, fallback = "medium") {
  if (!raw) return fallback;
  return SEVERITY_ALIASES[String(raw).trim().toLowerCase()] ?? fallback;
}
function makeToolFinding(i) {
  const id = shortHash(`${i.tool}:${i.ident}:${i.file ?? ""}:${i.line ?? ""}`);
  const f = {
    id,
    category: i.category,
    title: i.title || i.ident,
    severity: i.severity,
    confidence: i.confidence ?? "medium",
    message: i.message,
    tool: i.tool,
    status: "open"
  };
  if (i.cwe) f.cwe = i.cwe;
  if (i.references && i.references.length) f.references = i.references;
  if (i.file) {
    const loc = { file: i.file, line: i.line ?? 1 };
    f.sink = loc;
  }
  return f;
}
function parseJsonStream(raw) {
  const out = [];
  let depth = 0;
  let inStr = false;
  let esc3 = false;
  let start = -1;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (inStr) {
      if (esc3) esc3 = false;
      else if (ch === "\\") esc3 = true;
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') {
      inStr = true;
      continue;
    }
    if (ch === "{" || ch === "[") {
      if (depth === 0) start = i;
      depth++;
    } else if (ch === "}" || ch === "]") {
      depth--;
      if (depth === 0 && start >= 0) {
        try {
          out.push(JSON.parse(raw.slice(start, i + 1)));
        } catch {
        }
        start = -1;
      }
    }
  }
  return out;
}
function firstCwe(input) {
  const text = Array.isArray(input) ? input.join(" ") : typeof input === "string" ? input : "";
  const m = /CWE[-_ ]?(\d+)/i.exec(text);
  return m ? `CWE-${m[1]}` : void 0;
}

// src/tools/trivy.ts
var trivy = {
  name: "trivy",
  category: "dep",
  argv: (repo) => ["fs", "--scanners", "vuln,secret,misconfig", "--format", "json", "--quiet", repo],
  parse(raw) {
    const data = JSON.parse(raw || "{}");
    const out = [];
    for (const r of data.Results ?? []) {
      const target = r.Target ?? "";
      for (const v of r.Vulnerabilities ?? []) {
        out.push(
          makeToolFinding({
            tool: "trivy",
            category: "dep",
            ident: v.VulnerabilityID,
            title: v.Title || `${v.PkgName}: ${v.VulnerabilityID}`,
            severity: normalizeSeverity(v.Severity, "medium"),
            message: `${v.PkgName}@${v.InstalledVersion}: ${v.Title || v.Description || v.VulnerabilityID}` + (v.FixedVersion ? ` (fixed in ${v.FixedVersion})` : ""),
            file: target,
            cwe: firstCwe(v.CweIDs),
            references: [v.PrimaryURL, ...v.References ?? []].filter(Boolean)
          })
        );
      }
      for (const s of r.Secrets ?? []) {
        out.push(
          makeToolFinding({
            tool: "trivy",
            category: "secret",
            ident: `${s.RuleID}:${s.StartLine}`,
            title: s.Title || s.RuleID,
            severity: normalizeSeverity(s.Severity, "high"),
            message: `Hardcoded secret (${s.Title || s.RuleID}) at ${target}:${s.StartLine}`,
            file: target,
            line: s.StartLine,
            cwe: "CWE-798"
          })
        );
      }
      for (const mc of r.Misconfigurations ?? []) {
        const line = mc.CauseMetadata?.StartLine;
        out.push(
          makeToolFinding({
            tool: "trivy",
            category: "config",
            ident: mc.AVDID || mc.ID,
            title: mc.Title || mc.ID,
            severity: normalizeSeverity(mc.Severity, "medium"),
            message: `${mc.ID} ${mc.Title}: ${mc.Message || mc.Description || ""}`.trim(),
            file: target,
            line: typeof line === "number" ? line : void 0,
            references: [mc.PrimaryURL, ...mc.References ?? []].filter(Boolean)
          })
        );
      }
    }
    return out;
  }
};

// src/tools/gitleaks.ts
var gitleaks = {
  name: "gitleaks",
  category: "secret",
  argv: (repo) => ["detect", "--no-git", "--source", repo, "--report-format", "json", "--report-path", "/dev/stdout", "--no-banner", "--redact"],
  parse(raw) {
    const arr = JSON.parse(raw || "[]");
    if (!Array.isArray(arr)) return [];
    return arr.map(
      (f) => makeToolFinding({
        tool: "gitleaks",
        category: "secret",
        ident: `${f.RuleID}:${f.File}:${f.StartLine}`,
        title: f.Description || f.RuleID,
        severity: "high",
        message: `Hardcoded secret (${f.Description || f.RuleID}) at ${f.File}:${f.StartLine}`,
        file: f.File,
        line: f.StartLine,
        cwe: "CWE-798"
      })
    );
  }
};

// src/tools/cvss.ts
var AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
var AC = { L: 0.77, H: 0.44 };
var UI = { N: 0.85, R: 0.62 };
var CIA = { H: 0.56, L: 0.22, N: 0 };
var PR_U = { N: 0.85, L: 0.62, H: 0.27 };
var PR_C = { N: 0.85, L: 0.68, H: 0.5 };
function roundup(x) {
  return Math.ceil(x * 10) / 10;
}
function cvssBaseScore(vector) {
  if (!vector || !/CVSS:3/i.test(vector)) return null;
  const m = {};
  for (const part of vector.split("/")) {
    const [k, v] = part.split(":");
    if (k && v) m[k] = v;
  }
  const scope = m.S;
  const av = AV[m.AV ?? ""];
  const ac = AC[m.AC ?? ""];
  const ui = UI[m.UI ?? ""];
  const pr = (scope === "C" ? PR_C : PR_U)[m.PR ?? ""];
  const c = CIA[m.C ?? ""];
  const in_ = CIA[m.I ?? ""];
  const a = CIA[m.A ?? ""];
  if ([av, ac, ui, pr, c, in_, a].some((x) => x === void 0)) return null;
  const iss = 1 - (1 - c) * (1 - in_) * (1 - a);
  const impact = scope === "C" ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  const raw = scope === "C" ? 1.08 * (impact + exploitability) : impact + exploitability;
  return roundup(Math.min(raw, 10));
}
function scoreToSeverity(score) {
  if (score == null) return "medium";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score >= 0.1) return "low";
  return "info";
}
function deriveSeverity(input, fallback = "medium") {
  if (!input) return fallback;
  const s = input.trim();
  const asNum = Number(s);
  if (!Number.isNaN(asNum) && s !== "") return scoreToSeverity(asNum);
  if (/CVSS:3/i.test(s)) return scoreToSeverity(cvssBaseScore(s));
  return normalizeSeverity(s, fallback);
}

// src/tools/osv.ts
var osvScanner = {
  name: "osv-scanner",
  category: "dep",
  argv: (repo) => ["--format", "json", "--output", "-", "-r", repo],
  parse(raw) {
    const data = JSON.parse(raw || "{}");
    const out = [];
    for (const res of data.results ?? []) {
      const src = res.source?.path ?? "";
      for (const pkg of res.packages ?? []) {
        const name = pkg.package?.name;
        const version = pkg.package?.version;
        const groupSev = /* @__PURE__ */ new Map();
        for (const g of pkg.groups ?? []) for (const id of g.ids ?? []) groupSev.set(id, g.max_severity);
        for (const v of pkg.vulnerabilities ?? []) {
          const db = v.database_specific ?? {};
          const sevStr = groupSev.get(v.id) ?? db.severity ?? "";
          const fixed = (v.affected ?? []).flatMap((a) => (a.ranges ?? []).flatMap((r) => (r.events ?? []).map((e) => e.fixed))).filter(Boolean)[0];
          out.push(
            makeToolFinding({
              tool: "osv-scanner",
              category: "dep",
              ident: v.id,
              title: v.summary || v.id,
              severity: deriveSeverity(sevStr, "medium"),
              message: `${name}@${version}: ${v.summary || v.id}` + (fixed ? ` (fixed in ${fixed})` : ""),
              file: src,
              cwe: firstCwe(db.cwe_ids),
              references: (v.references ?? []).map((r) => r.url).filter(Boolean)
            })
          );
        }
      }
    }
    return out;
  }
};

// src/tools/semgrep.ts
var SEV = {
  ERROR: "high",
  WARNING: "medium",
  INFO: "low",
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low"
};
function parseSemgrep(tool, raw) {
  const data = JSON.parse(raw || "{}");
  const out = [];
  for (const r of data.results ?? []) {
    const md = r.extra?.metadata ?? {};
    if (r.extra?.sca_info) continue;
    out.push(
      makeToolFinding({
        tool,
        category: "sast",
        ident: `${r.check_id}:${r.path}:${r.start?.line ?? ""}`,
        title: r.check_id,
        severity: SEV[String(r.extra?.severity ?? "").toUpperCase()] ?? "medium",
        message: r.extra?.message || r.check_id,
        file: r.path,
        line: r.start?.line,
        cwe: firstCwe(md.cwe),
        references: md.references ?? []
      })
    );
  }
  return out;
}
var semgrep = {
  name: "semgrep",
  category: "sast",
  argv: (repo) => ["scan", "--json", "--quiet", "--config", "auto", repo],
  parse: (raw) => parseSemgrep("semgrep", raw)
};
var opengrep = {
  name: "opengrep",
  category: "sast",
  argv: (repo) => ["scan", "--json", "--quiet", "--config", "auto", repo],
  parse: (raw) => parseSemgrep("opengrep", raw)
};

// src/tools/cargo-audit.ts
var cargoAudit = {
  name: "cargo-audit",
  category: "dep",
  argv: () => ["audit", "--format", "json"],
  parse(raw) {
    const data = JSON.parse(raw || "{}");
    const out = [];
    for (const item of data.vulnerabilities?.list ?? []) {
      const adv = item.advisory ?? {};
      const pkg = item.package ?? {};
      const patched = (item.versions?.patched ?? []).join(", ");
      out.push(
        makeToolFinding({
          tool: "cargo-audit",
          category: "dep",
          ident: adv.id,
          title: adv.title || adv.id,
          severity: deriveSeverity(adv.cvss, "high"),
          message: `${pkg.name}@${pkg.version}: ${adv.title || adv.id}` + (patched ? ` (patched: ${patched})` : ""),
          file: "Cargo.lock",
          references: [adv.url, ...adv.aliases ?? []].filter(Boolean)
        })
      );
    }
    const warnings = data.warnings ?? {};
    for (const kind of Object.keys(warnings)) {
      for (const w of warnings[kind] ?? []) {
        const adv = w.advisory ?? {};
        const pkg = w.package ?? {};
        out.push(
          makeToolFinding({
            tool: "cargo-audit",
            category: "dep",
            ident: adv.id || `${kind}:${pkg.name}`,
            title: adv.title || `${pkg.name} is ${kind}`,
            severity: "low",
            confidence: "low",
            message: `${pkg.name}@${pkg.version}: ${kind}${adv.title ? ` \u2014 ${adv.title}` : ""}`,
            file: "Cargo.lock",
            references: adv.url ? [adv.url] : []
          })
        );
      }
    }
    return out;
  }
};

// src/tools/govulncheck.ts
var govulncheck = {
  name: "govulncheck",
  category: "dep",
  streaming: true,
  argv: () => ["-json", "./..."],
  parse(raw) {
    const msgs = parseJsonStream(raw);
    const osvById = /* @__PURE__ */ new Map();
    for (const m of msgs) if (m?.osv?.id) osvById.set(m.osv.id, m.osv);
    const out = [];
    const seen = /* @__PURE__ */ new Set();
    for (const m of msgs) {
      const f = m?.finding;
      if (!f?.osv) continue;
      if (seen.has(f.osv)) continue;
      seen.add(f.osv);
      const osv = osvById.get(f.osv) ?? {};
      const top = (f.trace ?? [])[0] ?? {};
      const reachable = Boolean(top.function && top.position);
      out.push(
        makeToolFinding({
          tool: "govulncheck",
          category: "dep",
          ident: f.osv,
          title: osv.summary || f.osv,
          severity: reachable ? "high" : "medium",
          confidence: reachable ? "high" : "low",
          message: `${osv.summary || f.osv}` + (f.fixed_version ? ` (fixed in ${f.fixed_version})` : "") + (reachable ? ` \u2014 reachable via ${top.package}.${top.function}` : " \u2014 imported, reachability not proven"),
          file: top.position?.filename,
          line: top.position?.line,
          references: (osv.references ?? []).map((r) => r.url).filter(Boolean)
        })
      );
    }
    return out;
  }
};

// src/tools/index.ts
var ADAPTERS = [
  trivy,
  opengrep,
  semgrep,
  gitleaks,
  osvScanner,
  cargoAudit,
  govulncheck
];

// src/store.ts
import { mkdirSync, writeFileSync, readFileSync as readFileSync2, existsSync } from "fs";
import { join as join3 } from "path";
function emptySeverityCounts() {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}
function countBySeverity(findings) {
  const c = emptySeverityCounts();
  for (const f of findings) c[f.severity]++;
  return c;
}
function writeDossier(outDir, d) {
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join3(outDir, "manifest.json"), JSON.stringify(d.manifest, null, 2));
  writeFileSync(join3(outDir, "findings.json"), JSON.stringify(d.findings, null, 2));
  writeFileSync(join3(outDir, "graph.json"), JSON.stringify(d.graph, null, 2));
  writeFileSync(join3(outDir, "DOSSIER.md"), renderDossierMd(d));
}
function loadDossier(outDir) {
  const read = (name) => JSON.parse(readFileSync2(join3(outDir, name), "utf8"));
  if (!existsSync(join3(outDir, "findings.json"))) {
    throw new Error(`no audit dossier at ${outDir} (run \`ultrasec scan --out ${outDir}\` first)`);
  }
  return { manifest: read("manifest.json"), findings: read("findings.json"), graph: read("graph.json") };
}
function severityBadge(s) {
  return { critical: "\u{1F7E5} CRIT", high: "\u{1F7E7} HIGH", medium: "\u{1F7E8} MED", low: "\u{1F7E9} LOW", info: "\u2B1C INFO" }[s];
}
function renderDossierMd(d) {
  const { manifest: m, findings } = d;
  const c = m.counts.bySeverity;
  const L = [];
  L.push(`# ultrasec audit dossier`);
  L.push("");
  L.push(`- repo: \`${m.repo}\``);
  L.push(`- languages: ${m.languages.join(", ") || "\u2014"}`);
  L.push(`- external tools run: ${m.toolsRun.join(", ") || "none (graph + taint only)"}`);
  L.push(`- findings: **${m.counts.findings}** \u2014 ${SEVERITIES.map((s) => `${severityBadge(s)} ${c[s]}`).join("  ")}`);
  L.push("");
  L.push(`> Candidates are deterministic and **recall-oriented** \u2014 every one needs`);
  L.push(`> adjudication. Open each with \`ultrasec dossier <id>\` (real code + the`);
  L.push(`> cross-file path), confirm whether the flow is real and exploitable, then`);
  L.push(`> record a verdict via \`ultrasec verify\`. An uncertain high-severity stays`);
  L.push(`> **needs-human** \u2014 never silently dropped.`);
  L.push("");
  if (!findings.length) {
    L.push(`_No candidate findings._`);
    return L.join("\n") + "\n";
  }
  L.push(`## Candidates`);
  L.push("");
  for (const f of findings) {
    L.push(`### ${f.id} \u2014 ${severityBadge(f.severity)} ${f.title}`);
    L.push("");
    L.push(`- category: ${f.category}${f.cwe ? ` \xB7 ${f.cwe}` : ""} \xB7 confidence ${f.confidence} \xB7 status ${f.status}${f.tool !== "ultrasec" ? ` \xB7 via ${f.tool}` : ""}`);
    if (f.path && f.path.length) {
      L.push(`- path: ${f.path.map((p) => `\`${p.file}:${p.line}\``).join(" \u2192 ")}`);
    } else if (f.sink) {
      L.push(`- at: \`${f.sink.file}:${f.sink.line}\``);
    }
    L.push(`- ${f.message}`);
    L.push("");
  }
  L.push(`---`);
  L.push(`Engine: ultrasec ${m.version}. ${m.generatedNote}`);
  return L.join("\n") + "\n";
}

// src/commands/scan.ts
function runScan(args) {
  const repo = resolve(flagStr(args, "repo") ?? ".");
  const out = resolve(flagStr(args, "out") ?? ".ultrasec");
  const scan = scanRepo(repo);
  const graph = buildGraph(scan);
  const taintFindings = enumerateTaint(scan, graph);
  const toolsFlag = flagStr(args, "tools");
  const skipTools = flagBool(args, "no-tools") || toolsFlag === "none";
  const which = toolsFlag && toolsFlag !== "auto" && toolsFlag !== "none" ? toolsFlag.split(",").map((s) => s.trim()) : void 0;
  const tool = skipTools ? { findings: [], toolsRun: [], results: [] } : orchestrate(ADAPTERS, repo, which);
  const findings = [...taintFindings, ...tool.findings].sort((a, b) => byStr(a.id, b.id));
  const languages = [...new Set(scan.files.map((f) => f.lang))].sort();
  const manifest = {
    version: VERSION,
    schemaVersion: SCHEMA_VERSION,
    repo,
    generatedNote: "Taint candidates are deterministic; external-tool results depend on installed scanners.",
    languages,
    toolsRun: tool.toolsRun,
    counts: { findings: findings.length, bySeverity: countBySeverity(findings) }
  };
  const dossier = { manifest, findings, graph };
  writeDossier(out, dossier);
  if (flagBool(args, "json")) {
    println(JSON.stringify({ out, counts: manifest.counts, languages, files: scan.files.length, toolsRun: tool.toolsRun }, null, 2));
    return 0;
  }
  const c = manifest.counts.bySeverity;
  println(`ultrasec scan \u2192 ${out}`);
  println(`  files scanned: ${scan.files.length}  \xB7  languages: ${languages.join(", ") || "\u2014"}`);
  if (!skipTools) {
    println(`  external tools run: ${tool.toolsRun.join(", ") || "none"}  (\`ultrasec tools\` to see/install more)`);
  }
  println(`  candidate findings: ${findings.length}  (crit ${c.critical} \xB7 high ${c.high} \xB7 med ${c.medium} \xB7 low ${c.low})  \xB7  ${taintFindings.length} taint + ${tool.findings.length} tool`);
  if (!findings.length) {
    println(`  no taint candidates \u2014 still review the DOSSIER and run external tools (\`ultrasec tools\`).`);
  } else {
    println(`  next: read ${out}/DOSSIER.md, then \`ultrasec dossier <id> --run ${out}\` to adjudicate.`);
  }
  return 0;
}

// src/commands/dossier.ts
import { resolve as resolve2 } from "path";

// src/dossier.ts
import { join as join4 } from "path";
function excerpt(repo, step, ctx = 3) {
  const lines = readText(join4(repo, step.file)).split(/\r?\n/);
  const lo = Math.max(1, step.line - ctx);
  const hi = Math.min(lines.length, step.line + ctx);
  const out = [];
  for (let n = lo; n <= hi; n++) {
    const marker = n === step.line ? ">>" : "  ";
    out.push(`${marker} ${String(n).padStart(4)} | ${lines[n - 1] ?? ""}`);
  }
  return out.join("\n");
}
function renderFindingDossier(repo, graph, f) {
  const L = [];
  L.push(`# ${f.id} \u2014 ${f.title}`);
  L.push("");
  L.push(`- severity: ${f.severity} \xB7 confidence: ${f.confidence} \xB7 status: ${f.status}`);
  if (f.cwe) L.push(`- ${f.cwe} \u2014 ${(f.references ?? [])[0] ?? ""}`);
  L.push(`- category: ${f.category}${f.tool !== "ultrasec" ? ` \xB7 reported by ${f.tool}` : ""}`);
  L.push("");
  L.push(`## What to decide`);
  L.push(f.message);
  L.push("");
  if (f.path && f.path.length) {
    L.push(`## Cross-file path (source \u2192 sink)`);
    L.push("");
    f.path.forEach((step, i) => {
      const tag = i === 0 ? "SOURCE" : i === f.path.length - 1 ? "SINK" : "HOP";
      L.push(`### ${i + 1}. [${tag}] ${step.file}:${step.line}${step.symbol ? ` \u2014 in ${step.symbol}()` : ""}`);
      L.push(`_${step.why}_`);
      L.push("```");
      L.push(excerpt(repo, step));
      L.push("```");
      L.push("");
    });
  } else if (f.sink) {
    L.push(`## Location`);
    L.push("```");
    L.push(excerpt(repo, { file: f.sink.file, line: f.sink.line, why: "" }));
    L.push("```");
    L.push("");
  }
  const anchor = f.sink?.file ?? f.path?.[f.path.length - 1]?.file;
  if (anchor && graph.files.includes(anchor)) {
    const nb = neighbors(graph, anchor, 1).links;
    if (nb.length) {
      L.push(`## Graph neighbours of \`${anchor}\``);
      for (const l of nb) {
        const arrow = l.direction === "out" ? "\u2192" : "\u2190";
        L.push(`- ${arrow} ${l.kind} ${l.node}${l.symbol ? ` [${l.symbol}]` : ""}`);
      }
      L.push("");
    }
  }
  L.push(`## How to verify`);
  L.push(`1. Confirm the SOURCE is genuinely attacker-controlled.`);
  L.push(`2. Follow each HOP \u2014 does the tainted value actually pass through unchanged?`);
  L.push(`3. Check for a sanitizer/validator/authz guard anywhere on the path.`);
  L.push(`4. Confirm the SINK is exploitable with the value that arrives.`);
  L.push(`5. Record \`supported\` / \`partial\` / \`unsupported\` / \`refuted\` via \`ultrasec verify\`.`);
  L.push(`   If unsure and severity is high, leave it **needs-human** \u2014 do not dismiss.`);
  return L.join("\n") + "\n";
}

// src/commands/dossier.ts
function runDossier(args) {
  const run = resolve2(flagStr(args, "run") ?? ".ultrasec");
  const id = args._[1];
  if (!id) {
    eprintln("ultrasec dossier: need a <finding-id>. List them in DOSSIER.md or with `paths`.");
    return 2;
  }
  let d;
  try {
    d = loadDossier(run);
  } catch (e) {
    eprintln(`ultrasec dossier: ${e.message}`);
    return 2;
  }
  const f = d.findings.find((x) => x.id === id || x.id.startsWith(id));
  if (!f) {
    eprintln(`ultrasec dossier: no finding "${id}" in ${run}.`);
    return 2;
  }
  const repo = flagStr(args, "repo") ?? d.manifest.repo;
  println(renderFindingDossier(repo, d.graph, f));
  return 0;
}

// src/commands/paths.ts
import { resolve as resolve3 } from "path";
function runPaths(args) {
  const run = resolve3(flagStr(args, "run") ?? ".ultrasec");
  const kind = flagStr(args, "kind");
  const sev = flagStr(args, "severity");
  let d;
  try {
    d = loadDossier(run);
  } catch (e) {
    eprintln(`ultrasec paths: ${e.message}`);
    return 2;
  }
  let findings = d.findings.filter((f) => f.path && f.path.length);
  if (kind) findings = findings.filter((f) => f.sink?.kind === kind);
  if (sev) findings = findings.filter((f) => f.severity === sev);
  if (flagBool(args, "json")) {
    println(JSON.stringify(findings.map((f) => ({ id: f.id, severity: f.severity, cwe: f.cwe, path: f.path })), null, 2));
    return 0;
  }
  if (!findings.length) {
    println("no candidate taint paths match.");
    return 0;
  }
  for (const f of findings) {
    println(`${f.id}  ${f.severity.padEnd(8)} ${f.cwe ?? ""}  ${f.title}`);
    println(`        ${f.path.map((p) => `${p.file}:${p.line}`).join(" \u2192 ")}`);
  }
  return 0;
}

// src/commands/verify.ts
import { readFileSync as readFileSync3, writeFileSync as writeFileSync2, readdirSync as readdirSync2, statSync as statSync2 } from "fs";
import { join as join5, resolve as resolve4 } from "path";

// src/verify.ts
function pending(findings) {
  return findings.filter((f) => f.status === "open" || f.status === "needs-human");
}
function buildWorklist(dossier) {
  return pending(dossier.findings).slice().sort((a, b) => byStr(a.id, b.id)).map((f) => {
    const files = /* @__PURE__ */ new Set();
    for (const p of f.path ?? []) files.add(`${p.file}:${p.line}`);
    if (f.sink) files.add(`${f.sink.file}:${f.sink.line}`);
    if (f.source) files.add(`${f.source.file}:${f.source.line}`);
    return {
      id: f.id,
      severity: f.severity,
      cwe: f.cwe,
      title: f.title,
      category: f.category,
      claim: f.message,
      files: [...files],
      verdict: null,
      note: ""
    };
  });
}
function shard(items, n, i) {
  return items.filter((_, idx) => idx % n === i);
}
function renderWorklistMd(items) {
  const L = [];
  L.push(`# ultrasec verification worklist (${items.length})`);
  L.push("");
  L.push(`For each item: open the cited code (\`ultrasec dossier <id>\`), decide whether`);
  L.push(`the flow is **real and exploitable**, and set a verdict:`);
  L.push(`\`supported\` \xB7 \`partial\` \xB7 \`unsupported\` \xB7 \`refuted\` (+ a short note, and an`);
  L.push(`\`exploitPath\` when supported). Save as verdicts.json (array of`);
  L.push(`{id, verdict, note, exploitPath}) and run \`ultrasec verify --apply verdicts.json\`.`);
  L.push("");
  L.push(`> Be skeptical, but do NOT dismiss a high/critical finding unless you can`);
  L.push(`> positively **refute** it. Uncertain \u21D2 leave it for a human.`);
  L.push("");
  for (const it of items) {
    L.push(`## ${it.id} \u2014 [${it.severity}] ${it.title}`);
    if (it.cwe) L.push(`- ${it.cwe} \xB7 ${it.category}`);
    L.push(`- files: ${it.files.map((f) => `\`${f}\``).join(", ")}`);
    L.push(`- claim: ${it.claim}`);
    L.push("");
  }
  return L.join("\n") + "\n";
}
function isHigh(sev) {
  return sev === "critical" || sev === "high";
}
function nextStatus(verdict, severity) {
  switch (verdict) {
    case "supported":
      return "confirmed";
    case "refuted":
      return "dismissed";
    // an explicit contradiction — safe to drop
    case "unsupported":
      return isHigh(severity) ? "needs-human" : "dismissed";
    case "partial":
      return "needs-human";
  }
}
function applyVerdicts(dossier, verdicts) {
  const byId = /* @__PURE__ */ new Map();
  for (const v of verdicts) byId.set(v.id, v);
  let confirmed = 0, dismissed = 0, needsHuman = 0, applied = 0;
  const keptForHuman = [];
  const findings = dossier.findings.map((f) => {
    const v = byId.get(f.id);
    if (!v) return f;
    applied++;
    const status = nextStatus(v.verdict, f.severity);
    if (v.verdict === "unsupported" && isHigh(f.severity)) keptForHuman.push({ id: f.id, verdict: v.verdict, severity: f.severity });
    if (status === "confirmed") confirmed++;
    else if (status === "dismissed") dismissed++;
    else needsHuman++;
    const next = {
      ...f,
      status,
      verdict: v.verdict,
      confidence: v.verdict === "supported" ? "high" : v.verdict === "partial" ? "medium" : f.confidence
    };
    if (v.exploitPath) next.exploitPath = v.exploitPath;
    if (v.note) next.message = `${f.message}

Verdict (${v.verdict}): ${v.note}`;
    return next;
  });
  return { findings, applied, confirmed, dismissed, needsHuman, keptForHuman };
}
function parseVerdicts(raw) {
  const data = JSON.parse(raw);
  const arr = Array.isArray(data) ? data : Array.isArray(data?.verdicts) ? data.verdicts : [];
  return arr.filter((v) => v && typeof v.id === "string" && typeof v.verdict === "string").map((v) => ({ id: v.id, verdict: v.verdict, note: v.note, exploitPath: v.exploitPath }));
}

// src/commands/verify.ts
function runVerify(args) {
  const run = resolve4(flagStr(args, "run") ?? ".ultrasec");
  let dossier;
  try {
    dossier = loadDossier(run);
  } catch (e) {
    eprintln(`ultrasec verify: ${e.message}`);
    return 2;
  }
  const applyPath = flagStr(args, "apply");
  if (applyPath) return applyMode(run, dossier, applyPath, args);
  let items = buildWorklist(dossier);
  const shards = Number(flagStr(args, "shards") ?? "0") || 0;
  const shardIdx = Number(flagStr(args, "shard") ?? "0") || 0;
  if (shards > 1) items = shard(items, shards, shardIdx);
  const todoName = shards > 1 ? `VERIFY.todo.${shardIdx}.json` : "VERIFY.todo.json";
  writeFileSync2(join5(run, todoName), JSON.stringify(items, null, 2));
  writeFileSync2(join5(run, "VERIFY.md"), renderWorklistMd(buildWorklist(dossier)));
  if (flagBool(args, "json")) {
    println(JSON.stringify(items, null, 2));
    return 0;
  }
  println(`ultrasec verify \u2192 ${join5(run, todoName)} (${items.length} item${items.length === 1 ? "" : "s"}${shards > 1 ? `, shard ${shardIdx}/${shards}` : ""})`);
  println(`  adjudicate each (\`ultrasec dossier <id> --run ${run}\`), save verdicts.json, then:`);
  println(`  ultrasec verify --apply verdicts.json --run ${run}`);
  return 0;
}
function collectVerdictFiles(applyPath) {
  if (applyPath.includes(",")) return applyPath.split(",").map((s) => resolve4(s.trim()));
  const abs = resolve4(applyPath);
  try {
    if (statSync2(abs).isDirectory()) {
      return readdirSync2(abs).filter((n) => /verdict.*\.json$/i.test(n)).map((n) => join5(abs, n));
    }
  } catch {
  }
  return [abs];
}
function applyMode(run, dossier, applyPath, args) {
  const files = collectVerdictFiles(applyPath);
  const verdicts = [];
  for (const f of files) {
    try {
      verdicts.push(...parseVerdicts(readFileSync3(f, "utf8")));
    } catch (e) {
      eprintln(`ultrasec verify: cannot read verdicts at ${f}: ${e.message}`);
      return 2;
    }
  }
  const res = applyVerdicts(dossier, verdicts);
  const manifest = { ...dossier.manifest, counts: { findings: res.findings.length, bySeverity: countBySeverity(res.findings) } };
  writeDossier(run, { manifest, findings: res.findings, graph: dossier.graph });
  if (flagBool(args, "json")) {
    println(JSON.stringify({ applied: res.applied, confirmed: res.confirmed, dismissed: res.dismissed, needsHuman: res.needsHuman, keptForHuman: res.keptForHuman }, null, 2));
    return 0;
  }
  println(`ultrasec verify --apply \u2192 updated ${run}/findings.json`);
  println(`  applied ${res.applied} verdict(s): ${res.confirmed} confirmed \xB7 ${res.dismissed} dismissed \xB7 ${res.needsHuman} needs-human`);
  if (res.keptForHuman.length) {
    println(`  kept for human (high-severity, only 'unsupported' \u2014 not auto-dismissed):`);
    for (const k of res.keptForHuman) println(`    - ${k.id} [${k.severity}]`);
  }
  return 0;
}

// src/commands/check.ts
import { resolve as resolve5 } from "path";

// src/check.ts
import { existsSync as existsSync2, readFileSync as readFileSync4 } from "fs";
import { join as join6 } from "path";
function lineCount(repo, file) {
  const abs = join6(repo, file);
  if (!existsSync2(abs)) return null;
  try {
    return readFileSync4(abs, "utf8").split(/\r?\n/).length;
  } catch {
    return null;
  }
}
function locsOf(f) {
  const locs = [];
  if (f.source) locs.push(f.source);
  if (f.sink) locs.push(f.sink);
  for (const p of f.path ?? []) locs.push(p);
  return locs;
}
function atLeast(sev, floor) {
  return SEVERITIES.indexOf(sev) <= SEVERITIES.indexOf(floor);
}
function check(dossier, opts = {}) {
  const repo = opts.repo ?? dossier.manifest.repo;
  const floor = opts.minSeverity;
  const findings = floor ? dossier.findings.filter((f) => atLeast(f.severity, floor)) : dossier.findings;
  const dangling = [];
  const lineCache = /* @__PURE__ */ new Map();
  const linesOf = (file) => {
    if (!lineCache.has(file)) lineCache.set(file, lineCount(repo, file));
    return lineCache.get(file);
  };
  for (const f of findings) {
    if (f.status === "dismissed") continue;
    for (const loc of locsOf(f)) {
      const lc = linesOf(loc.file);
      if (lc === null) dangling.push({ id: f.id, file: loc.file, line: loc.line, reason: "file not found" });
      else if (loc.line < 1 || loc.line > lc) dangling.push({ id: f.id, file: loc.file, line: loc.line, reason: `line out of range (file has ${lc} lines)` });
    }
  }
  const open = findings.filter((f) => f.status === "open").length;
  const confirmed = findings.filter((f) => f.status === "confirmed").length;
  const dismissed = findings.filter((f) => f.status === "dismissed").length;
  const needsHuman = findings.filter((f) => f.status === "needs-human").length;
  const messages = [];
  let ok = true;
  if (dangling.length) {
    ok = false;
    messages.push(`${dangling.length} dangling citation(s) \u2014 a cited [file:line] does not resolve (hallucinated or stale).`);
  }
  if (opts.semantic) {
    if (open > 0) {
      ok = false;
      messages.push(`${open} candidate(s) still unadjudicated \u2014 run \`ultrasec verify\` and \`--apply\` verdicts before the gate can pass.`);
    }
    if (needsHuman > 0) messages.push(`${needsHuman} finding(s) flagged needs-human \u2014 review required (not auto-failing).`);
  }
  if (ok) messages.push(`grounding OK${opts.semantic ? " \xB7 audit adjudicated" : ""} \u2014 ${confirmed} confirmed, ${dismissed} dismissed, ${needsHuman} needs-human.`);
  return { ok, dangling, open, confirmed, dismissed, needsHuman, gated: findings.length, messages };
}

// src/commands/check.ts
function runCheck(args) {
  const run = resolve5(flagStr(args, "run") ?? ".ultrasec");
  const repo = flagStr(args, "repo");
  const semantic = flagBool(args, "semantic");
  const minSevRaw = flagStr(args, "min-severity");
  const minSeverity = minSevRaw && SEVERITIES.includes(minSevRaw) ? minSevRaw : void 0;
  let dossier;
  try {
    dossier = loadDossier(run);
  } catch (e) {
    eprintln(`ultrasec check: ${e.message}`);
    return 2;
  }
  const res = check(dossier, { repo, semantic, minSeverity });
  if (flagBool(args, "json")) {
    println(JSON.stringify(res, null, 2));
    return res.ok ? 0 : 1;
  }
  for (const d of res.dangling.slice(0, 50)) {
    eprintln(`  \u2717 ${d.id}: ${d.file}:${d.line} \u2014 ${d.reason}`);
  }
  for (const m of res.messages) println((res.ok ? "  \u2713 " : "  \u2022 ") + m);
  return res.ok ? 0 : 1;
}

// src/commands/render.ts
import { writeFileSync as writeFileSync3 } from "fs";
import { join as join7, resolve as resolve6 } from "path";

// src/render/mermaid.ts
function esc(s) {
  return s.replace(/"/g, "'").replace(/[\n\r]/g, " ");
}
function pathMermaid(f) {
  if (!f.path || f.path.length < 2) return null;
  const L = ["flowchart LR"];
  f.path.forEach((p, i) => {
    const tag = i === 0 ? "SOURCE" : i === f.path.length - 1 ? "SINK" : "hop";
    const sym = p.symbol ? `<br/>${esc(p.symbol)}()` : "";
    L.push(`  n${i}["${tag}<br/>${esc(p.file)}:${p.line}${sym}"]`);
  });
  for (let i = 0; i < f.path.length - 1; i++) L.push(`  n${i} --> n${i + 1}`);
  L.push(`  classDef src fill:#fde68a,stroke:#b45309;`);
  L.push(`  classDef snk fill:#fecaca,stroke:#b91c1c;`);
  L.push(`  class n0 src;`);
  L.push(`  class n${f.path.length - 1} snk;`);
  return L.join("\n");
}

// src/render/report.ts
var BADGE = {
  critical: "\u{1F7E5} CRITICAL",
  high: "\u{1F7E7} HIGH",
  medium: "\u{1F7E8} MEDIUM",
  low: "\u{1F7E9} LOW",
  info: "\u2B1C INFO"
};
function sevRank(s) {
  return SEVERITIES.indexOf(s);
}
function sortFindings(fs) {
  return fs.slice().sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || byStr(a.id, b.id));
}
function pathLine(f) {
  if (f.path?.length) return f.path.map((p) => `\`${p.file}:${p.line}\``).join(" \u2192 ");
  if (f.sink) return `\`${f.sink.file}:${f.sink.line}\``;
  return "\u2014";
}
function header(d) {
  const c = d.manifest.counts.bySeverity;
  return [
    `repo \`${d.manifest.repo}\` \xB7 ultrasec ${d.manifest.version}`,
    `findings: **${d.manifest.counts.findings}** \u2014 ${SEVERITIES.map((s) => `${BADGE[s]} ${c[s]}`).join(" \xB7 ")}`,
    `tools: ${d.manifest.toolsRun.join(", ") || "none (graph + taint only)"}`
  ].join("  \n");
}
function statusTag(f) {
  const v = f.verdict ? ` \xB7 verdict ${f.verdict}` : "";
  return `status **${f.status}**${v} \xB7 confidence ${f.confidence}`;
}
function renderSummary(d) {
  const fs = sortFindings(d.findings);
  const confirmed = fs.filter((f) => f.status === "confirmed");
  const needs = fs.filter((f) => f.status === "needs-human");
  const L = [`# Security audit \u2014 summary`, "", header(d), ""];
  if (!confirmed.length && !needs.length) {
    L.push(d.findings.length ? `No confirmed issues. ${d.findings.length} candidate(s) \u2014 see REPORT.md.` : `No findings.`);
    return L.join("\n") + "\n";
  }
  if (confirmed.length) {
    L.push(`## Confirmed (${confirmed.length})`);
    for (const f of confirmed) L.push(`- ${BADGE[f.severity]} **${f.title}** \u2014 ${pathLine(f)} (${f.cwe ?? f.category})`);
    L.push("");
  }
  if (needs.length) {
    L.push(`## Needs human review (${needs.length})`);
    for (const f of needs) L.push(`- ${BADGE[f.severity]} ${f.title} \u2014 ${pathLine(f)} (${f.cwe ?? f.category})`);
  }
  return L.join("\n") + "\n";
}
function renderFinding(f, opts = {}) {
  const L = [];
  L.push(`### ${BADGE[f.severity]} ${f.title}`);
  L.push("");
  L.push(`\`${f.id}\` \xB7 ${f.cwe ? `[${f.cwe}](${(f.references ?? [])[0] ?? `https://cwe.mitre.org/`}) \xB7 ` : ""}${f.category} \xB7 ${statusTag(f)}${f.tool !== "ultrasec" ? ` \xB7 via ${f.tool}` : ""}`);
  L.push("");
  L.push(`**Path:** ${pathLine(f)}`);
  L.push("");
  L.push(f.message);
  if (f.exploitPath) {
    L.push("");
    L.push(`**Exploit path:** ${f.exploitPath}`);
  }
  if (opts.mermaid) {
    const mm = pathMermaid(f);
    if (mm) {
      L.push("");
      L.push("```mermaid");
      L.push(mm);
      L.push("```");
    }
  }
  if (f.references?.length) {
    L.push("");
    L.push(`References: ${f.references.slice(0, 5).map((r) => `<${r}>`).join(" \xB7 ")}`);
  }
  return L.join("\n");
}
function renderReport(d) {
  const fs = sortFindings(d.findings).filter((f) => f.status === "confirmed" || f.status === "needs-human" || f.status === "open");
  const L = [`# Security audit \u2014 report`, "", header(d), ""];
  if (!fs.length) {
    L.push(`No actionable findings. (See FULL.md for dismissed candidates.)`);
    return L.join("\n") + "\n";
  }
  L.push(`Confirmed and to-review findings, most severe first. Dismissed candidates are in FULL.md.`);
  L.push("");
  for (const f of fs) {
    L.push(renderFinding(f, { mermaid: true }));
    L.push("");
    L.push("---");
    L.push("");
  }
  return L.join("\n") + "\n";
}
function renderFull(d) {
  const fs = sortFindings(d.findings);
  const L = [`# Security audit \u2014 full`, "", header(d), ""];
  const groups = [
    ["Confirmed", fs.filter((f) => f.status === "confirmed")],
    ["Needs human review", fs.filter((f) => f.status === "needs-human")],
    ["Unadjudicated candidates", fs.filter((f) => f.status === "open")],
    ["Dismissed", fs.filter((f) => f.status === "dismissed")]
  ];
  for (const [name, list] of groups) {
    if (!list.length) continue;
    L.push(`## ${name} (${list.length})`);
    L.push("");
    for (const f of list) {
      L.push(renderFinding(f, { mermaid: name !== "Dismissed" }));
      L.push("");
    }
  }
  L.push(`---`);
  L.push(`Engine: ultrasec ${d.manifest.version}. ${d.manifest.generatedNote}`);
  return L.join("\n") + "\n";
}

// src/render/html.ts
function esc2(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
var SEV_COLOR = {
  critical: "#b91c1c",
  high: "#c2410c",
  medium: "#b45309",
  low: "#15803d",
  info: "#64748b"
};
function sevRank2(s) {
  return SEVERITIES.indexOf(s);
}
function badge(text, color) {
  return `<span class="badge" style="background:${color}">${esc2(text)}</span>`;
}
function pathHtml(f) {
  if (!f.path?.length) return f.sink ? `<code>${esc2(f.sink.file)}:${f.sink.line}</code>` : "\u2014";
  const nodes = f.path.map((p, i) => {
    const tag = i === 0 ? "source" : i === f.path.length - 1 ? "sink" : "hop";
    const sym = p.symbol ? `<div class="sym">${esc2(p.symbol)}()</div>` : "";
    return `<div class="node ${tag}"><div class="loc">${esc2(p.file)}:${p.line}</div>${sym}<div class="why">${esc2(p.why)}</div></div>`;
  }).join('<div class="arrow">\u2192</div>');
  return `<div class="flow">${nodes}</div>`;
}
function findingHtml(f) {
  const refs = (f.references ?? []).slice(0, 5).map((r) => `<a href="${esc2(r)}" rel="noreferrer noopener">${esc2(r.replace(/^https?:\/\//, ""))}</a>`).join(" \xB7 ");
  return `
  <section class="finding" id="${esc2(f.id)}">
    <h3>${badge(f.severity.toUpperCase(), SEV_COLOR[f.severity])} ${esc2(f.title)}</h3>
    <div class="meta">
      <code>${esc2(f.id)}</code>
      ${f.cwe ? `\xB7 ${esc2(f.cwe)}` : ""} \xB7 ${esc2(f.category)}
      \xB7 status ${badge(f.status, f.status === "confirmed" ? "#b91c1c" : f.status === "needs-human" ? "#b45309" : f.status === "dismissed" ? "#64748b" : "#475569")}
      \xB7 confidence ${esc2(f.confidence)}
      ${f.verdict ? `\xB7 verdict ${esc2(f.verdict)}` : ""}
      ${f.tool !== "ultrasec" ? `\xB7 via ${esc2(f.tool)}` : ""}
    </div>
    ${pathHtml(f)}
    <p class="msg">${esc2(f.message)}</p>
    ${f.exploitPath ? `<p class="exploit"><strong>Exploit path:</strong> ${esc2(f.exploitPath)}</p>` : ""}
    ${refs ? `<p class="refs">${refs}</p>` : ""}
  </section>`;
}
function renderHtml(d) {
  const c = d.manifest.counts.bySeverity;
  const fs = d.findings.slice().sort((a, b) => sevRank2(a.severity) - sevRank2(b.severity) || byStr(a.id, b.id));
  const shown = fs.filter((f) => f.status !== "dismissed");
  const dismissed = fs.filter((f) => f.status === "dismissed");
  const counts = SEVERITIES.map((s) => `${badge(`${s} ${c[s]}`, SEV_COLOR[s])}`).join(" ");
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ultrasec \u2014 security audit</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 980px; margin: 0 auto; padding: 24px; color: #111; background: #fff; }
  @media (prefers-color-scheme: dark) { body { color: #e5e7eb; background: #0b0f17; } a { color: #93c5fd; } code { background: #1f2937; } .node { background: #111827; border-color:#374151; } .finding{border-color:#1f2937;} }
  h1 { font-size: 24px; margin: 0 0 4px; }
  .sub { color: #6b7280; margin-bottom: 16px; }
  .badge { display:inline-block; color:#fff; padding:1px 8px; border-radius:10px; font-size:12px; font-weight:600; }
  code { background:#f3f4f6; padding:1px 5px; border-radius:4px; font-size:13px; }
  .finding { border:1px solid #e5e7eb; border-radius:10px; padding:14px 16px; margin:14px 0; }
  .finding h3 { margin:0 0 6px; font-size:17px; }
  .meta { color:#6b7280; font-size:13px; margin-bottom:10px; }
  .flow { display:flex; flex-wrap:wrap; align-items:stretch; gap:6px; margin:10px 0; }
  .node { background:#f9fafb; border:1px solid #e5e7eb; border-radius:8px; padding:6px 10px; min-width:120px; }
  .node.source { border-color:#b45309; } .node.sink { border-color:#b91c1c; }
  .node .loc { font-family: ui-monospace, monospace; font-size:12px; font-weight:600; }
  .node .sym { font-family: ui-monospace, monospace; font-size:11px; color:#6b7280; }
  .node .why { font-size:11px; color:#6b7280; margin-top:2px; max-width:220px; }
  .arrow { align-self:center; color:#9ca3af; font-size:18px; }
  .msg { margin:8px 0; }
  .exploit { background:#fef2f2; border-left:3px solid #b91c1c; padding:6px 10px; border-radius:4px; }
  @media (prefers-color-scheme: dark){ .exploit{ background:#1f1315; } }
  .refs { font-size:12px; color:#6b7280; word-break:break-all; }
  details { margin-top:18px; }
</style></head>
<body>
  <h1>Security audit</h1>
  <div class="sub">repo <code>${esc2(d.manifest.repo)}</code> \xB7 ultrasec ${esc2(d.manifest.version)} \xB7 tools: ${esc2(d.manifest.toolsRun.join(", ") || "none")}</div>
  <div>${counts}</div>
  ${shown.length ? shown.map(findingHtml).join("\n") : "<p>No actionable findings.</p>"}
  ${dismissed.length ? `<details><summary>${dismissed.length} dismissed candidate(s)</summary>${dismissed.map(findingHtml).join("\n")}</details>` : ""}
</body></html>
`;
}

// src/commands/render.ts
function runRender(args) {
  const run = resolve6(flagStr(args, "run") ?? ".ultrasec");
  let dossier;
  try {
    dossier = loadDossier(run);
  } catch (e) {
    eprintln(`ultrasec render: ${e.message}`);
    return 2;
  }
  const outputs = [
    ["SUMMARY.md", renderSummary(dossier)],
    ["REPORT.md", renderReport(dossier)],
    ["FULL.md", renderFull(dossier)],
    ["index.html", renderHtml(dossier)]
  ];
  for (const [name, body] of outputs) writeFileSync3(join7(run, name), body);
  println(`ultrasec render \u2192 ${run}`);
  for (const [name] of outputs) println(`  ${join7(run, name)}`);
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
    case "scan":
      return runScan(args);
    case "dossier":
      return runDossier(args);
    case "paths":
      return runPaths(args);
    case "verify":
      return runVerify(args);
    case "check":
      return runCheck(args);
    case "render":
      return runRender(args);
    default:
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

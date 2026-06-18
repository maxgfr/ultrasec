#!/usr/bin/env node

// src/types.ts
var VERSION = "1.2.0";
var SCHEMA_VERSION = 2;
var SEVERITIES = ["critical", "high", "medium", "low", "info"];
var VERDICTS = ["supported", "partial", "unsupported", "refuted"];

// src/util.ts
import { createHash } from "crypto";
function parseArgs(argv) {
  const _ = [];
  const flags = /* @__PURE__ */ Object.create(null);
  const set = (key, val) => {
    if (Object.prototype.hasOwnProperty.call(flags, key)) {
      const cur = flags[key];
      if (Array.isArray(cur)) cur.push(val);
      else flags[key] = [cur, val];
    } else {
      flags[key] = val;
    }
  };
  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i];
    if (tok.startsWith("--")) {
      const body = tok.slice(2);
      const eq = body.indexOf("=");
      if (eq >= 0) {
        set(body.slice(0, eq), body.slice(eq + 1));
        continue;
      }
      const next = argv[i + 1];
      if (next !== void 0 && !next.startsWith("--")) {
        set(body, next);
        i++;
      } else {
        set(body, true);
      }
    } else {
      _.push(tok);
    }
  }
  return { _, flags };
}
function flagStr(args, name) {
  const v = args.flags[name];
  if (Array.isArray(v)) {
    for (let i = v.length - 1; i >= 0; i--) if (typeof v[i] === "string") return v[i];
    return void 0;
  }
  return typeof v === "string" ? v : void 0;
}
function flagBool(args, name) {
  const v = args.flags[name];
  if (Array.isArray(v)) return v.some((x) => x === true || x === "true");
  return v === true || v === "true";
}
function listFlag(args, name) {
  const v = args.flags[name];
  if (v === void 0) return void 0;
  const raw = Array.isArray(v) ? v : [v];
  const parts = raw.flatMap((x) => typeof x === "string" ? x.split(",") : []).map((s) => s.trim()).filter(Boolean);
  return parts.length ? parts : void 0;
}
function numFlag(args, name) {
  const v = flagStr(args, name);
  if (v === void 0) return void 0;
  const n = Number(v);
  return Number.isFinite(n) ? n : void 0;
}
function own(obj, key) {
  return obj != null && Object.prototype.hasOwnProperty.call(obj, key) ? obj[key] : void 0;
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
    description: "IaC/misconfig with a cross-resource graph (Terraform, k8s, Dockerfile, CloudFormation\u2026) \u2014 deeper than per-block scanning.",
    languages: ["*"],
    install: { pip: "pipx install checkov", docker: "bridgecrew/checkov", url: "https://www.checkov.io/" },
    runHint: "checkov -d <repo> -o json --compact --quiet --soft-fail",
    primary: true
  },
  {
    name: "bandit",
    category: "sast",
    description: "Python AST security linter \u2014 dangerous idioms (shell=True, eval, weak crypto, pickle/yaml.load) a taint engine can't see.",
    languages: ["python"],
    install: { pip: "pipx install bandit", docker: "ghcr.io/pycqa/bandit", url: "https://bandit.readthedocs.io/" },
    runHint: "bandit -r <repo> -f json -ll -ii -q"
  },
  {
    name: "gosec",
    category: "sast",
    description: "Go security checker, stdlib-aware (math/rand, InsecureSkipVerify, exec with tainted args, SQL concat).",
    languages: ["go"],
    install: { brew: "brew install gosec", go: "go install github.com/securego/gosec/v2/cmd/gosec@latest", docker: "ghcr.io/securego/gosec", url: "https://github.com/securego/gosec" },
    runHint: "gosec -fmt json -quiet -no-fail ./..."
  },
  {
    name: "hadolint",
    category: "config",
    description: "Dockerfile linter with ShellCheck embedded \u2014 audits the bash inside RUN, which trivy/checkov don't.",
    languages: ["docker"],
    install: { brew: "brew install hadolint", docker: "hadolint/hadolint", url: "https://github.com/hadolint/hadolint" },
    runHint: "hadolint --format json --no-fail <Dockerfile\u2026>"
  },
  {
    name: "kingfisher",
    category: "secret",
    description: "Secret scanner: offline checksum+entropy+language-aware pre-filter (fewer FPs), 950+ rules, git history, SARIF.",
    languages: ["*"],
    install: { brew: "brew install kingfisher", docker: "ghcr.io/mongodb/kingfisher", url: "https://github.com/mongodb/kingfisher" },
    runHint: "kingfisher scan <repo> --format sarif --no-validate"
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
import { readFileSync, readdirSync, lstatSync, statSync, realpathSync } from "fs";
import { join, relative, resolve, sep } from "path";
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
function globToRe(pattern) {
  let p = pattern.replace(/^\.\//, "").replace(/\/+$/g, (m) => m ? "/" : "");
  let dirMatch = false;
  if (p.endsWith("/")) {
    dirMatch = true;
    p = p.slice(0, -1);
  }
  let re = "";
  let i = 0;
  while (i < p.length) {
    if (p.startsWith("**/", i)) {
      re += "(?:.*/)?";
      i += 3;
      continue;
    }
    if (p.startsWith("**", i)) {
      re += ".*";
      i += 2;
      continue;
    }
    const ch = p[i];
    if (ch === "*") {
      re += "[^/]*";
      i++;
    } else if (ch === "?") {
      re += "[^/]";
      i++;
    } else if (ch === "[") {
      let j = i + 1;
      const neg = p[j] === "!" || p[j] === "^";
      if (neg) j++;
      if (p[j] === "]") j++;
      while (j < p.length && p[j] !== "]") j++;
      if (j >= p.length) {
        re += "\\[";
        i++;
      } else {
        const cls = p.slice(neg ? i + 2 : i + 1, j).replace(/\\/g, "\\\\").replace(/\]/g, "\\]");
        re += neg ? `[^/${cls}]` : `[${cls}]`;
        i = j + 1;
      }
    } else {
      re += ch.replace(/[.+^${}()|[\]\\]/g, "\\$&");
      i++;
    }
  }
  const body = dirMatch ? re + "(?:/.*)?" : re;
  return new RegExp("^" + body + "$");
}
function literalBase(s) {
  const clean = s.replace(/^\.\//, "").replace(/\/+$/, "");
  const wi = clean.search(/[*?]/);
  if (wi === -1) return clean;
  const lit = clean.slice(0, wi);
  const slash = lit.lastIndexOf("/");
  return slash === -1 ? "" : lit.slice(0, slash);
}
function toScopeEntries(scopes) {
  return scopes.map((raw) => {
    const clean = raw.replace(/^\.\//, "").replace(/\/+$/, "");
    const hasWild = /[*?]/.test(clean);
    return { raw: clean, base: literalBase(clean), re: hasWild ? globToRe(clean) : void 0 };
  });
}
function dirInScope(relDir, scopes) {
  if (relDir === "") return true;
  for (const sc of scopes) {
    const base = sc.base;
    if (base === "") return true;
    if (relDir === base) return true;
    if (relDir.startsWith(base + "/")) return true;
    if (base.startsWith(relDir + "/")) return true;
  }
  return false;
}
function fileInScope(rel, scopes) {
  for (const sc of scopes) {
    if (sc.re) {
      if (sc.re.test(rel)) return true;
    } else if (rel === sc.raw || rel.startsWith(sc.raw + "/")) {
      return true;
    }
  }
  return false;
}
function parseGitignore(content) {
  const rules = [];
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const negated = line.startsWith("!");
    let body = negated ? line.slice(1) : line;
    if (body.startsWith("\\")) body = body.slice(1);
    const rooted = body.startsWith("/");
    let pat = rooted ? body.slice(1) : body;
    const dirOnly = pat.endsWith("/");
    if (dirOnly) pat = pat.replace(/\/+$/, "");
    if (!pat) continue;
    const anchored = rooted || pat.includes("/");
    const g = anchored ? pat : "**/" + pat;
    rules.push({ glob: g + "/", negated });
    if (!dirOnly) rules.push({ glob: g, negated });
  }
  return rules;
}
function walk(root, opts = {}) {
  return walkWithMeta(root, opts).files;
}
function walkWithMeta(root, opts = {}) {
  const ignore = opts.ignoreDirs ?? DEFAULT_IGNORE_DIRS;
  const maxBytes = opts.maxBytes ?? MAX_FILE_BYTES;
  const maxFiles = opts.maxFiles ?? Infinity;
  const scopes = opts.scope && opts.scope.length ? toScopeEntries(opts.scope) : void 0;
  const includeRes = opts.include && opts.include.length ? opts.include.map(globToRe) : void 0;
  const userExcludeRes = opts.exclude && opts.exclude.length ? opts.exclude.map(globToRe) : void 0;
  const giRules = [];
  if (opts.gitignore) {
    try {
      for (const r of parseGitignore(readFileSync(join(root, ".gitignore"), "utf8"))) giRules.push({ re: globToRe(r.glob), negated: r.negated });
    } catch {
    }
  }
  const isExcluded = (rel) => {
    if (userExcludeRes && userExcludeRes.some((re) => re.test(rel))) return true;
    let ex = false;
    for (const r of giRules) if (r.re.test(rel)) ex = !r.negated;
    return ex;
  };
  let rootReal;
  try {
    rootReal = realpathSync(root);
  } catch {
    rootReal = resolve(root);
  }
  const out = [];
  let truncated = false;
  const visit = (dir) => {
    if (truncated) return;
    let entries;
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of entries.sort(byStr)) {
      if (truncated) return;
      const abs = join(dir, name);
      let st;
      try {
        st = lstatSync(abs);
      } catch {
        continue;
      }
      if (st.isSymbolicLink()) {
        try {
          const real = realpathSync(abs);
          if (real !== rootReal && !real.startsWith(rootReal + sep)) continue;
          const target = statSync(abs);
          if (target.isDirectory()) continue;
          st = target;
        } catch {
          continue;
        }
      }
      const rel = relative(root, abs).split(sep).join("/");
      if (st.isDirectory()) {
        if (ignore.has(name)) continue;
        if (scopes && !dirInScope(rel, scopes)) continue;
        if (isExcluded(rel)) continue;
        visit(abs);
      } else if (st.isFile()) {
        if (st.size > maxBytes) continue;
        if (scopes && !fileInScope(rel, scopes)) continue;
        if (includeRes && !includeRes.some((re) => re.test(rel))) continue;
        if (isExcluded(rel)) continue;
        if (out.length >= maxFiles) {
          truncated = true;
          return;
        }
        out.push({ rel, abs, bytes: st.size });
      }
    }
  };
  visit(root);
  const files = out.sort((a, b) => byStr(a.rel, b.rel));
  return { files, truncated, totalSeen: files.length };
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
      const before = cm.index > 0 ? line[cm.index - 1] : "";
      if (before && /[\w$]/.test(before)) continue;
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
  const { files: walked, truncated } = walkWithMeta(repo, {
    maxBytes: opts.maxBytes,
    scope: opts.scope,
    include: opts.include,
    exclude: opts.exclude,
    maxFiles: opts.maxFiles,
    gitignore: opts.gitignore
  });
  const files = [];
  for (const wf of walked) {
    const spec = langForFile(wf.rel);
    if (!spec) continue;
    const { symbols, imports, calls } = extract(spec, readText(wf.abs));
    files.push({ rel: wf.rel, lang: spec.id, symbols, imports, calls });
  }
  files.sort((a, b) => byStr(a.rel, b.rel));
  return { repo, files, truncated, walkedFiles: walked.length };
}
function scanRepoCached(repo, opts, cache) {
  const { files: walked, truncated } = walkWithMeta(repo, {
    maxBytes: opts.maxBytes,
    scope: opts.scope,
    include: opts.include,
    exclude: opts.exclude,
    maxFiles: opts.maxFiles,
    gitignore: opts.gitignore
  });
  const files = [];
  for (const wf of walked) {
    const spec = langForFile(wf.rel);
    if (!spec) continue;
    const content = readText(wf.abs);
    const hash = shortHash(content);
    const cached = cache.get(wf.rel);
    let fileScan;
    if (cached && cached.hash === hash) {
      fileScan = cached.fileScan;
    } else {
      const { symbols, imports, calls } = extract(spec, content);
      fileScan = { rel: wf.rel, lang: spec.id, symbols, imports, calls };
    }
    files.push(fileScan);
    cache.set(wf.rel, { hash, fileScan });
  }
  files.sort((a, b) => byStr(a.rel, b.rel));
  return { repo, files, truncated, walkedFiles: walked.length };
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
    if (seg === "..") {
      if (parts.length && parts[parts.length - 1] !== "..") parts.pop();
      else parts.push("..");
    } else parts.push(seg);
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
  const callers = /* @__PURE__ */ new Map();
  for (const f of scan.files) {
    for (const imp of f.imports) {
      const to = resolveImport(f.rel, imp.spec, fileSet);
      if (to && to !== f.rel) add(edgeMap, { from: f.rel, to, kind: "import", weight: 1 });
    }
    for (const c of f.calls) {
      const callerSym = enclosingSymbol(f.symbols, c.line);
      (callers.get(c.callee) ?? callers.set(c.callee, []).get(c.callee)).push({ file: f.rel, line: c.line, symbol: callerSym });
      const targets = defs.get(c.callee);
      if (!targets || targets.size !== 1) continue;
      const to = [...targets][0];
      if (to === f.rel) continue;
      add(edgeMap, { from: f.rel, to, kind: "call", weight: 1, fromSymbol: callerSym, toSymbol: c.callee });
    }
  }
  const edges = [...edgeMap.values()].sort(
    (a, b) => byStr(a.from, b.from) || byStr(a.to, b.to) || byStr(a.kind, b.kind) || byStr(a.toSymbol ?? "", b.toSymbol ?? "")
  );
  const callersBySymbol = {};
  for (const [name, refs] of [...callers.entries()].sort((a, b) => byStr(a[0], b[0]))) {
    callersBySymbol[name] = refs.sort((a, b) => byStr(a.file, b.file) || a.line - b.line);
  }
  return { files: [...fileSet].sort(byStr), edges, symbolDefs, callersBySymbol };
}
var edgeSort = (a, b) => byStr(a.from, b.from) || byStr(a.to, b.to) || byStr(a.kind, b.kind) || byStr(a.toSymbol ?? "", b.toSymbol ?? "");
function mergeGraphs(a, b) {
  const files = [.../* @__PURE__ */ new Set([...a.files, ...b.files])].sort(byStr);
  const edgeMap = /* @__PURE__ */ new Map();
  for (const e of [...a.edges, ...b.edges]) {
    const k = keyOf(e);
    const prev = edgeMap.get(k);
    if (prev) prev.weight = Math.max(prev.weight, e.weight);
    else edgeMap.set(k, { ...e });
  }
  const edges = [...edgeMap.values()].sort(edgeSort);
  const symbolDefs = {};
  for (const src of [a.symbolDefs, b.symbolDefs]) {
    for (const [name, defFiles] of Object.entries(src)) {
      const prev = Array.isArray(symbolDefs[name]) ? symbolDefs[name] : [];
      symbolDefs[name] = [.../* @__PURE__ */ new Set([...prev, ...defFiles])].sort(byStr);
    }
  }
  const callersBySymbol = {};
  for (const src of [a.callersBySymbol ?? {}, b.callersBySymbol ?? {}]) {
    for (const [name, refs] of Object.entries(src)) {
      const existing = Array.isArray(callersBySymbol[name]) ? callersBySymbol[name] : [];
      const seen = new Set(existing.map((r) => `${r.file}:${r.line}:${r.symbol ?? ""}`));
      const merged = [...existing];
      for (const r of refs) {
        const k = `${r.file}:${r.line}:${r.symbol ?? ""}`;
        if (!seen.has(k)) {
          seen.add(k);
          merged.push(r);
        }
      }
      callersBySymbol[name] = merged.sort((x, y) => byStr(x.file, y.file) || x.line - y.line);
    }
  }
  return { files, edges, symbolDefs, callersBySymbol };
}
function reverseDependents(graph, seeds, depth) {
  const inbound = /* @__PURE__ */ new Map();
  for (const e of graph.edges) (inbound.get(e.to) ?? inbound.set(e.to, []).get(e.to)).push(e.from);
  const seen = new Set(seeds);
  let frontier = [...seeds];
  for (let d = 0; d < depth && frontier.length; d++) {
    const next = [];
    for (const node of frontier) {
      for (const from of inbound.get(node) ?? []) {
        if (seen.has(from)) continue;
        seen.add(from);
        next.push(from);
      }
    }
    frontier = next;
  }
  return [...seen].sort(byStr);
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
        links.push({ node: e.from, direction: "in", kind: e.kind, weight: e.weight, depth: d, symbol: e.fromSymbol });
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
    if (Array.isArray(defs) && defs.length === 1) node = defs[0];
    else if (Array.isArray(defs) && defs.length > 1) {
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

// src/commands/map.ts
import { resolve as resolve2, join as join3 } from "path";
import { mkdirSync, writeFileSync, readFileSync as readFileSync2, existsSync } from "fs";

// src/map.ts
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
    callees: ["readFile", "readFileSync", "writeFile", "writeFileSync", "createReadStream", "createWriteStream", "sendFile", "unlink", "open", "readdir", "appendFile", "extractall", "extract", "unzip", "extractAll"],
    title: "Path traversal / archive extraction (zip-slip)",
    note: "Tainted data used as a filesystem path, or an archive extracted without validating entry names (zip-slip). Confine to a base dir (basename/realpath + allow-list) and reject entries that escape it."
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
  },
  {
    kind: "nosql",
    cwe: "CWE-943",
    severity: "high",
    languages: ["javascript", "python"],
    callees: ["find", "findOne", "findOneAndUpdate", "findOneAndDelete", "updateOne", "deleteOne", "aggregate", "mapReduce", "distinct"],
    receivers: ["db", "collection", "coll", "Model", "model", "User", "users", "mongo", "mongoose", "repo", "repository"],
    title: "NoSQL injection",
    note: "Tainted data shaped into a NoSQL query object/operator ($where, $ne, $gt \u2026). Coerce types and reject operator keys (mongo-sanitize); never pass a raw request object as a filter."
  },
  {
    kind: "ssti",
    cwe: "CWE-1336",
    severity: "high",
    languages: ["*"],
    callees: ["from_string", "renderString", "compileString", "Template", "createTemplate", "renderTemplate"],
    title: "Server-side template injection (SSTI)",
    note: "Tainted data compiled into a template. Render data as context VALUES, never concatenate into the template source; enable autoescaping."
  },
  {
    kind: "xxe",
    cwe: "CWE-611",
    severity: "high",
    languages: ["*"],
    callees: ["parseString", "parseXml", "parseFromString", "fromstring", "SAXParser", "DocumentBuilder", "XMLReader", "createDocument"],
    title: "XML external entity (XXE)",
    note: "Tainted XML parsed with external entities/DTDs enabled. Disable entity resolution (resolve_entities=False / FEATURE_SECURE_PROCESSING / noent off)."
  },
  {
    kind: "ldap",
    cwe: "CWE-90",
    severity: "high",
    languages: ["*"],
    callees: ["search", "bind", "searchSync"],
    receivers: ["ldap", "ldapClient", "ldapjs", "client", "conn", "connection", "ld"],
    title: "LDAP injection",
    note: "Tainted data concatenated into an LDAP filter/DN. Escape with the LDAP escaping API (ldap.escape / escapeFilter / escapeDN)."
  },
  {
    kind: "crlf",
    cwe: "CWE-93",
    severity: "medium",
    languages: ["javascript", "python", "java", "go", "php", "ruby"],
    callees: ["setHeader", "header", "addHeader", "setRequestHeader", "putHeader"],
    receivers: ["res", "response", "resp", "w", "headers"],
    title: "HTTP response splitting / header (CRLF) injection",
    note: "Tainted data written into a response header. Strip CR/LF (\\r\\n) or use an API that rejects them."
  },
  {
    kind: "proto",
    cwe: "CWE-1321",
    severity: "high",
    languages: ["javascript"],
    callees: ["merge", "mergeWith", "extend", "defaultsDeep", "setWith", "set"],
    receivers: ["_", "lodash", "$", "jQuery", "angular", "Object", "util"],
    title: "Prototype pollution",
    note: "Tainted keys deep-merged into an object can reach Object.prototype (__proto__/constructor/prototype). Reject those keys or use a null-prototype target / Map."
  },
  {
    kind: "buffer",
    cwe: "CWE-120",
    severity: "high",
    languages: ["c_cpp"],
    callees: ["strcpy", "strcat", "sprintf", "gets", "memcpy", "stpcpy", "vsprintf"],
    title: "Classic buffer overflow (unbounded copy)",
    note: "Best-effort (C/C++): tainted data into an unbounded copy. Prefer the bounded forms (strncpy/snprintf/memcpy with a checked length). Pair with cppcheck/gosec."
  }
];
function findSinks(lang, calls) {
  const out = [];
  for (const c of calls) {
    for (const rule of SINKS) {
      if (!appliesTo(rule.languages, lang.id)) continue;
      if (!rule.callees.includes(c.callee)) continue;
      if (rule.receivers && c.receiver && !rule.receivers.includes(c.receiver)) continue;
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
  { kind: "http", languages: ["javascript"], re: /(?<![\w.])req(?:uest)?\s*\.\s*(?:query|body|params|headers|cookies|url|originalUrl|hostname|ip|files|file)\b/, title: "HTTP request input" },
  { kind: "ws", languages: ["javascript"], re: /\.on\s*\(\s*['"](?:message|data)['"]/, title: "WebSocket/stream message" },
  { kind: "http", languages: ["javascript"], re: /\bctx\s*\.\s*(?:request|query|params|body)\b/, title: "Koa/HTTP context input" },
  { kind: "http", languages: ["python"], re: /(?<![\w.])request\s*\.\s*(?:args|form|values|json|data|files|cookies|headers|GET|POST)\b/, title: "HTTP request input" },
  { kind: "http", languages: ["php"], re: /\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b/, title: "HTTP superglobal input" },
  { kind: "http", languages: ["java", "kotlin", "scala"], re: /\.get(?:Parameter|Header|QueryString)\s*\(/, title: "Servlet request input" },
  { kind: "http", languages: ["ruby"], re: /(?<![\w.])params\s*\[/, title: "Rails params input" },
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
  { kind: "command", languages: ["*"], re: /\bexecFile\b|\bexecvp?\b|shlex\.quote|escapeshellarg/, note: "argv-array / quoting present" },
  { kind: "path", languages: ["*"], re: /\bbasename\b|\brealpath\b|secure_filename|path\.resolve|startsWith\(/, note: "path-confinement helper present" },
  { kind: "xss", languages: ["*"], re: /\bescape(?:Html)?\b|sanitize|DOMPurify|bleach|markupsafe|escapeHTML/, note: "escaping/sanitizer present" },
  { kind: "deserialize", languages: ["*"], re: /safe_load|safeLoad|JSON\.parse/, note: "safe loader present" },
  { kind: "nosql", languages: ["*"], re: /mongo-?[sS]anitize|sanitizeFilter|\$eq\b/, note: "operator-stripping sanitizer present" },
  { kind: "xxe", languages: ["*"], re: /resolve_entities\s*=\s*False|feature_external_ges|FEATURE_SECURE_PROCESSING|noent\s*=\s*False|XMLConstants/, note: "external-entity resolution disabled" },
  { kind: "ldap", languages: ["*"], re: /ldap\.escape|escapeDN|escapeFilter|escape_filter_chars/, note: "LDAP escaping present" },
  { kind: "crlf", languages: ["*"], re: /encodeURIComponent|stripCRLF|replace\(\s*\/[^/]*[\\]r/, note: "CR/LF stripping present" },
  { kind: "proto", languages: ["*"], re: /__proto__|Object\.freeze|Object\.create\(\s*null|hasOwnProperty|structuredClone/, note: "prototype-pollution guard present" },
  { kind: "ssti", languages: ["*"], re: /autoescape|markupsafe|\|\s*e\b|escape\(/, note: "template autoescaping present" },
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

// src/map.ts
var SEV_WEIGHT = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
var MAX_SAMPLES = 8;
function topDir(rel) {
  const i = rel.indexOf("/");
  return i === -1 ? "." : rel.slice(0, i);
}
function buildAttackSurface(scan, coveredScopes = []) {
  const covered = new Set(coveredScopes);
  const entryByKind = /* @__PURE__ */ new Map();
  const sinkByKind = /* @__PURE__ */ new Map();
  const langAgg = /* @__PURE__ */ new Map();
  const dirAgg = /* @__PURE__ */ new Map();
  let totalSources = 0;
  let totalSinks = 0;
  for (const f of scan.files) {
    const lang = langForFile(f.rel);
    if (!lang) continue;
    const dir = topDir(f.rel);
    const la = langAgg.get(f.lang) ?? langAgg.set(f.lang, { lang: f.lang, files: 0, sources: 0, sinks: 0 }).get(f.lang);
    const da = dirAgg.get(dir) ?? dirAgg.set(dir, { dir, files: 0, sources: 0, sinks: 0, score: 0 }).get(dir);
    la.files++;
    da.files++;
    const sources = findSources(lang, readText(join2(scan.repo, f.rel)));
    for (const s of sources) {
      totalSources++;
      la.sources++;
      da.sources++;
      const arr = entryByKind.get(s.kind) ?? entryByKind.set(s.kind, []).get(s.kind);
      arr.push({ file: f.rel, line: s.line, kind: s.kind, title: s.title });
    }
    for (const sink of findSinks(lang, f.calls)) {
      totalSinks++;
      la.sinks++;
      da.sinks++;
      da.score += SEV_WEIGHT[sink.severity];
      const ss = sinkByKind.get(sink.kind) ?? sinkByKind.set(sink.kind, { kind: sink.kind, cwe: sink.cwe, severity: sink.severity, count: 0, samples: [] }).get(sink.kind);
      ss.count++;
      if (ss.samples.length < MAX_SAMPLES) ss.samples.push({ file: f.rel, line: sink.line, callee: sink.callee });
    }
  }
  const entryPoints = [...entryByKind.entries()].sort((a, b) => byStr(a[0], b[0])).map(([kind, eps]) => {
    const sorted = eps.sort((a, b) => byStr(a.file, b.file) || a.line - b.line);
    return { kind, count: sorted.length, samples: sorted.slice(0, MAX_SAMPLES) };
  });
  const sinks = [...sinkByKind.values()].sort(
    (a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || b.count - a.count || byStr(a.kind, b.kind)
  );
  for (const s of sinks) s.samples.sort((a, b) => byStr(a.file, b.file) || a.line - b.line);
  const byLanguage = [...langAgg.values()].sort((a, b) => byStr(a.lang, b.lang));
  const byTopDir = [...dirAgg.values()].sort((a, b) => b.score - a.score || b.sinks - a.sinks || byStr(a.dir, b.dir));
  const suggestedTargets = byTopDir.filter((d) => d.sinks > 0 || d.sources > 0).map((d) => ({
    scope: d.dir,
    sinks: d.sinks,
    sources: d.sources,
    score: d.score,
    covered: covered.has(d.dir),
    reason: `${d.sinks} sink(s), ${d.sources} entry point(s) across ${d.files} file(s)`
  }));
  return {
    totals: { files: scan.files.length, sources: totalSources, sinks: totalSinks, truncated: !!scan.truncated },
    entryPoints,
    sinks,
    byLanguage,
    byTopDir,
    suggestedTargets
  };
}
function renderMapMd(repo, s) {
  const L = [];
  L.push(`# ultrasec attack-surface map`);
  L.push("");
  L.push(`- repo: \`${repo}\``);
  L.push(`- files: ${s.totals.files} \xB7 entry points: ${s.totals.sources} \xB7 sinks: ${s.totals.sinks}`);
  if (s.totals.truncated) L.push(`- \u26A0\uFE0F partial walk (\`--max-files\` hit) \u2014 some files were not mapped.`);
  L.push("");
  L.push(`> The cheap recon pass: WHERE untrusted input enters and WHAT dangerous sinks`);
  L.push(`> exist \u2014 no taint BFS, no tools, no network. Use it to pick \`--scope\` targets,`);
  L.push(`> then \`ultrasec scan --scope <dir> --merge\` to drill in. The order below is a`);
  L.push(`> deterministic suggestion \u2014 override it with your own judgement.`);
  L.push("");
  L.push(`## Suggested targets (highest attack-surface density first)`);
  L.push("");
  if (!s.suggestedTargets.length) {
    L.push(`_No sources or sinks detected._`);
  } else {
    for (const t of s.suggestedTargets) {
      L.push(`- ${t.covered ? "\u2705" : "\u25A2"} \`${t.scope}\` \u2014 ${t.reason}${t.covered ? " \xB7 already scanned" : ""}`);
    }
    const next = s.suggestedTargets.find((t) => !t.covered);
    if (next) {
      L.push("");
      L.push(`**Next:** \`ultrasec scan --repo ${repo} --scope ${next.scope} --merge --out <run>\``);
    }
  }
  L.push("");
  L.push(`## Entry points (untrusted input)`);
  L.push("");
  if (!s.entryPoints.length) L.push(`_None detected._`);
  for (const g of s.entryPoints) {
    L.push(`- **${g.kind}** (${g.count}): ${g.samples.map((e) => `\`${e.file}:${e.line}\``).join(", ")}${g.count > g.samples.length ? " \u2026" : ""}`);
  }
  L.push("");
  L.push(`## Sinks by class`);
  L.push("");
  if (!s.sinks.length) L.push(`_None detected._`);
  for (const k of s.sinks) {
    L.push(`- **${k.kind}** (${k.cwe}, ${k.severity}) \xD7${k.count}: ${k.samples.map((x) => `\`${x.file}:${x.line}\``).join(", ")}${k.count > k.samples.length ? " \u2026" : ""}`);
  }
  L.push("");
  L.push(`## By language`);
  L.push("");
  for (const l of s.byLanguage) L.push(`- ${l.lang}: ${l.files} file(s), ${l.sources} entry point(s), ${l.sinks} sink(s)`);
  L.push("");
  return L.join("\n") + "\n";
}

// src/commands/map.ts
async function runMap(args) {
  const repo = resolve2(flagStr(args, "repo") ?? ".");
  const out = flagStr(args, "out");
  const scope = listFlag(args, "scope");
  const include = listFlag(args, "include");
  const exclude = listFlag(args, "exclude");
  const maxFiles = numFlag(args, "max-files");
  const gitignore = flagBool(args, "gitignore");
  let coveredScopes = [];
  if (out) {
    const mPath = join3(resolve2(out), "manifest.json");
    if (existsSync(mPath)) {
      try {
        const m = JSON.parse(readFileSync2(mPath, "utf8"));
        if (Array.isArray(m.scopes)) coveredScopes = m.scopes;
      } catch {
      }
    }
  }
  const scan = scanRepo(repo, { scope, include, exclude, maxFiles, gitignore });
  const surface = buildAttackSurface(scan, coveredScopes);
  if (out) {
    const outDir = resolve2(out);
    mkdirSync(outDir, { recursive: true });
    writeFileSync(join3(outDir, "attack-surface.json"), JSON.stringify(surface, null, 2));
    writeFileSync(join3(outDir, "MAP.md"), renderMapMd(repo, surface));
  }
  if (flagBool(args, "json")) {
    println(JSON.stringify(surface, null, 2));
    return 0;
  }
  println(renderMapMd(repo, surface));
  if (out) println(`
wrote ${join3(resolve2(out), "MAP.md")} + attack-surface.json`);
  return 0;
}

// src/commands/scan.ts
import { resolve as resolve3, join as join9, relative as relative2 } from "path";
import { existsSync as existsSync5 } from "fs";

// src/taint.ts
import { join as join4 } from "path";
var DEFAULT_MAX_DEPTH = 6;
var DEFAULT_MAX_CANDIDATES = 1e3;
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
function enumerateTaint(scan, graph, opts = {}) {
  const MAX_DEPTH = opts.maxDepth ?? DEFAULT_MAX_DEPTH;
  const maxCandidates = opts.maxCandidates ?? DEFAULT_MAX_CANDIDATES;
  const byRel = new Map(scan.files.map((f) => [f.rel, f]));
  const contentCache = /* @__PURE__ */ new Map();
  const sourceCache = /* @__PURE__ */ new Map();
  const lineCache = /* @__PURE__ */ new Map();
  const content = (rel) => {
    let c = contentCache.get(rel);
    if (c === void 0) contentCache.set(rel, c = readText(join4(scan.repo, rel)));
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
    const crossFile2 = new Set(path.map((p) => p.file)).size > 1;
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
      message: `${crossFile2 ? "Cross-file" : "Intra-file"} candidate: ${srcHit.kind} input at ${srcStep.file}:${srcStep.line} may reach the ${sink.kind} sink ${sink.callee}() at ${sinkFile}:${sink.line} through ${path.length - 1} hop(s). ${sink.note}${note} Heuristic \u2014 verify the data actually reaches the sink unsanitized before trusting it.`,
      tool: "ultrasec",
      references: [cweUrl(sink.cwe)],
      status: "open"
    });
  };
  for (const file of scan.files) {
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
        if (!Array.isArray(defs) || !defs.includes(fr.file)) continue;
        const callerList = graph.callersBySymbol?.[fr.sym];
        for (const caller of Array.isArray(callerList) ? callerList : []) {
          if (caller.file === fr.file) continue;
          const key = `${caller.file}#${caller.symbol ?? caller.line}`;
          if (visited.has(key)) continue;
          visited.add(key);
          const hop = { file: caller.file, line: caller.line, symbol: caller.symbol, why: `calls ${fr.sym}()` };
          queue.push({ file: caller.file, sym: caller.symbol, entryLine: caller.line, hops: [hop, ...fr.hops], depth: fr.depth + 1 });
        }
      }
    }
  }
  const crossFile = (f) => f.path && new Set(f.path.map((p) => p.file)).size > 1 ? 1 : 0;
  const proximity = (f) => f.path ? f.path.length : Number.MAX_SAFE_INTEGER;
  findings.sort(
    (a, b) => severityRank(a.severity) - severityRank(b.severity) || proximity(a) - proximity(b) || crossFile(b) - crossFile(a) || byStr(a.id, b.id)
  );
  const total = findings.length;
  const kept = total > maxCandidates ? findings.slice(0, maxCandidates) : findings;
  return { findings: kept, truncated: total - kept.length, total };
}

// src/git.ts
import { execFileSync as execFileSync2 } from "child_process";
function git(repo, args) {
  try {
    return execFileSync2("git", ["-C", repo, ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      maxBuffer: 64 * 1024 * 1024
    });
  } catch {
    return null;
  }
}
function isGitRepo(repo) {
  return git(repo, ["rev-parse", "--is-inside-work-tree"])?.trim() === "true";
}
function changedFiles(repo, ref) {
  if (!isGitRepo(repo)) return null;
  if (git(repo, ["rev-parse", "--verify", "--quiet", `${ref}^{commit}`]) === null) return null;
  const out = /* @__PURE__ */ new Set();
  const diff = git(repo, ["diff", "--name-only", "--diff-filter=d", `${ref}...HEAD`]);
  if (diff === null) return null;
  for (const line of diff.split(/\r?\n/)) if (line.trim()) out.add(line.trim());
  const worktree = git(repo, ["diff", "--name-only", "--diff-filter=d", ref]);
  if (worktree) {
    for (const line of worktree.split(/\r?\n/)) if (line.trim()) out.add(line.trim());
  }
  const untracked = git(repo, ["ls-files", "--others", "--exclude-standard"]);
  if (untracked) {
    for (const line of untracked.split(/\r?\n/)) if (line.trim()) out.add(line.trim());
  }
  return [...out].sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
}

// src/cache.ts
import { mkdirSync as mkdirSync2, writeFileSync as writeFileSync2, readFileSync as readFileSync3 } from "fs";
import { join as join5 } from "path";
var CACHE_VERSION = 1;
function cachePath(run) {
  return join5(run, "cache", "scan-cache.json");
}
function loadScanCache(run) {
  try {
    const data = JSON.parse(readFileSync3(cachePath(run), "utf8"));
    if (!data || data.cacheVersion !== CACHE_VERSION || typeof data.entries !== "object") return /* @__PURE__ */ new Map();
    return new Map(Object.entries(data.entries));
  } catch {
    return /* @__PURE__ */ new Map();
  }
}
function saveScanCache(run, cache) {
  const dir = join5(run, "cache");
  mkdirSync2(dir, { recursive: true });
  const entries = {};
  for (const [k, v] of [...cache.entries()].sort((a, b) => byStr(a[0], b[0]))) entries[k] = v;
  writeFileSync2(cachePath(run), JSON.stringify({ cacheVersion: CACHE_VERSION, entries }, null, 2));
}

// src/tools/run.ts
import { execFileSync as execFileSync3 } from "child_process";

// src/tools/normalize.ts
var SEVERITY_ALIASES = Object.assign(/* @__PURE__ */ Object.create(null), {
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
});
function normalizeSeverity(raw, fallback = "medium") {
  if (!raw) return fallback;
  return SEVERITY_ALIASES[String(raw).trim().toLowerCase()] ?? fallback;
}
function pickCve(ids) {
  for (const id of ids) {
    const m = /^CVE-\d{4}-\d{4,}$/i.exec(String(id ?? "").trim());
    if (m) return m[0].toUpperCase();
  }
  return void 0;
}
function cvesIn(...inputs) {
  const text = inputs.flat(Infinity).map((x) => typeof x === "string" ? x : "").join(" ");
  const out = /* @__PURE__ */ new Set();
  const re = /CVE-\d{4}-\d{4,}/gi;
  let m;
  while (m = re.exec(text)) out.add(m[0].toUpperCase());
  return [...out];
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
    sources: [i.tool],
    status: "open"
  };
  if (i.cwe) f.cwe = i.cwe;
  if (i.references && i.references.length) f.references = i.references;
  const aliases = [i.ident, ...i.aliases ?? []].filter((x) => Boolean(x));
  const uniqAliases = [...new Set(aliases)];
  if (i.aliases !== void 0 || /^(CVE|GHSA|RUSTSEC|GO|PYSEC|OSV)-/i.test(i.ident)) {
    if (uniqAliases.length) f.aliases = uniqAliases;
    const cve = pickCve(uniqAliases);
    if (cve) f.cve = cve;
  }
  if (i.pkg) f.pkg = i.pkg;
  if (i.version) f.version = i.version;
  if (i.verified !== void 0) f.verified = i.verified;
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

// src/tools/correlate.ts
function sevRank(s) {
  return SEVERITIES.indexOf(s);
}
function maxSeverity(a, b) {
  return sevRank(a) <= sevRank(b) ? a : b;
}
function pkgKey(f) {
  return `${(f.pkg ?? "").toLowerCase()}@${(f.version ?? "").toLowerCase()}`;
}
function depIds(f) {
  const ids = /* @__PURE__ */ new Set();
  if (f.cve) ids.add(f.cve.toUpperCase());
  for (const a of f.aliases ?? []) ids.add(a.toUpperCase());
  if (!ids.size) ids.add(f.title.toUpperCase());
  return [...ids];
}
var DSU = class {
  p;
  constructor(n) {
    this.p = Array.from({ length: n }, (_, i) => i);
  }
  find(x) {
    while (this.p[x] !== x) x = this.p[x] = this.p[this.p[x]];
    return x;
  }
  union(a, b) {
    this.p[this.find(a)] = this.find(b);
  }
};
function bumpConfidence(c, agree) {
  return agree >= 2 ? "high" : c;
}
function mergeCluster(group) {
  const rep = group.slice().sort(
    (a, b) => sevRank(a.severity) - sevRank(b.severity) || (b.risk ?? 0) - (a.risk ?? 0) || byStr(a.id, b.id)
  )[0];
  const sources = [...new Set(group.flatMap((f) => f.sources ?? [f.tool]))].sort(byStr);
  const references = [...new Set(group.flatMap((f) => f.references ?? []))];
  const aliases = [...new Set(group.flatMap((f) => f.aliases ?? []).map((a) => a.toUpperCase()))].sort(byStr);
  const severity = group.reduce((s, f) => maxSeverity(s, f.severity), "info");
  const cve = group.map((f) => f.cve).find(Boolean) ?? pickCve(aliases);
  const cwe = group.map((f) => f.cwe).find(Boolean);
  const verified = group.some((f) => f.verified === true);
  const out = {
    ...rep,
    severity,
    sources,
    confidence: bumpConfidence(rep.confidence, sources.length)
  };
  if (references.length) out.references = references;
  else delete out.references;
  if (aliases.length) out.aliases = aliases;
  if (cve) out.cve = cve;
  if (cwe) out.cwe = cwe;
  if (verified) out.verified = true;
  return out;
}
function correlate(findings) {
  const taint = findings.filter((f) => f.tool === "ultrasec");
  const tool = findings.filter((f) => f.tool !== "ultrasec");
  const out = [...taint];
  const nonDep = tool.filter((f) => f.category !== "dep");
  const byKey = /* @__PURE__ */ new Map();
  for (const f of nonDep) {
    const where = f.sink ? `${f.sink.file}:${f.sink.line}` : "";
    const ident = (f.cwe ?? f.title).trim().toLowerCase();
    const key = `${f.category}::${ident}::${where}`;
    (byKey.get(key) ?? byKey.set(key, []).get(key)).push(f);
  }
  for (const group of byKey.values()) out.push(group.length === 1 ? withSources(group[0]) : mergeCluster(group));
  const dep = tool.filter((f) => f.category === "dep");
  const dsu = new DSU(dep.length);
  const seen = /* @__PURE__ */ new Map();
  dep.forEach((f, i) => {
    const pk = pkgKey(f);
    for (const id of depIds(f)) {
      const k = `${pk}|${id}`;
      const prev = seen.get(k);
      if (prev === void 0) seen.set(k, i);
      else dsu.union(prev, i);
    }
  });
  const clusters = /* @__PURE__ */ new Map();
  dep.forEach((f, i) => {
    const r = dsu.find(i);
    (clusters.get(r) ?? clusters.set(r, []).get(r)).push(f);
  });
  for (const group of clusters.values()) out.push(group.length === 1 ? withSources(group[0]) : mergeCluster(group));
  return out.sort((a, b) => byStr(a.id, b.id));
}
function withSources(f) {
  return f.sources && f.sources.length ? f : { ...f, sources: [f.tool] };
}

// src/tools/run.ts
var TIMEOUT_MS = 3e5;
var MAX_BUFFER = 64 * 1024 * 1024;
var MOUNT = "/work";
function exec(name, args, cwd) {
  try {
    const stdout = execFileSync3(name, args, {
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
function relLoc(loc, base) {
  if (base && loc.file.startsWith(base + "/")) return { ...loc, file: loc.file.slice(base.length + 1) };
  if (base && loc.file === base) return { ...loc, file: "." };
  return loc;
}
function relativizeFindings(findings, base) {
  return findings.map((f) => ({
    ...f,
    source: f.source ? relLoc(f.source, base) : f.source,
    sink: f.sink ? relLoc(f.sink, base) : f.sink,
    path: f.path ? f.path.map((p) => relLoc(p, base)) : f.path
  }));
}
function buildArgv(adapter, repo, target) {
  const base = adapter.argv(target);
  if (!adapter.enumerate) return base;
  const files = adapter.enumerate(repo);
  if (!files.length) return null;
  return [...base, ...files];
}
function runNative(adapter, repo) {
  if (!detect(adapter.name).installed) {
    return { name: adapter.name, ran: false, ok: false, findings: [], note: "not installed" };
  }
  const argv = buildArgv(adapter, repo, repo);
  if (!argv) return { name: adapter.name, ran: false, ok: false, findings: [], note: "no target files" };
  const { stdout, failed, err } = exec(adapter.name, argv, repo);
  return finish(adapter, repo, stdout, failed, err, false);
}
function runDocker(adapter, repo) {
  if (!adapter.dockerImage) return { name: adapter.name, ran: false, ok: false, findings: [], note: "no docker image" };
  const argv = buildArgv(adapter, repo, MOUNT);
  if (!argv) return { name: adapter.name, ran: false, ok: false, findings: [], note: "no target files" };
  const inner = (adapter.dockerEntrypointIsTool === false ? [adapter.name] : []).concat(argv);
  const args = ["run", "--rm", "-v", `${repo}:${MOUNT}`, "-w", MOUNT, adapter.dockerImage, ...inner];
  const { stdout, failed, err } = exec("docker", args, repo);
  return finish(adapter, repo, stdout, failed, err, true);
}
function finish(adapter, repo, stdout, failed, err, docker2) {
  if (failed) return { name: adapter.name, ran: true, ok: false, findings: [], note: `run failed: ${err ?? "no output"}` };
  try {
    const base = docker2 ? MOUNT : repo;
    const findings = relativizeFindings(adapter.parse(stdout, repo), base);
    return { name: adapter.name, ran: true, ok: true, findings, note: `${findings.length} finding(s)${docker2 ? " (docker)" : ""}` };
  } catch (e) {
    return { name: adapter.name, ran: true, ok: false, findings: [], note: `parse failed: ${e.message}` };
  }
}
function runAdapter(adapter, repo, useDocker = false) {
  return useDocker ? runDocker(adapter, repo) : runNative(adapter, repo);
}
function orchestrate(adapters, repo, opts = {}) {
  let selected = opts.which && opts.which.length ? adapters.filter((a) => opts.which.includes(a.name)) : adapters;
  if (opts.useDocker) selected = selected.filter((a) => a.dockerImage);
  const results = [];
  const all = [];
  for (const a of selected) {
    const r = runAdapter(a, repo, opts.useDocker);
    results.push(r);
    all.push(...r.findings);
  }
  const findings = correlate(all);
  const toolsRun = results.filter((r) => r.ran && r.ok).map((r) => r.name);
  return { findings, toolsRun, results };
}

// src/tools/scoring.ts
import { existsSync as existsSync2, mkdirSync as mkdirSync3, readFileSync as readFileSync4, statSync as statSync2, writeFileSync as writeFileSync3 } from "fs";
import { gunzipSync } from "zlib";
import { homedir } from "os";
import { join as join6 } from "path";
var SEVERITY_WEIGHT = {
  critical: 1,
  high: 0.8,
  medium: 0.5,
  low: 0.25,
  info: 0.1
};
function riskScore({ severity, epss, kev }) {
  const base = 0.6 * SEVERITY_WEIGHT[severity] + 0.4 * Math.min(Math.max(epss ?? 0, 0), 1);
  let score = Math.round(100 * base);
  if (kev) score = Math.max(score, 95);
  return Math.min(Math.max(score, 0), 100);
}
function parseEpssCsv(csv) {
  const out = /* @__PURE__ */ new Map();
  for (const line of csv.split("\n")) {
    const row = line.trim();
    if (!row || row.startsWith("#")) continue;
    const [cve, epss, pct] = row.split(",");
    if (!cve || !/^CVE-/i.test(cve)) continue;
    const e = Number(epss);
    if (Number.isNaN(e)) continue;
    out.set(cve.toUpperCase(), { epss: e, percentile: pct !== void 0 ? Number(pct) : void 0 });
  }
  return out;
}
function parseKev(json) {
  const out = /* @__PURE__ */ new Map();
  let data;
  try {
    data = JSON.parse(json || "{}");
  } catch {
    return out;
  }
  for (const v of data?.vulnerabilities ?? []) {
    if (v?.cveID) out.set(String(v.cveID).toUpperCase(), v.dateAdded);
  }
  return out;
}
function applyEnrichment(findings, feeds) {
  return findings.map((f) => {
    const out = { ...f };
    const cve = f.cve?.toUpperCase();
    if (cve) {
      const e = feeds.epss.get(cve);
      if (e) out.epss = e.epss;
      if (feeds.kev.has(cve)) {
        out.kev = true;
        const d = feeds.kev.get(cve);
        if (d) out.kevDateAdded = d;
      }
    }
    out.risk = riskScore({ severity: out.severity, epss: out.epss, kev: out.kev });
    return out;
  });
}
var EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
var KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
var TTL_MS = 24 * 60 * 60 * 1e3;
var FETCH_TIMEOUT_MS = 2e4;
function cacheDir() {
  return process.env.ULTRASEC_CACHE_DIR || join6(homedir(), ".cache", "ultrasec");
}
function fresh(path) {
  try {
    return existsSync2(path) && Date.now() - statSync2(path).mtimeMs < TTL_MS;
  } catch {
    return false;
  }
}
async function fetchBuf(url) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: ctrl.signal, redirect: "follow" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return Buffer.from(await res.arrayBuffer());
  } finally {
    clearTimeout(t);
  }
}
async function loadCached(url, file, gz) {
  const dir = cacheDir();
  const path = join6(dir, file);
  if (fresh(path)) {
    try {
      return readFileSync4(path, "utf8");
    } catch {
    }
  }
  try {
    const buf = await fetchBuf(url);
    const text = (gz ? gunzipSync(buf) : buf).toString("utf8");
    try {
      mkdirSync3(dir, { recursive: true });
      writeFileSync3(path, text);
    } catch {
    }
    return text;
  } catch {
    try {
      if (existsSync2(path)) return readFileSync4(path, "utf8");
    } catch {
    }
    return "";
  }
}
async function loadFeeds() {
  const [epssCsv, kevJson] = await Promise.all([
    loadCached(EPSS_URL, "epss.csv", true),
    loadCached(KEV_URL, "kev.json", false)
  ]);
  return { epss: parseEpssCsv(epssCsv), kev: parseKev(kevJson) };
}
async function enrichFindings(findings, opts = {}) {
  if (opts.enabled === false) {
    return { findings: applyEnrichment(findings, { epss: /* @__PURE__ */ new Map(), kev: /* @__PURE__ */ new Map() }), note: "risk: severity-only (enrichment off)" };
  }
  let feeds;
  try {
    feeds = await loadFeeds();
  } catch {
    feeds = { epss: /* @__PURE__ */ new Map(), kev: /* @__PURE__ */ new Map() };
  }
  const enriched = applyEnrichment(findings, feeds);
  const withCve = enriched.filter((f) => f.cve);
  const kevHits = enriched.filter((f) => f.kev).length;
  const note = feeds.epss.size || feeds.kev.size ? `risk: EPSS ${feeds.epss.size} CVEs \xB7 KEV ${feeds.kev.size} \xB7 ${withCve.length} finding(s) with CVE${kevHits ? ` \xB7 ${kevHits} in KEV` : ""}` : "risk: severity-only (feeds unavailable offline)";
  return { findings: enriched, note };
}

// src/tools/trivy.ts
var trivy = {
  name: "trivy",
  category: "dep",
  dockerImage: "ghcr.io/aquasecurity/trivy:0.71.1",
  argv: (target) => ["fs", "--scanners", "vuln,secret,misconfig", "--format", "json", "--quiet", target],
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
            references: [v.PrimaryURL, ...v.References ?? []].filter(Boolean),
            pkg: v.PkgName,
            version: v.InstalledVersion,
            // VulnerabilityID may be a GHSA; surface any CVE in the refs so the
            // cross-tool correlator can match it against osv/grype on the CVE.
            aliases: [v.VulnerabilityID, ...cvesIn(v.PrimaryURL, v.References)]
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
import { existsSync as existsSync3 } from "fs";
import { join as join7 } from "path";
var gitleaks = {
  name: "gitleaks",
  category: "secret",
  dockerImage: "ghcr.io/gitleaks/gitleaks:v8.30.1",
  // `--report-path -` is gitleaks' documented stdout sink (json to a file otherwise);
  // `--exit-code 0` so "leaks found" (normally exit 1) isn't treated as a tool failure.
  argv: (target) => {
    const onHost = existsSync3(target);
    const hasGit = onHost && existsSync3(join7(target, ".git"));
    const base = ["detect", "--source", target, "--report-format", "json", "--report-path", "-", "--no-banner", "--redact", "--exit-code", "0"];
    return hasGit ? base : [...base, "--no-git"];
  },
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
var nullObj = (o) => Object.assign(/* @__PURE__ */ Object.create(null), o);
var AV = nullObj({ N: 0.85, A: 0.62, L: 0.55, P: 0.2 });
var AC = nullObj({ L: 0.77, H: 0.44 });
var UI = nullObj({ N: 0.85, R: 0.62 });
var CIA = nullObj({ H: 0.56, L: 0.22, N: 0 });
var PR_U = nullObj({ N: 0.85, L: 0.62, H: 0.27 });
var PR_C = nullObj({ N: 0.85, L: 0.68, H: 0.5 });
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
  dockerImage: "ghcr.io/google/osv-scanner:v2.3.8",
  // v2 CLI: `scan source` walks a directory for lockfiles/manifests. JSON → stdout.
  argv: (target) => ["scan", "source", "--recursive", "--format", "json", target],
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
          const refs = (v.references ?? []).map((r) => r.url).filter(Boolean);
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
              references: refs,
              pkg: name,
              version,
              // v.id is usually a GHSA; v.aliases carries the CVE — the join key.
              aliases: [...v.aliases ?? [], ...cvesIn(refs)]
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
  // The semgrep/semgrep image entrypoint is NOT `semgrep`, so the runner prepends it.
  dockerImage: "semgrep/semgrep:1.166.0",
  dockerEntrypointIsTool: false,
  argv: (target) => ["scan", "--json", "--quiet", "--config", "auto", target],
  parse: (raw) => parseSemgrep("semgrep", raw)
};
var opengrep = {
  name: "opengrep",
  category: "sast",
  // No official OpenGrep image yet (only broken third-party ones) — native-only.
  argv: (target) => ["scan", "--json", "--quiet", "--config", "auto", target],
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
          references: [adv.url, ...adv.aliases ?? []].filter(Boolean),
          pkg: pkg.name,
          version: pkg.version,
          aliases: adv.aliases ?? []
          // RUSTSEC id is the ident; aliases carry the CVE
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
      const osv = osvById.get(f.osv) ?? {};
      const top = (f.trace ?? [])[0] ?? {};
      const key = `${f.osv}:${top.position?.filename ?? ""}:${top.position?.line ?? ""}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const reachable = Boolean(top.function && top.position);
      const refs = (osv.references ?? []).map((r) => r.url).filter(Boolean);
      const mod = osv.affected?.[0]?.package?.name;
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
          references: refs,
          pkg: mod || top.package,
          // GO-id is the ident; osv.aliases carries the CVE/GHSA — the join key.
          aliases: [...osv.aliases ?? [], ...cvesIn(refs, osv.summary)]
        })
      );
    }
    return out;
  }
};

// src/tools/bandit.ts
var bandit = {
  name: "bandit",
  category: "sast",
  dockerImage: "ghcr.io/pycqa/bandit:1.8.6",
  argv: (target) => ["-r", target, "-f", "json", "-ll", "-ii", "-q"],
  parse(raw) {
    const data = JSON.parse(raw || "{}");
    const out = [];
    for (const r of data.results ?? []) {
      const cweId = r.issue_cwe?.id;
      const conf = String(r.issue_confidence ?? "").toLowerCase();
      out.push(
        makeToolFinding({
          tool: "bandit",
          category: "sast",
          ident: `${r.test_id}:${r.filename}:${r.line_number}`,
          title: `${r.test_id} ${r.test_name ?? ""}`.trim(),
          severity: normalizeSeverity(r.issue_severity, "medium"),
          confidence: conf === "high" ? "high" : conf === "low" ? "low" : "medium",
          message: r.issue_text || r.test_name || r.test_id,
          file: r.filename,
          line: r.line_number,
          cwe: cweId != null ? `CWE-${cweId}` : void 0,
          references: [r.more_info, r.issue_cwe?.link].filter(Boolean)
        })
      );
    }
    return out;
  }
};

// src/tools/gosec.ts
var gosec = {
  name: "gosec",
  category: "sast",
  dockerImage: "ghcr.io/securego/gosec:v2.21.4",
  argv: () => ["-fmt", "json", "-quiet", "-no-fail", "./..."],
  parse(raw) {
    const data = JSON.parse(raw || "{}");
    const out = [];
    for (const i of data.Issues ?? []) {
      const line = parseInt(String(i.line).split("-")[0] ?? "", 10);
      const cweId = i.cwe?.id;
      out.push(
        makeToolFinding({
          tool: "gosec",
          category: "sast",
          ident: `${i.rule_id}:${i.file}:${i.line}`,
          title: `${i.rule_id} ${i.details ?? ""}`.trim(),
          severity: normalizeSeverity(i.severity, "medium"),
          confidence: String(i.confidence ?? "").toLowerCase() === "high" ? "high" : "medium",
          message: `${i.details || i.rule_id}`,
          file: i.file,
          line: Number.isNaN(line) ? void 0 : line,
          cwe: cweId ? `CWE-${cweId}` : void 0,
          references: [i.cwe?.url].filter(Boolean)
        })
      );
    }
    return out;
  }
};

// src/tools/checkov.ts
var checkov = {
  name: "checkov",
  category: "config",
  dockerImage: "bridgecrew/checkov:3.2.0",
  argv: (target) => ["-d", target, "-o", "json", "--compact", "--quiet", "--soft-fail"],
  parse(raw) {
    const data = JSON.parse(raw || "{}");
    const blocks = Array.isArray(data) ? data : [data];
    const out = [];
    for (const b of blocks) {
      for (const c of b?.results?.failed_checks ?? []) {
        const file = String(c.file_path ?? "").replace(/^\/+/, "");
        const line = Array.isArray(c.file_line_range) ? c.file_line_range[0] : void 0;
        out.push(
          makeToolFinding({
            tool: "checkov",
            category: "config",
            ident: `${c.check_id}:${file}:${line ?? ""}`,
            title: `${c.check_id} ${c.check_name ?? ""}`.trim(),
            severity: normalizeSeverity(c.severity, "medium"),
            message: `${c.check_name || c.check_id}${c.resource ? ` (${c.resource})` : ""}`,
            file: file || void 0,
            line: typeof line === "number" ? line : void 0,
            references: [c.guideline].filter(Boolean)
          })
        );
      }
    }
    return out;
  }
};

// src/tools/hadolint.ts
import { basename } from "path";
var LEVEL = { error: "high", warning: "medium", info: "low", style: "info" };
function isDockerfile(rel) {
  const b = basename(rel).toLowerCase();
  return b === "dockerfile" || b === "containerfile" || b.startsWith("dockerfile.") || b.endsWith(".dockerfile");
}
var hadolint = {
  name: "hadolint",
  category: "config",
  dockerImage: "hadolint/hadolint:v2.12.0",
  argv: () => ["--format", "json", "--no-fail"],
  enumerate: (repo) => walk(repo).map((f) => f.rel).filter(isDockerfile),
  parse(raw) {
    const arr = JSON.parse(raw || "[]");
    if (!Array.isArray(arr)) return [];
    return arr.map(
      (d) => makeToolFinding({
        tool: "hadolint",
        category: "config",
        ident: `${d.code}:${d.file}:${d.line}`,
        title: `${d.code} ${d.message ?? ""}`.trim(),
        severity: LEVEL[String(d.level ?? "").toLowerCase()] ?? "low",
        message: `${d.code}: ${d.message ?? ""}`.trim(),
        file: d.file,
        line: d.line,
        references: String(d.code ?? "").startsWith("DL") ? [`https://github.com/hadolint/hadolint/wiki/${d.code}`] : []
      })
    );
  }
};

// src/tools/sarif.ts
function levelSeverity(level, fallback) {
  if (!level) return fallback;
  return normalizeSeverity(level, fallback);
}
function cweFromTags(tags) {
  const arr = Array.isArray(tags) ? tags : [];
  for (const t of arr) {
    const cwe = firstCwe(typeof t === "string" ? t : "");
    if (cwe) return cwe;
  }
  return void 0;
}
function parseSarif(raw, opts) {
  let data;
  try {
    data = JSON.parse(raw || "{}");
  } catch {
    return [];
  }
  const out = [];
  const fallbackSev = opts.defaultSeverity ?? "medium";
  for (const run of data?.runs ?? []) {
    const rules = run?.tool?.driver?.rules ?? [];
    const byId = /* @__PURE__ */ new Map();
    rules.forEach((r) => r?.id && byId.set(r.id, r));
    for (const res of run?.results ?? []) {
      const ruleId = res.ruleId ?? (typeof res.ruleIndex === "number" ? rules[res.ruleIndex]?.id : void 0) ?? "rule";
      const rule = byId.get(ruleId) ?? (typeof res.ruleIndex === "number" ? rules[res.ruleIndex] : void 0) ?? {};
      const loc = res.locations?.[0]?.physicalLocation ?? {};
      const file = loc.artifactLocation?.uri;
      const line = loc.region?.startLine;
      const secSev = res.properties?.["security-severity"] ?? rule.properties?.["security-severity"];
      const level = res.level ?? rule.defaultConfiguration?.level;
      const severity = secSev !== void 0 && secSev !== null && String(secSev).trim() !== "" ? deriveSeverity(String(secSev), fallbackSev) : levelSeverity(level, fallbackSev);
      const cwe = cweFromTags(rule.properties?.tags) ?? cweFromTags(res.properties?.tags) ?? firstCwe(rule.properties?.cwe) ?? opts.defaultCwe;
      const message = res.message?.text ?? rule.shortDescription?.text ?? rule.fullDescription?.text ?? ruleId;
      const refs = [rule.helpUri, res.hostedViewerUri].filter((x) => Boolean(x));
      out.push(
        makeToolFinding({
          tool: opts.tool,
          category: opts.category,
          ident: `${ruleId}:${file ?? ""}:${line ?? ""}`,
          title: ruleId,
          severity,
          message: file ? `${message} [${ruleId}] at ${file}:${line ?? "?"}` : `${message} [${ruleId}]`,
          file,
          line,
          cwe,
          references: refs.length ? refs : void 0
        })
      );
    }
  }
  return out;
}

// src/tools/kingfisher.ts
var kingfisher = {
  name: "kingfisher",
  category: "secret",
  argv: (target) => ["scan", target, "--format", "sarif", "--no-validate"],
  parse: (raw) => parseSarif(raw, { tool: "kingfisher", category: "secret", defaultCwe: "CWE-798", defaultSeverity: "high" })
};

// src/tools/index.ts
var ADAPTERS = [
  trivy,
  opengrep,
  semgrep,
  gitleaks,
  osvScanner,
  cargoAudit,
  govulncheck,
  bandit,
  gosec,
  checkov,
  hadolint,
  kingfisher
];

// src/store.ts
import { mkdirSync as mkdirSync4, writeFileSync as writeFileSync4, readFileSync as readFileSync5, existsSync as existsSync4 } from "fs";
import { join as join8 } from "path";
function emptySeverityCounts() {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}
function countBySeverity(findings) {
  const c = emptySeverityCounts();
  for (const f of findings) c[f.severity]++;
  return c;
}
function writeDossier(outDir, d) {
  mkdirSync4(outDir, { recursive: true });
  writeFileSync4(join8(outDir, "manifest.json"), JSON.stringify(d.manifest, null, 2));
  writeFileSync4(join8(outDir, "findings.json"), JSON.stringify(d.findings, null, 2));
  writeFileSync4(join8(outDir, "graph.json"), JSON.stringify(d.graph, null, 2));
  writeFileSync4(join8(outDir, "DOSSIER.md"), renderDossierMd(d));
}
function mergeDossier(prev, next) {
  const byId = /* @__PURE__ */ new Map();
  for (const f of prev.findings) byId.set(f.id, f);
  for (const f of next.findings) {
    const old = byId.get(f.id);
    if (old && old.status !== "open") {
      byId.set(f.id, {
        ...f,
        status: old.status,
        verdict: old.verdict,
        exploitPath: old.exploitPath,
        confidence: old.confidence,
        message: old.message
      });
    } else {
      byId.set(f.id, f);
    }
  }
  const findings = [...byId.values()].sort((a, b) => byStr(a.id, b.id));
  const graph = mergeGraphs(prev.graph, next.graph);
  const scopes = [.../* @__PURE__ */ new Set([...prev.manifest.scopes ?? [], ...next.manifest.scopes ?? []])].sort(byStr);
  const pt = prev.manifest.truncation;
  const nt = next.manifest.truncation;
  const nextScoped = !!(next.manifest.scopes && next.manifest.scopes.length);
  const truncation = nextScoped ? pt || nt ? {
    candidates: Math.max(pt?.candidates ?? 0, nt?.candidates ?? 0),
    total: Math.max(pt?.total ?? 0, nt?.total ?? 0),
    ...pt?.files || nt?.files ? { files: true } : {}
  } : void 0 : nt;
  const manifest = {
    ...next.manifest,
    languages: [.../* @__PURE__ */ new Set([...prev.manifest.languages, ...next.manifest.languages])].sort(),
    toolsRun: [.../* @__PURE__ */ new Set([...prev.manifest.toolsRun, ...next.manifest.toolsRun])].sort(),
    counts: { findings: findings.length, bySeverity: countBySeverity(findings) },
    ...truncation ? { truncation } : { truncation: void 0 },
    ...scopes.length ? { scopes } : {}
  };
  return { manifest, findings, graph };
}
function loadDossier(outDir) {
  const read = (name) => JSON.parse(readFileSync5(join8(outDir, name), "utf8"));
  if (!existsSync4(join8(outDir, "findings.json"))) {
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
  if (m.truncation?.candidates) {
    L.push(`> \u26A0\uFE0F **Coverage capped:** **${m.truncation.candidates}** of **${m.truncation.total}** taint candidate(s) were not enumerated. Raise \`--max-candidates\` (or \`--budget thorough\`) or narrow \`--scope\` to see the rest.`);
    L.push("");
  }
  if (m.truncation?.files) {
    L.push(`> \u26A0\uFE0F **Partial walk:** the file walk hit \`--max-files\` \u2014 some files were **not scanned**. Raise \`--max-files\` or narrow \`--scope\`.`);
    L.push("");
  }
  if (m.scopes && m.scopes.length) {
    L.push(`> \u{1F50E} **Scoped run** \u2014 only these paths were analysed: ${m.scopes.map((s) => `\`${s}\``).join(", ")}. Findings outside this scope are not represented.`);
    L.push("");
  }
  if (!findings.length) {
    L.push(`_No candidate findings._`);
    return L.join("\n") + "\n";
  }
  L.push(`## Candidates`);
  L.push("");
  const ordered = findings.slice().sort((a, b) => (b.risk ?? -1) - (a.risk ?? -1) || SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
  for (const f of ordered) {
    L.push(`### ${f.id} \u2014 ${severityBadge(f.severity)} ${f.title}`);
    L.push("");
    const src = f.sources && f.sources.length > 1 ? ` \xB7 agreed by ${f.sources.join(", ")}` : f.tool !== "ultrasec" ? ` \xB7 via ${f.tool}` : "";
    L.push(`- category: ${f.category}${f.cwe ? ` \xB7 ${f.cwe}` : ""} \xB7 confidence ${f.confidence} \xB7 status ${f.status}${src}`);
    const risk = [];
    if (typeof f.risk === "number") risk.push(`risk ${f.risk}`);
    if (typeof f.epss === "number") risk.push(`EPSS ${(f.epss * 100).toFixed(1)}%`);
    if (f.kev) risk.push(`\u{1F6A8} CISA KEV${f.kevDateAdded ? ` (${f.kevDateAdded})` : ""}`);
    if (f.verified) risk.push(`\u2705 verified secret`);
    if (risk.length) L.push(`- ${risk.join(" \xB7 ")}`);
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
var BUDGETS = {
  quick: { maxDepth: 3, maxCandidates: 200 },
  standard: { maxDepth: 6, maxCandidates: 1e3 },
  thorough: { maxDepth: 8, maxCandidates: 5e3 }
};
var REVDEP_DEPTH = 2;
var DOSSIER_FILES = /* @__PURE__ */ new Set(["manifest.json", "findings.json", "graph.json", "DOSSIER.md", "MAP.md", "attack-surface.json", "VERIFY.md", "VERIFY.todo.json", "SUMMARY.md", "REPORT.md", "FULL.md", "index.html"]);
var isDossierArtifact = (f) => DOSSIER_FILES.has(f) || /^VERIFY\.todo\.\d+\.json$/.test(f) || f.startsWith("cache/");
async function runScan(args) {
  const repo = resolve3(flagStr(args, "repo") ?? ".");
  const out = resolve3(flagStr(args, "out") ?? ".ultrasec");
  const scope = listFlag(args, "scope");
  const include = listFlag(args, "include");
  const exclude = listFlag(args, "exclude");
  const maxFiles = numFlag(args, "max-files");
  const gitignore = flagBool(args, "gitignore");
  const budgetName = flagStr(args, "budget");
  const preset = own(BUDGETS, budgetName ?? "standard") ?? BUDGETS.standard;
  const maxDepth = numFlag(args, "max-depth") ?? preset.maxDepth;
  const maxCandidates = numFlag(args, "max-candidates") ?? preset.maxCandidates;
  const diffRef = flagStr(args, "diff") ?? flagStr(args, "since");
  let effectiveScope = scope;
  let diffNote;
  if (diffRef) {
    const changedRaw = changedFiles(repo, diffRef);
    if (changedRaw === null) {
      eprintln(`ultrasec: --diff/--since needs a git work tree and a resolvable ref (got '${diffRef}'). Aborting \u2014 no silent full scan.`);
      return 2;
    }
    const relOut = relative2(repo, out);
    let changed;
    if (relOut === "" || relOut === ".") {
      changed = changedRaw.filter((f) => !isDossierArtifact(f));
    } else if (!relOut.startsWith("..")) {
      changed = changedRaw.filter((f) => f !== relOut && !f.startsWith(relOut + "/"));
    } else {
      changed = changedRaw;
    }
    let targets = changed;
    if (existsSync5(join9(out, "graph.json"))) {
      try {
        targets = reverseDependents(loadDossier(out).graph, changed, REVDEP_DEPTH);
        diffNote = `--diff ${diffRef}: ${changed.length} changed \u2192 ${targets.length} file(s) incl. reverse-deps`;
      } catch {
        diffNote = `--diff ${diffRef}: ${changed.length} changed file(s) (prior dossier unreadable; reverse-deps skipped)`;
      }
    } else {
      diffNote = `--diff ${diffRef}: ${changed.length} changed file(s) \u2014 run a full scan first to include reverse-dependents`;
    }
    if (targets.length === 0) {
      println(`ultrasec scan: no changed files since ${diffRef} \u2014 nothing to do.`);
      return 0;
    }
    effectiveScope = [...scope ?? [], ...targets];
  }
  const scanOpts = { scope: effectiveScope, include, exclude, maxFiles, gitignore };
  const resume = flagBool(args, "resume");
  const cache = resume ? loadScanCache(out) : void 0;
  const scan = cache ? scanRepoCached(repo, scanOpts, cache) : scanRepo(repo, scanOpts);
  const graph = buildGraph(scan);
  const taint = enumerateTaint(scan, graph, { maxDepth, maxCandidates });
  const taintFindings = taint.findings;
  const scopedScan = !!(effectiveScope && effectiveScope.length || include?.length || exclude?.length || diffRef);
  const toolsFlag = flagStr(args, "tools");
  const toolsAutoSkipped = scopedScan && toolsFlag === void 0 && !flagBool(args, "no-tools");
  const skipTools = flagBool(args, "no-tools") || toolsFlag === "none" || toolsAutoSkipped;
  const which = toolsFlag && toolsFlag !== "auto" && toolsFlag !== "none" ? toolsFlag.split(",").map((s) => s.trim()) : void 0;
  const useDocker = flagBool(args, "docker");
  const tool = skipTools ? { findings: [], toolsRun: [], results: [] } : orchestrate(ADAPTERS, repo, { which, useDocker });
  const merged = [...taintFindings, ...tool.findings].sort((a, b) => byStr(a.id, b.id));
  const enrich = !(flagBool(args, "no-enrich") || flagBool(args, "offline"));
  const { findings, note: riskNote } = await enrichFindings(merged, { enabled: enrich });
  const languages = [...new Set(scan.files.map((f) => f.lang))].sort();
  const truncation = taint.truncated > 0 || scan.truncated ? { candidates: taint.truncated, total: taint.total, ...scan.truncated ? { files: true } : {} } : void 0;
  const recordedScopes = [...scope ?? [], ...diffRef ? [`diff:${diffRef}`] : []].sort(byStr);
  const manifest = {
    version: VERSION,
    schemaVersion: SCHEMA_VERSION,
    repo,
    generatedNote: "Taint candidates are deterministic; external-tool results depend on installed scanners.",
    languages,
    toolsRun: tool.toolsRun,
    counts: { findings: findings.length, bySeverity: countBySeverity(findings) },
    ...truncation ? { truncation } : {},
    ...recordedScopes.length ? { scopes: recordedScopes } : {}
  };
  const nextDossier = { manifest, findings, graph };
  let final = nextDossier;
  let mergedNote = "";
  if (flagBool(args, "merge") && existsSync5(join9(out, "findings.json"))) {
    try {
      const prev = loadDossier(out);
      final = mergeDossier(prev, nextDossier);
      mergedNote = ` \xB7 merged into ${prev.findings.length} prior finding(s)`;
    } catch (e) {
      eprintln(`ultrasec: could not merge into the existing dossier at ${out} (${e instanceof Error ? e.message : String(e)}); writing a fresh dossier instead.`);
    }
  }
  writeDossier(out, final);
  if (cache) saveScanCache(out, cache);
  const fm = final.manifest;
  const fc = fm.counts.bySeverity;
  if (flagBool(args, "json")) {
    const kev = final.findings.filter((f) => f.kev).length;
    println(
      JSON.stringify(
        { out, counts: fm.counts, languages: fm.languages, files: scan.files.length, toolsRun: fm.toolsRun, kev, risk: riskNote, truncation, scopes: fm.scopes, diff: diffNote, merged: mergedNote.trim() || void 0 },
        null,
        2
      )
    );
    return 0;
  }
  println(`ultrasec scan \u2192 ${out}${mergedNote}`);
  println(`  files scanned: ${scan.files.length}  \xB7  languages: ${languages.join(", ") || "\u2014"}`);
  if (diffNote) println(`  ${diffNote}`);
  if (toolsAutoSkipped) {
    println(`  external scanners skipped in scoped mode \u2014 pass \`--tools auto\` to run them.`);
  } else if (!skipTools) {
    println(`  external tools run: ${tool.toolsRun.join(", ") || "none"}  (\`ultrasec tools\` to see/install more)`);
  }
  println(`  candidate findings: ${fm.counts.findings}  (crit ${fc.critical} \xB7 high ${fc.high} \xB7 med ${fc.medium} \xB7 low ${fc.low})  \xB7  ${taintFindings.length} taint + ${tool.findings.length} tool this pass`);
  println(`  ${riskNote}`);
  if (truncation?.candidates) {
    println(`  \u26A0\uFE0F  showing top ${maxCandidates} of ${truncation.total} taint candidates \u2014 ${truncation.candidates} not shown. Raise --max-candidates or narrow --scope.`);
  }
  if (truncation?.files) {
    println(`  \u26A0\uFE0F  file walk hit --max-files (${maxFiles}) \u2014 some files were NOT scanned. Raise --max-files or narrow --scope.`);
  }
  if (!fm.counts.findings) {
    println(`  no taint candidates \u2014 still review the DOSSIER and run external tools (\`ultrasec tools\`).`);
  } else {
    println(`  next: read ${out}/DOSSIER.md, then \`ultrasec dossier <id> --run ${out}\` to adjudicate.`);
  }
  return 0;
}

// src/commands/dossier.ts
import { resolve as resolve4 } from "path";

// src/dossier.ts
import { join as join10 } from "path";
function excerpt(repo, step, ctx = 3) {
  const lines = readText(join10(repo, step.file)).split(/\r?\n/);
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
  const run = resolve4(flagStr(args, "run") ?? ".ultrasec");
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
import { resolve as resolve5 } from "path";
function runPaths(args) {
  const run = resolve5(flagStr(args, "run") ?? ".ultrasec");
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
import { readFileSync as readFileSync6, writeFileSync as writeFileSync5, readdirSync as readdirSync2, statSync as statSync3 } from "fs";
import { join as join11, resolve as resolve6 } from "path";

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
    default:
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
  return arr.filter((v) => v && typeof v.id === "string" && VERDICTS.includes(v.verdict)).map((v) => ({ id: v.id, verdict: v.verdict, note: v.note, exploitPath: v.exploitPath }));
}

// src/commands/verify.ts
function runVerify(args) {
  const run = resolve6(flagStr(args, "run") ?? ".ultrasec");
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
  writeFileSync5(join11(run, todoName), JSON.stringify(items, null, 2));
  writeFileSync5(join11(run, "VERIFY.md"), renderWorklistMd(buildWorklist(dossier)));
  if (flagBool(args, "json")) {
    println(JSON.stringify(items, null, 2));
    return 0;
  }
  println(`ultrasec verify \u2192 ${join11(run, todoName)} (${items.length} item${items.length === 1 ? "" : "s"}${shards > 1 ? `, shard ${shardIdx}/${shards}` : ""})`);
  println(`  adjudicate each (\`ultrasec dossier <id> --run ${run}\`), save verdicts.json, then:`);
  println(`  ultrasec verify --apply verdicts.json --run ${run}`);
  return 0;
}
function collectVerdictFiles(applyPath) {
  if (applyPath.includes(",")) return applyPath.split(",").map((s) => resolve6(s.trim()));
  const abs = resolve6(applyPath);
  try {
    if (statSync3(abs).isDirectory()) {
      return readdirSync2(abs).filter((n) => /verdict.*\.json$/i.test(n)).map((n) => join11(abs, n));
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
      verdicts.push(...parseVerdicts(readFileSync6(f, "utf8")));
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
import { resolve as resolve8 } from "path";

// src/check.ts
import { existsSync as existsSync6, readFileSync as readFileSync7 } from "fs";
import { join as join12, resolve as resolve7, sep as sep2 } from "path";
function insideRepo(repo, file) {
  const base = resolve7(repo);
  const abs = resolve7(base, file);
  return abs === base || abs.startsWith(base + sep2);
}
function lineCount(repo, file) {
  if (!insideRepo(repo, file)) return null;
  const abs = join12(repo, file);
  if (!existsSync6(abs)) return null;
  try {
    return readFileSync7(abs, "utf8").split(/\r?\n/).length;
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
      if (!insideRepo(repo, loc.file)) continue;
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
  const run = resolve8(flagStr(args, "run") ?? ".ultrasec");
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
import { writeFileSync as writeFileSync6 } from "fs";
import { join as join13, resolve as resolve9 } from "path";

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
function sevRank2(s) {
  return SEVERITIES.indexOf(s);
}
function sortFindings(fs) {
  return fs.slice().sort((a, b) => (b.risk ?? -1) - (a.risk ?? -1) || sevRank2(a.severity) - sevRank2(b.severity) || byStr(a.id, b.id));
}
function riskTag(f) {
  const parts = [];
  if (typeof f.risk === "number") parts.push(`risk ${f.risk}`);
  if (typeof f.epss === "number") parts.push(`EPSS ${(f.epss * 100).toFixed(1)}%`);
  if (f.kev) parts.push(`\u{1F6A8} CISA KEV${f.kevDateAdded ? ` (${f.kevDateAdded})` : ""}`);
  if (f.verified) parts.push(`\u2705 verified secret`);
  return parts.join(" \xB7 ");
}
function sourcesTag(f) {
  const s = f.sources && f.sources.length ? f.sources : f.tool !== "ultrasec" ? [f.tool] : [];
  if (s.length > 1) return `agreed by ${s.join(", ")}`;
  return f.tool !== "ultrasec" ? `via ${f.tool}` : "";
}
function pathLine(f) {
  if (f.path?.length) return f.path.map((p) => `\`${p.file}:${p.line}\``).join(" \u2192 ");
  if (f.sink) return `\`${f.sink.file}:${f.sink.line}\``;
  return "\u2014";
}
function header(d) {
  const c = d.manifest.counts.bySeverity;
  const kev = d.findings.filter((f) => f.kev).length;
  const ranked = d.findings.some((f) => typeof f.risk === "number");
  const lines = [
    `repo \`${d.manifest.repo}\` \xB7 ultrasec ${d.manifest.version}`,
    `findings: **${d.manifest.counts.findings}** \u2014 ${SEVERITIES.map((s) => `${BADGE[s]} ${c[s]}`).join(" \xB7 ")}${kev ? ` \xB7 \u{1F6A8} ${kev} in CISA KEV` : ""}`,
    `tools: ${d.manifest.toolsRun.join(", ") || "none (graph + taint only)"}`
  ];
  if (ranked) lines.push(`_ranked by composite risk (severity \u2295 EPSS \u2295 KEV)_`);
  return lines.join("  \n");
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
  const tail = (f) => {
    const rt = riskTag(f);
    return ` (${f.cwe ?? f.category})${rt ? ` \xB7 ${rt}` : ""}`;
  };
  if (confirmed.length) {
    L.push(`## Confirmed (${confirmed.length})`);
    for (const f of confirmed) L.push(`- ${BADGE[f.severity]} **${f.title}** \u2014 ${pathLine(f)}${tail(f)}`);
    L.push("");
  }
  if (needs.length) {
    L.push(`## Needs human review (${needs.length})`);
    for (const f of needs) L.push(`- ${BADGE[f.severity]} ${f.title} \u2014 ${pathLine(f)}${tail(f)}`);
  }
  return L.join("\n") + "\n";
}
function renderFinding(f, opts = {}) {
  const L = [];
  L.push(`### ${BADGE[f.severity]} ${f.title}`);
  L.push("");
  const src = sourcesTag(f);
  L.push(`\`${f.id}\` \xB7 ${f.cwe ? `[${f.cwe}](${(f.references ?? [])[0] ?? `https://cwe.mitre.org/`}) \xB7 ` : ""}${f.category} \xB7 ${statusTag(f)}${src ? ` \xB7 ${src}` : ""}`);
  const rt = riskTag(f);
  if (rt) {
    L.push("");
    L.push(`**Risk:** ${rt}`);
  }
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
function sevRank3(s) {
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
function riskHtml(f) {
  const out = [];
  if (typeof f.risk === "number") out.push(badge(`risk ${f.risk}`, f.risk >= 95 ? "#7f1d1d" : f.risk >= 70 ? "#b91c1c" : f.risk >= 40 ? "#b45309" : "#475569"));
  if (typeof f.epss === "number") out.push(`<span class="kv">EPSS ${(f.epss * 100).toFixed(1)}%</span>`);
  if (f.kev) out.push(badge(`CISA KEV${f.kevDateAdded ? ` ${f.kevDateAdded}` : ""}`, "#7f1d1d"));
  if (f.verified) out.push(badge("verified secret", "#7f1d1d"));
  return out.length ? `<div class="risk">${out.join(" ")}</div>` : "";
}
function sourcesHtml(f) {
  const s = f.sources && f.sources.length ? f.sources : f.tool !== "ultrasec" ? [f.tool] : [];
  if (s.length > 1) return `\xB7 agreed by ${esc2(s.join(", "))}`;
  return f.tool !== "ultrasec" ? `\xB7 via ${esc2(f.tool)}` : "";
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
      ${sourcesHtml(f)}
    </div>
    ${riskHtml(f)}
    ${pathHtml(f)}
    <p class="msg">${esc2(f.message)}</p>
    ${f.exploitPath ? `<p class="exploit"><strong>Exploit path:</strong> ${esc2(f.exploitPath)}</p>` : ""}
    ${refs ? `<p class="refs">${refs}</p>` : ""}
  </section>`;
}
function renderHtml(d) {
  const c = d.manifest.counts.bySeverity;
  const fs = d.findings.slice().sort((a, b) => (b.risk ?? -1) - (a.risk ?? -1) || sevRank3(a.severity) - sevRank3(b.severity) || byStr(a.id, b.id));
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
  .risk { margin:6px 0 4px; display:flex; flex-wrap:wrap; gap:6px; align-items:center; }
  .kv { font-size:12px; font-weight:600; color:#6b7280; }
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
  const run = resolve9(flagStr(args, "run") ?? ".ultrasec");
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
  for (const [name, body] of outputs) writeFileSync6(join13(run, name), body);
  println(`ultrasec render \u2192 ${run}`);
  for (const [name] of outputs) println(`  ${join13(run, name)}`);
  return 0;
}

// src/commands/clean.ts
import { execFileSync as execFileSync4 } from "child_process";
import { existsSync as existsSync7, rmSync } from "fs";
import { resolve as resolve10 } from "path";
var TOOLBOX_IMAGE = "ultrasec-toolbox";
var VOLUME_NAME_FILTER = "trivy-cache";
function dockerImages() {
  return [...new Set(ADAPTERS.map((a) => a.dockerImage).filter((x) => Boolean(x))), TOOLBOX_IMAGE];
}
function dockerAvailable() {
  try {
    execFileSync4("docker", ["--version"], { stdio: "ignore", timeout: 5e3 });
    return true;
  } catch {
    return false;
  }
}
function docker(args) {
  try {
    const out = execFileSync4("docker", args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 6e4 });
    return { ok: true, out };
  } catch {
    return { ok: false, out: "" };
  }
}
function runClean(args) {
  const run = resolve10(flagStr(args, "run") ?? ".ultrasec");
  const dry = flagBool(args, "dry-run");
  const withDocker = flagBool(args, "docker");
  const keepOutput = flagBool(args, "keep-output");
  const removed = [];
  if (!keepOutput && existsSync7(run)) {
    if (!dry) rmSync(run, { recursive: true, force: true });
    removed.push(`output  ${run}`);
  }
  if (withDocker) {
    if (!dockerAvailable()) {
      eprintln("ultrasec clean: docker not available \u2014 skipping image/volume cleanup.");
    } else {
      for (const img of dockerImages()) {
        const present = docker(["images", "-q", img]);
        if (present.ok && present.out.trim()) {
          if (!dry) docker(["image", "rm", "-f", img]);
          removed.push(`image   ${img}`);
        }
      }
      const vols = docker(["volume", "ls", "-q", "-f", `name=${VOLUME_NAME_FILTER}`]);
      for (const v of vols.out.split("\n").map((s) => s.trim()).filter(Boolean)) {
        if (!dry) docker(["volume", "rm", v]);
        removed.push(`volume  ${v}`);
      }
    }
  }
  if (flagBool(args, "json")) {
    println(JSON.stringify({ dryRun: dry, removed }, null, 2));
    return 0;
  }
  if (!removed.length) {
    println("ultrasec clean: nothing to remove.");
    return 0;
  }
  println(`ultrasec clean${dry ? " (dry-run)" : ""}:`);
  for (const r of removed) println(`  ${dry ? "would remove" : "removed"}  ${r}`);
  if (!withDocker) println(`  (add --docker to also remove scanner images + the trivy cache volume)`);
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
  map        Cheap attack-surface recon: where untrusted input enters + what sinks
             exist, with suggested scoped targets. No taint BFS, no tools, no
             network \u2014 fast on huge repos. Flags: --scope \xB7 --out \xB7 --json.
  scan       Scan a repo: detect stack, run available tools (correlated across
             scanners), build the link-graph, enumerate candidate taint paths,
             rank by EPSS/KEV/CVSS risk, write the audit dossier.
             Flags: --tools auto|none|a,b \xB7 --docker \xB7 --no-enrich/--offline \xB7
             --scope/--include/--exclude/--max-files/--gitignore (focus) \xB7
             --budget quick|standard|thorough \xB7 --max-candidates \xB7 --max-depth \xB7
             --diff <ref>/--since <commit> \xB7 --merge \xB7 --resume (incremental).
  tools      List known external scanners, which are installed, and how to get them.
  graph      Show the links into/out of a file or symbol.
  paths      List candidate cross-file source\u2192sink chains.
  dossier    Print the grounding packet for one finding (real code + neighbours).
  verify     Emit / apply the adversarial finding\u2194evidence worklist.
  render     Render SUMMARY/REPORT/FULL.md + a self-contained index.html.
  check      Gate: every finding must cite resolvable [file:line] (anti-hallucination);
             --semantic also folds in the verify verdicts.
  clean      Remove the audit dossier and, with --docker, the scanner images +
             toolbox image + trivy cache volume (--dry-run to preview).

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
    case "map":
      return runMap(args);
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
    case "clean":
      return runClean(args);
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

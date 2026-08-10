import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { flagBool, flagStr, println, eprintln, type ParsedArgs } from "../util.js";

// `ultrasec route <target>` — the triage desk for work OUTSIDE ultrasec's scope.
//
// ultrasec is a static source auditor. It does not reverse binaries, drive a
// fuzzer, or run a pentest — and it must not pretend to. But when someone hands
// it an .apk, a stripped .so, a .pcap or a live host, the useful answer isn't
// "out of scope"; it's "here is the methodology and the tools for THAT". This
// command classifies a target by shape and prints that guidance. It is ADVISORY
// ONLY: it reads a filename/URL string, matches a data table, and prints — it
// never executes a tool, never touches the network, never reads the target. In
// scope, it routes back to `ultrasec scan` (source) or `ultrasec probe` (a live
// host you own). Anything else, it hands you the right external toolkit.

interface RouteTool {
  name: string;
  why: string;
  run: string;
  url: string;
}

interface RouteEntry {
  id: string;
  title: string;
  exts: string[];
  methodology: string;
  tools: RouteTool[];
  note?: string;
}

// The out-of-scope target catalog, data-only (mirrors src/actions.ts VECTORS and
// src/tools/registry.ts TOOLS). Ordered: the first entry whose ext matches wins;
// an entry's `note` names the alternates for an ambiguous extension.
export const ROUTE_TABLE: RouteEntry[] = [
  {
    id: "android-apk",
    title: "Android app (APK)",
    exts: ["apk", "aab", "dex"],
    methodology:
      "Unpack → read the manifest & smali/Java → find the interesting code (crypto, network, WebViews, exported components) → hook at runtime if needed.",
    tools: [
      { name: "jadx", why: "APK → readable Java", run: "jadx -d out app.apk", url: "https://github.com/skylot/jadx" },
      { name: "apktool", why: "decode resources + smali, repackage", run: "apktool d app.apk", url: "https://apktool.org" },
      { name: "MobSF", why: "automated static+dynamic mobile audit", run: "mobsf (docker)", url: "https://mobsf.github.io/docs/" },
      { name: "frida / objection", why: "runtime hooking, SSL-pinning bypass", run: "objection -g <pkg> explore", url: "https://frida.re" },
    ],
    note: "Extracted Java/Kotlin/JS can then be audited statically with `ultrasec scan` on the decompiled tree.",
  },
  {
    id: "ios-ipa",
    title: "iOS app (IPA / Mach-O)",
    exts: ["ipa"],
    methodology: "Unzip the IPA → inspect the Mach-O + Info.plist → class-dump the Objective-C/Swift metadata → hook with Frida on a jailbroken device.",
    tools: [
      { name: "MobSF", why: "iOS static analysis", run: "mobsf (docker)", url: "https://mobsf.github.io/docs/" },
      { name: "class-dump / dsdump", why: "recover ObjC/Swift interfaces", run: "class-dump App", url: "https://github.com/nygard/class-dump" },
      { name: "frida / objection", why: "runtime hooking, pinning bypass", run: "objection -g <app> explore", url: "https://frida.re" },
    ],
  },
  {
    id: "native-binary",
    title: "Native binary (ELF / PE / Mach-O)",
    exts: ["so", "elf", "exe", "bin", "o", "a", "dylib", "out", "ko"],
    methodology:
      "Triage (file/strings/checksec) → disassemble/decompile → identify the vulnerable routine → debug dynamically. For a crash/exploit target, pivot to the pwn toolkit.",
    tools: [
      { name: "radare2 / rizin + cutter", why: "open-source disassembly & decompilation", run: "r2 -A ./bin", url: "https://rizin.re" },
      { name: "Ghidra", why: "free decompiler (NSA)", run: "ghidraRun", url: "https://ghidra-sre.org" },
      { name: "IDA Pro", why: "industry-standard decompiler", run: "ida64 ./bin", url: "https://hex-rays.com" },
      { name: "gdb + pwndbg/gef", why: "dynamic analysis & exploit dev", run: "gdb ./bin", url: "https://github.com/pwndbg/pwndbg" },
    ],
    note: "A .dll/.exe may be managed .NET — if so use the .NET toolkit (dnSpy/ILSpy). A firmware blob → binwalk. An exploitation target → pwntools/ROPgadget.",
  },
  {
    id: "dotnet",
    title: ".NET assembly (managed)",
    exts: ["nupkg"],
    methodology: "Decompile IL → C# → deobfuscate if packed (ConfuserEx/de4dot) → read the logic.",
    tools: [
      { name: "dnSpyEx", why: "decompile + debug .NET", run: "dnSpy app.dll", url: "https://github.com/dnSpyEx/dnSpy" },
      { name: "ILSpy", why: "cross-platform .NET decompiler", run: "ilspycmd app.dll", url: "https://github.com/icsharpcode/ILSpy" },
      { name: "de4dot", why: "unpack common .NET obfuscators", run: "de4dot app.dll", url: "https://github.com/de4dot/de4dot" },
    ],
    note: "Managed .dll/.exe share extensions with native ones — this is the managed toolkit; use `native-binary` for compiled code.",
  },
  {
    id: "firmware",
    title: "Firmware image",
    exts: ["img", "fw", "trx", "chk", "dlf", "rom"],
    methodology: "Carve the filesystem → extract → enumerate binaries/creds/config → analyze the interesting binaries as native code.",
    tools: [
      { name: "binwalk", why: "carve & extract firmware filesystems", run: "binwalk -eM firmware.bin", url: "https://github.com/ReFirmLabs/binwalk" },
      { name: "EMBA", why: "automated firmware security analyzer", run: "emba -f firmware.bin", url: "https://github.com/e-m-b-a/emba" },
      { name: "ubi_reader / jefferson", why: "UBIFS/JFFS2 extraction", run: "ubireader_extract_files", url: "https://github.com/onekey-sec/ubi_reader" },
    ],
    note: "Once the rootfs is extracted, `ultrasec scan` the scripts/source and `ultrasec route` the extracted binaries.",
  },
  {
    id: "network-capture",
    title: "Network capture (pcap)",
    exts: ["pcap", "pcapng"],
    methodology: "Open the capture → follow streams → extract objects/creds → build a timeline; automate with a network-analysis engine for large captures.",
    tools: [
      { name: "Wireshark / tshark", why: "packet inspection, stream follow", run: "tshark -r capture.pcap", url: "https://www.wireshark.org" },
      { name: "Zeek", why: "protocol logs from a capture", run: "zeek -r capture.pcap", url: "https://zeek.org" },
      { name: "NetworkMiner", why: "extract files/credentials", run: "NetworkMiner", url: "https://www.netresec.com/?page=NetworkMiner" },
    ],
  },
  {
    id: "wifi-capture",
    title: "Wi-Fi handshake capture",
    exts: ["cap", "hccapx", "22000", "pcapng-wifi"],
    methodology: "Confirm the handshake → convert to the cracker's format → run a wordlist/mask attack (only on networks you own or are authorized to test).",
    tools: [
      { name: "aircrack-ng", why: "capture/verify/crack WPA handshakes", run: "aircrack-ng -w wordlist capture.cap", url: "https://www.aircrack-ng.org" },
      { name: "hashcat", why: "GPU cracking of 22000/hccapx", run: "hashcat -m 22000 hash wordlist", url: "https://hashcat.net/hashcat/" },
    ],
    note: "A .cap can also be a generic pcap — if it isn't a Wi-Fi handshake, use the network-capture tools.",
  },
  {
    id: "browser-extension",
    title: "Browser extension (CRX / XPI)",
    exts: ["crx", "xpi"],
    methodology: "Unzip → read the manifest (permissions, host_permissions, content scripts) → audit the JS (often the highest-risk surface).",
    tools: [
      { name: "unzip", why: "a CRX/XPI is a zip", run: "unzip ext.crx -d ext/", url: "https://linux.die.net/man/1/unzip" },
      { name: "CRXViewer", why: "browse/download extension source", run: "web tool", url: "https://robwu.nl/crxviewer/" },
    ],
    note: "After unzip, `ultrasec scan --repo ext/` audits the extension's JavaScript directly (this part IS in scope).",
  },
  {
    id: "jvm-archive",
    title: "Java archive (JAR / WAR)",
    exts: ["jar", "war", "ear", "class"],
    methodology: "Decompile to Java → read the logic → then audit the recovered source statically.",
    tools: [
      { name: "CFR / procyon", why: "JAR → Java", run: "cfr app.jar --outputdir out", url: "https://www.benf.org/other/cfr/" },
      { name: "jadx", why: "also decompiles JAR/class", run: "jadx -d out app.jar", url: "https://github.com/skylot/jadx" },
    ],
    note: "Decompiled sources → `ultrasec scan` on the output tree.",
  },
  {
    id: "malware-sample",
    title: "Suspected malware sample",
    exts: ["vir", "malware", "sample"],
    methodology: "Handle in an isolated VM → static triage (hashes, YARA, capabilities) → detonate in a sandbox → extract IOCs. Never run it on a real host.",
    tools: [
      { name: "YARA", why: "signature matching / classification", run: "yara rules.yar sample", url: "https://virustotal.github.io/yara/" },
      { name: "capa", why: "identify capabilities in an executable", run: "capa sample", url: "https://github.com/mandiant/capa" },
      { name: "CAPE / Cuckoo", why: "sandbox detonation + IOCs", run: "cape (docker)", url: "https://github.com/kevoreilly/CAPEv2" },
    ],
    note: "For the executable's internals, also see `native-binary`.",
  },
];

const OUT_OF_SCOPE_NOTE =
  "ultrasec is a static SOURCE auditor — it does NOT run these tools, touch the network, or read the target. This is advisory triage; run the tools yourself, on assets you are authorized to test.";

// ultrasec's own source-language extensions — a target with one of these (or no
// extension, i.e. a directory) is IN scope: route it to `scan`.
const SOURCE_EXTS = new Set([
  "js",
  "jsx",
  "mjs",
  "cjs",
  "ts",
  "tsx",
  "mts",
  "cts",
  "py",
  "pyi",
  "go",
  "java",
  "rb",
  "php",
  "rs",
  "c",
  "h",
  "cc",
  "cpp",
  "cxx",
  "hpp",
  "hh",
  "hxx",
  "cs",
  "kt",
  "kts",
  "swift",
  "scala",
  "sc",
  "sh",
  "bash",
  "zsh",
  "lua",
  "ex",
  "exs",
  // IaC / config / manifests: NOT a parsed "language", but the cloud, web-config
  // and agentic-CI detectors read them under `scan` — so they are in scope, and
  // routing them to an external toolkit would send the user away from the tool
  // that actually covers them (measured on kubernetes-goat / terragoat).
  "yaml",
  "yml",
  "tf",
  "tfvars",
  "hcl",
  "json",
]);

/** Files with no extension that ultrasec's detectors still cover. */
const SOURCE_BASENAMES = new Set(["dockerfile", "makefile", "jenkinsfile", "procfile"]);

function extOf(target: string): string {
  const base = target.split(/[\\/]/).pop() ?? target;
  const i = base.lastIndexOf(".");
  return i <= 0 ? "" : base.slice(i + 1).toLowerCase();
}

function baseNameOf(target: string): string {
  return (target.split(/[\\/]/).pop() ?? target).toLowerCase();
}

type Classification = { kind: "probe"; url: string } | { kind: "scan" } | { kind: "external"; entry: RouteEntry } | { kind: "unknown"; ext: string };

export function classifyTarget(target: string): Classification {
  if (/^https?:\/\//i.test(target)) return { kind: "probe", url: target };
  const ext = extOf(target);
  // No extension = a directory (or a Dockerfile-style name) → the repo case.
  if (ext === "" || SOURCE_EXTS.has(ext) || SOURCE_BASENAMES.has(baseNameOf(target))) return { kind: "scan" };
  const entry = ROUTE_TABLE.find((e) => e.exts.includes(ext));
  if (entry) return { kind: "external", entry };
  return { kind: "unknown", ext };
}

interface RouteResult {
  target: string;
  type: string;
  inScope: boolean;
  recommendedCommand?: string;
  methodology?: string;
  tools?: RouteTool[];
  note: string;
}

function buildResult(target: string, c: Classification): RouteResult {
  if (c.kind === "probe")
    return {
      target,
      type: "Live host / running web app",
      inScope: true,
      recommendedCommand: `ultrasec probe ${target} --i-own-this`,
      methodology: "Static posture (headers/TLS/cookies/CORS/GraphQL) with `ultrasec probe`; full dynamic testing needs a DAST toolkit.",
      tools: [
        { name: "ultrasec probe", why: "read-only posture on the wire (ours)", run: `ultrasec probe ${target} --i-own-this`, url: "" },
        { name: "nmap", why: "port/service discovery", run: "nmap -sVC host", url: "https://nmap.org" },
        { name: "nuclei", why: "templated vulnerability checks", run: "nuclei -u " + target, url: "https://github.com/projectdiscovery/nuclei" },
        { name: "OWASP ZAP / Burp Suite", why: "intercepting proxy + active scan", run: "zaproxy", url: "https://www.zaproxy.org" },
        { name: "sqlmap", why: "confirm/exploit SQL injection", run: "sqlmap -u " + target, url: "https://sqlmap.org" },
      ],
      note: "Only test hosts you own or are explicitly authorized to. ultrasec runs none of these except its own read-only probe.",
    };
  if (c.kind === "scan")
    return {
      target,
      type: "Source code / repository",
      inScope: true,
      recommendedCommand: `ultrasec scan --repo ${target || "."}`,
      methodology: "This IS ultrasec's job — cross-file taint + config/auth/cloud detectors + external scanners.",
      note: "Run `ultrasec scan` on it directly; no external routing needed.",
    };
  if (c.kind === "external")
    return {
      target,
      type: c.entry.title,
      inScope: false,
      methodology: c.entry.methodology,
      tools: c.entry.tools,
      note: c.entry.note ? `${c.entry.note} ${OUT_OF_SCOPE_NOTE}` : OUT_OF_SCOPE_NOTE,
    };
  return {
    target,
    type: `Unrecognized (.${c.ext || "?"})`,
    inScope: false,
    note: `No routing rule matched. If it's source, run \`ultrasec scan\`; if it's a live host, pass an http(s):// URL. Otherwise pick the closest category below. ${OUT_OF_SCOPE_NOTE}`,
  };
}

function renderMd(r: RouteResult): string {
  const L: string[] = [`# ultrasec route — ${r.target}`, ""];
  L.push(`- target type: **${r.type}** ${r.inScope ? "(in scope)" : "(out of scope — advisory)"}`);
  if (r.recommendedCommand) L.push(`- recommended: \`${r.recommendedCommand}\``);
  if (r.methodology) L.push(`- methodology: ${r.methodology}`);
  L.push("");
  if (r.tools?.length) {
    L.push(`## Recommended tools`);
    for (const t of r.tools) L.push(`- **${t.name}** — ${t.why}${t.run ? `  ·  run: \`${t.run}\`` : ""}${t.url ? `  ·  ${t.url}` : ""}`);
    L.push("");
  }
  if (c_unknownGeneralGuide(r)) {
    L.push(`## Target categories`);
    for (const e of ROUTE_TABLE) L.push(`- **${e.title}** — .${e.exts.join(", .")}`);
    L.push(`- **Live host** — an http(s):// URL → \`ultrasec probe\``);
    L.push(`- **Source / repo** — a directory or source file → \`ultrasec scan\``);
    L.push("");
  }
  L.push(`> ${r.note}`);
  return `${L.join("\n")}\n`;
}

// The general category guide is shown only when nothing matched.
function c_unknownGeneralGuide(r: RouteResult): boolean {
  return r.type.startsWith("Unrecognized");
}

export function runRoute(args: ParsedArgs): number {
  const target = args._[1];
  if (!target) {
    eprintln("usage: ultrasec route <target>   (a file path like app.apk / ./bin/x.so, or an http(s):// URL)");
    return 2;
  }
  const c = classifyTarget(target);
  const result = buildResult(target, c);

  if (flagStr(args, "out") !== undefined || flagBool(args, "write")) {
    const out = resolve(flagStr(args, "out") ?? ".");
    mkdirSync(out, { recursive: true });
    const p = join(out, "ROUTE.md");
    writeFileSync(p, renderMd(result));
    if (!flagBool(args, "json")) println(`ultrasec route → ${p}`);
  }

  if (flagBool(args, "json")) {
    println(JSON.stringify(result, null, 2));
    return 0;
  }

  println(`ultrasec route: ${result.target}`);
  println(`  type: ${result.type}  ${result.inScope ? "(in scope)" : "(out of scope — advisory)"}`);
  if (result.recommendedCommand) println(`  → ${result.recommendedCommand}`);
  if (result.methodology) println(`  methodology: ${result.methodology}`);
  if (result.tools?.length) {
    println(`  recommended tools:`);
    for (const t of result.tools) println(`    - ${t.name} — ${t.why}${t.run ? `  (run: ${t.run})` : ""}`);
  }
  if (c.kind === "unknown") {
    println(`  target categories:`);
    for (const e of ROUTE_TABLE) println(`    - ${e.title}: .${e.exts.join(", .")}`);
    println(`    - Live host: http(s):// URL → ultrasec probe`);
    println(`    - Source / repo: a directory or source file → ultrasec scan`);
  }
  println(`  note: ${result.note}`);
  return 0;
}

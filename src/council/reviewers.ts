import { accessSync, constants, existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import { compilePlaceholderPatterns } from "../placeholders.js";

// Reviewers are DATA. A reviewer is an agent CLI described by one spec: how it
// is started on the snapshot, how one of its sessions is resumed for a single
// closing turn, what it prints, and how its stops are told apart. The runner
// knows nothing about any particular CLI; the built-in entries below are
// presets in exactly the format a user writes in a config file, and a config
// entry of the same name overrides a preset field by field.
//
// The rules every spec must keep were paid for on a real audit that ran several
// CLIs in parallel as blind reviewers:
//  - argv arrays, never shell strings;
//  - the message is the SHORT static pointer to the brief file (`{message}`) —
//    a ~60 KB prompt passed as one argv element made a CLI hang at init for
//    eleven minutes, and the brief carries attacker-influenced paths that must
//    never reach a command line anyway (the same rule powered mode follows);
//  - the CLI's read-only mode, and its user plugins switched off when it has
//    any: a user plugin once replaced a CLI's default agent with one that
//    delegated to a model that did not exist, and the run stalled with no error.

/** What the CLI prints on stdout. */
export type EventsKind =
  /** One JSON event per line — steps with usage, text parts, tool calls, errors. */
  | "jsonl-steps"
  /** One JSON result object (the last JSON line on stdout). */
  | "jsonl"
  /** Plain text: stdout IS the report. */
  | "text"
  /** Nothing useful on stdout: the report is read from `{outFile}`. */
  | "none";
export const EVENTS_KINDS: readonly EventsKind[] = ["jsonl-steps", "jsonl", "text", "none"];

export type FinalTextFrom = "events-text" | "stdout" | "file";
export const FINAL_TEXT_FROM: readonly FinalTextFrom[] = ["events-text", "stdout", "file"];

/** An argv element, or a group of elements kept or dropped together (`["--model", "{model}"]`). */
export type ArgTemplate = string | string[];

/** Dotted paths into a JSON event (`part.tokens.input`). */
export interface UsagePaths {
  input?: string;
  output?: string;
  reasoning?: string;
  cacheRead?: string;
  cacheWrite?: string;
  /** USD. */
  cost?: string;
  /** Turns; absent on `jsonl-steps`, where each step event counts one. */
  steps?: string;
}

export interface EventPaths {
  /** Field naming the event type (`jsonl-steps`). Default `type`. */
  type?: string;
  textType?: string;
  stepType?: string;
  toolType?: string;
  errorType?: string;
  /** The text of a text event (`jsonl-steps`), or the final answer in the result object (`jsonl`). */
  text?: string;
  /** The message a text event belongs to: the report is the LAST message's text. */
  messageId?: string;
  /** Paths that carry an error payload on any event. */
  errors?: string[];
  /** `jsonl`: a boolean path that marks the result an error. */
  errorFlag?: string;
}

export interface ReviewerSpec {
  name: string;
  /** Binary looked up on PATH (or an absolute path). */
  bin: string;
  /** Arguments for a fresh review. Placeholders: {brief} {briefPath} {message} {model} {dir} {title} {session} {maxTurns} {outFile}. */
  args: ArgTemplate[];
  /** Arguments to resume `{session}` for ONE closing turn; absent when the CLI cannot. */
  resumeArgs?: ArgTemplate[];
  events: EventsKind;
  /** Where the report is read from. Default: `events-text` for JSON kinds, `stdout` for text, `file` for none. */
  finalTextFrom?: FinalTextFrom;
  /** Path(s) to the session id in an event or the result object. */
  sessionIdPath?: string[];
  /** Where usage is read; absent means "usage not exposed". */
  usagePaths?: UsagePaths;
  eventPaths?: EventPaths;
  /** Prepended to `{model}` unless already there (a CLI that addresses models through its own gateway). */
  modelPrefix?: string;
  /** Extra environment, templated like args (an entry that expands empty is dropped) — configuration, never a credential. */
  env?: Record<string, string>;
  /** Variables copied from the launching shell. Each one weakens the emptied environment: name only what the CLI needs. */
  envPassthrough?: string[];
  /** Regexes (case-insensitive) checked before the generic ones. */
  quotaPatterns?: string[];
  creditPatterns?: string[];
  transientPatterns?: string[];
  /** How read-only is enforced — shown in the plan. */
  readOnly: string;
  description?: string;
}

const PLACEHOLDERS = ["brief", "briefPath", "message", "model", "dir", "title", "session", "maxTurns", "outFile"] as const;
export type Placeholder = (typeof PLACEHOLDERS)[number];
export type TemplateValues = Partial<Record<Placeholder, string>>;

// ── Presets ────────────────────────────────────────────────────────────────
// Common agent CLIs, as data. No model names: the model is always the user's
// `--models "<reviewer>:<model>"`. Each preset uses its CLI's read-only mode.

/** The `jsonl-steps` event layout these CLIs share. */
const STEP_EVENTS = {
  sessionIdPath: ["sessionID", "part.sessionID"],
  usagePaths: {
    input: "part.tokens.input",
    output: "part.tokens.output",
    reasoning: "part.tokens.reasoning",
    cacheRead: "part.tokens.cache.read",
    cacheWrite: "part.tokens.cache.write",
    cost: "part.cost",
  },
  eventPaths: {
    type: "type",
    textType: "text",
    stepType: "step_finish",
    toolType: "tool_use",
    errorType: "error",
    text: "part.text",
    messageId: "part.messageID",
    errors: ["error", "part.error"],
  },
} as const satisfies Partial<ReviewerSpec>;

const stepRun = (extra: string[]): ArgTemplate[] => [
  "run",
  ["-m", "{model}"],
  "--agent",
  "plan",
  "--pure",
  ...extra,
  "--dir",
  "{dir}",
  "--format",
  "json",
  "--title",
  "{title}",
  "{message}",
];
const stepResume = (extra: string[]): ArgTemplate[] => ["run", "-s", "{session}", ...stepRun(extra).slice(1)];

export const PRESETS: Readonly<Record<string, ReviewerSpec>> = {
  opencode: {
    name: "opencode",
    bin: "opencode",
    args: stepRun([]),
    resumeArgs: stepResume([]),
    events: "jsonl-steps",
    ...STEP_EVENTS,
    readOnly: "`--agent plan` (read-only primary agent), `--pure` (user plugins off)",
  },
  kilo: {
    name: "kilo",
    bin: "kilo",
    // `--auto` keeps a headless run from blocking on a permission prompt; with
    // the plan agent it approves only what that agent does not deny (edits are).
    args: stepRun(["--auto"]),
    resumeArgs: stepResume(["--auto"]),
    events: "jsonl-steps",
    ...STEP_EVENTS,
    modelPrefix: "kilo/",
    readOnly: "`--agent plan --auto` (plan agent denies edits), `--pure`",
  },
  vibe: {
    name: "vibe",
    bin: "vibe",
    // Text only when the run ends, no usage, no session id; the model is configuration.
    args: ["-p", "{message}", "--agent", "plan", "--trust", "--workdir", "{dir}", "--max-turns", "{maxTurns}", "--output", "text"],
    events: "text",
    env: { VIBE_ACTIVE_MODEL: "{model}" },
    readOnly: "`--agent plan`",
  },
  claude: {
    name: "claude",
    bin: "claude",
    args: ["-p", "{message}", "--output-format", "json", "--allowedTools", "Read,Grep,Glob", "--max-turns", "{maxTurns}", ["--model", "{model}"]],
    resumeArgs: [
      "-p",
      "{message}",
      "--resume",
      "{session}",
      "--output-format",
      "json",
      "--allowedTools",
      "Read,Grep,Glob",
      "--max-turns",
      "1",
      ["--model", "{model}"],
    ],
    events: "jsonl",
    sessionIdPath: ["session_id"],
    usagePaths: {
      input: "usage.input_tokens",
      output: "usage.output_tokens",
      cacheRead: "usage.cache_read_input_tokens",
      cacheWrite: "usage.cache_creation_input_tokens",
      cost: "total_cost_usd",
      steps: "num_turns",
    },
    eventPaths: { text: "result", errorFlag: "is_error" },
    readOnly: "`--allowedTools Read,Grep,Glob`",
  },
  codex: {
    name: "codex",
    bin: "codex",
    // The snapshot is not a git checkout, which this CLI refuses without the flag.
    args: ["exec", "--sandbox", "read-only", "--skip-git-repo-check", "-C", "{dir}", ["-m", "{model}"], "{message}"],
    events: "text",
    readOnly: "`--sandbox read-only`",
  },
};

// ── Config ─────────────────────────────────────────────────────────────────

/**
 * Where a user's reviewer config is found when `--reviewer-config` is not given:
 * `$XDG_CONFIG_HOME/ultrasec/council.json` (default `~/.config/…`).
 *
 * Never inside the repository under audit, nor the run directory (which
 * defaults to `.ultrasec/` inside that repository): a reviewer spec names a
 * binary and its argv, and a config the audited code could ship would be a
 * command it runs on the auditor's machine. For the same reason a `--resume`
 * re-resolves its reviewer from presets and config, never from the ledger.
 */
export function defaultConfigPath(env: NodeJS.ProcessEnv = process.env): string {
  const base = env.XDG_CONFIG_HOME || join(env.HOME || homedir(), ".config");
  return join(base, "ultrasec", "council.json");
}

export interface CouncilConfig {
  reviewers: Record<string, ReviewerSpec>;
  placeholderPatterns: RegExp[];
  /** Where it came from, for messages. */
  source?: string;
}

export interface ReviewerRegistry {
  specs: ReadonlyMap<string, ReviewerSpec>;
  /** Which names come from the config (new or overriding a preset). */
  fromConfig: ReadonlySet<string>;
  placeholderPatterns: RegExp[];
  source?: string;
}

const SPEC_KEYS = new Set<string>([
  "extends",
  "bin",
  "args",
  "resumeArgs",
  "events",
  "finalTextFrom",
  "sessionIdPath",
  "usagePaths",
  "eventPaths",
  "modelPrefix",
  "env",
  "envPassthrough",
  "quotaPatterns",
  "creditPatterns",
  "transientPatterns",
  "readOnly",
  "description",
]);
const USAGE_KEYS = new Set(["input", "output", "reasoning", "cacheRead", "cacheWrite", "cost", "steps"]);
const EVENT_KEYS = new Set(["type", "textType", "stepType", "toolType", "errorType", "text", "messageId", "errors", "errorFlag"]);
/** Reviewer names become directory and file names: keep them boring. */
const NAME = /^[a-z][a-z0-9_]*(?:-[a-z][a-z0-9_]*)*$/;

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const isStrArr = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string");

function checkTemplate(where: string, s: string): void {
  for (const m of s.matchAll(/\{(\w+)\}/g)) {
    if (!(PLACEHOLDERS as readonly string[]).includes(m[1]!))
      throw new Error(`${where}: unknown placeholder {${m[1]}} (known: ${PLACEHOLDERS.map((p) => `{${p}}`).join(" ")})`);
  }
}

function checkArgs(where: string, v: unknown): ArgTemplate[] {
  if (!Array.isArray(v) || !v.length) throw new Error(`${where}: expected a non-empty array of strings or string groups`);
  return v.map((a, i) => {
    if (typeof a === "string") {
      checkTemplate(`${where}[${i}]`, a);
      return a;
    }
    if (isStrArr(a) && a.length) {
      for (const s of a) checkTemplate(`${where}[${i}]`, s);
      return [...a];
    }
    throw new Error(`${where}[${i}]: expected a string or a non-empty array of strings`);
  });
}

function checkPatterns(where: string, v: unknown): string[] {
  if (!isStrArr(v)) throw new Error(`${where}: expected an array of regex strings`);
  for (const p of v) {
    try {
      new RegExp(p, "i");
    } catch (e) {
      throw new Error(`${where}: invalid regex ${JSON.stringify(p)} (${(e as Error).message})`);
    }
  }
  return [...v];
}

function checkPaths<K extends string>(where: string, v: unknown, keys: ReadonlySet<string>): Partial<Record<K, unknown>> {
  if (!isObj(v)) throw new Error(`${where}: expected an object`);
  for (const [k, val] of Object.entries(v)) {
    if (!keys.has(k)) throw new Error(`${where}: unknown key "${k}" (known: ${[...keys].join(", ")})`);
    if (k === "errors") {
      if (!isStrArr(val)) throw new Error(`${where}.errors: expected an array of paths`);
    } else if (typeof val !== "string" || !val) throw new Error(`${where}.${k}: expected a non-empty dotted path`);
  }
  return v as Partial<Record<K, unknown>>;
}

/**
 * Validate one reviewer entry from a config file, fail-closed: an unknown key
 * is a typo that would otherwise silently change nothing. `base` is the preset
 * (or `extends` target) it overrides, field by field.
 */
export function parseReviewerEntry(name: string, raw: unknown, base: ReviewerSpec | undefined, where: string): ReviewerSpec {
  if (!NAME.test(name)) throw new Error(`${where}: reviewer name "${name}" must be lower-case letters, digits, "_" and "-"`);
  if (!isObj(raw)) throw new Error(`${where}: expected an object`);
  for (const k of Object.keys(raw)) if (!SPEC_KEYS.has(k)) throw new Error(`${where}: unknown key "${k}" (known: ${[...SPEC_KEYS].join(", ")})`);
  const out: Record<string, unknown> = { ...(base ?? {}), name };
  for (const [k, v] of Object.entries(raw)) {
    const at = `${where}.${k}`;
    switch (k) {
      case "extends":
        break;
      case "bin":
      case "readOnly":
      case "description":
      case "modelPrefix":
        if (typeof v !== "string" || (k !== "modelPrefix" && !v)) throw new Error(`${at}: expected a non-empty string`);
        out[k] = v;
        break;
      case "args":
      case "resumeArgs":
        out[k] = checkArgs(at, v);
        break;
      case "events":
        if (!(EVENTS_KINDS as readonly unknown[]).includes(v)) throw new Error(`${at}: expected one of ${EVENTS_KINDS.join(" | ")}`);
        out[k] = v;
        break;
      case "finalTextFrom":
        if (!(FINAL_TEXT_FROM as readonly unknown[]).includes(v)) throw new Error(`${at}: expected one of ${FINAL_TEXT_FROM.join(" | ")}`);
        out[k] = v;
        break;
      case "sessionIdPath":
        if (typeof v === "string" && v) out[k] = [v];
        else if (isStrArr(v) && v.length) out[k] = [...v];
        else throw new Error(`${at}: expected a dotted path or an array of them`);
        break;
      case "usagePaths":
        out[k] = checkPaths(at, v, USAGE_KEYS);
        break;
      case "eventPaths":
        out[k] = { ...((base?.eventPaths as object | undefined) ?? {}), ...checkPaths(at, v, EVENT_KEYS) };
        break;
      case "env": {
        if (!isObj(v) || !Object.values(v).every((x) => typeof x === "string")) throw new Error(`${at}: expected an object of strings`);
        for (const [ek, ev] of Object.entries(v)) {
          if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(ek)) throw new Error(`${at}: "${ek}" is not an environment variable name`);
          checkTemplate(`${at}.${ek}`, ev as string);
        }
        out[k] = { ...(v as Record<string, string>) };
        break;
      }
      case "envPassthrough":
        if (!isStrArr(v)) throw new Error(`${at}: expected an array of variable names`);
        out[k] = [...v];
        break;
      case "quotaPatterns":
      case "creditPatterns":
      case "transientPatterns":
        out[k] = checkPatterns(at, v);
        break;
    }
  }
  if (typeof out.bin !== "string" || !out.bin) throw new Error(`${where}: "bin" is required`);
  if (!Array.isArray(out.args)) throw new Error(`${where}: "args" is required`);
  if (!out.events) throw new Error(`${where}: "events" is required (${EVENTS_KINDS.join(" | ")})`);
  if (typeof out.readOnly !== "string" || !out.readOnly) throw new Error(`${where}: "readOnly" is required — say how this CLI is kept from writing`);
  const spec = out as unknown as ReviewerSpec;
  if (!spec.args.flat().some((a) => a.includes("{message}") || a.includes("{briefPath}") || a.includes("{brief}")))
    throw new Error(`${where}: "args" must pass the brief — {message}, {brief} or {briefPath}`);
  if (finalTextFrom(spec) === "file" && !spec.args.flat().some((a) => a.includes("{outFile}")))
    throw new Error(`${where}: the report is read from a file, so "args" must pass {outFile}`);
  return spec;
}

/**
 * Parse a council config file: `{ "reviewers": { "<name>": {…} }, "placeholderPatterns": ["…"] }`.
 * An entry named like a preset, or with `"extends": "<preset>"`, overrides that
 * preset field by field; any other entry must be complete.
 */
export function parseCouncilConfig(raw: string, source: string): CouncilConfig {
  let doc: unknown;
  try {
    doc = JSON.parse(raw);
  } catch (e) {
    throw new Error(`${source}: not JSON (${(e as Error).message})`);
  }
  if (!isObj(doc)) throw new Error(`${source}: expected an object with "reviewers" and/or "placeholderPatterns"`);
  for (const k of Object.keys(doc))
    if (k !== "reviewers" && k !== "placeholderPatterns" && k !== "$schema")
      throw new Error(`${source}: unknown key "${k}" (known: reviewers, placeholderPatterns)`);
  const reviewers: Record<string, ReviewerSpec> = {};
  if (doc.reviewers !== undefined) {
    if (!isObj(doc.reviewers)) throw new Error(`${source}: "reviewers" must be an object keyed by reviewer name`);
    for (const [name, entry] of Object.entries(doc.reviewers)) {
      const where = `${source}: reviewers.${name}`;
      const ext = isObj(entry) ? entry.extends : undefined;
      if (ext !== undefined && (typeof ext !== "string" || !Object.hasOwn(PRESETS, ext)))
        throw new Error(`${where}.extends: unknown preset ${JSON.stringify(ext)} (presets: ${Object.keys(PRESETS).join(", ")})`);
      const base = typeof ext === "string" ? PRESETS[ext] : Object.hasOwn(PRESETS, name) ? PRESETS[name] : undefined;
      reviewers[name] = parseReviewerEntry(name, entry, base, where);
    }
  }
  const pp = doc.placeholderPatterns;
  if (pp !== undefined && !isStrArr(pp)) throw new Error(`${source}: "placeholderPatterns" must be an array of regex strings`);
  return { reviewers, placeholderPatterns: compilePlaceholderPatterns(pp ?? [], `${source}: placeholderPatterns`), source };
}

/** Load `path` (explicit) or the default location; presets alone when neither exists. */
export function loadRegistry(opts: { configPath?: string; env?: NodeJS.ProcessEnv; extraPlaceholders?: RegExp[] } = {}): ReviewerRegistry {
  let cfg: CouncilConfig | undefined;
  const explicit = opts.configPath ? resolve(opts.configPath) : undefined;
  const path = explicit ?? defaultConfigPath(opts.env);
  if (explicit && !existsSync(explicit)) throw new Error(`--reviewer-config: ${explicit} does not exist`);
  if (existsSync(path)) cfg = parseCouncilConfig(readFileSync(path, "utf8"), path);
  const specs = new Map<string, ReviewerSpec>(Object.entries(PRESETS));
  for (const [name, spec] of Object.entries(cfg?.reviewers ?? {})) specs.set(name, spec);
  return {
    specs,
    fromConfig: new Set(Object.keys(cfg?.reviewers ?? {})),
    placeholderPatterns: [...(cfg?.placeholderPatterns ?? []), ...(opts.extraPlaceholders ?? [])],
    ...(cfg?.source ? { source: cfg.source } : {}),
  };
}

/** The registry of presets only — for callers that take no config. */
export function presetRegistry(): ReviewerRegistry {
  return { specs: new Map(Object.entries(PRESETS)), fromConfig: new Set(), placeholderPatterns: [] };
}

export function getSpec(reg: ReviewerRegistry, name: string): ReviewerSpec {
  const s = reg.specs.get(name);
  if (!s) throw new Error(`unknown reviewer "${name}" (known: ${[...reg.specs.keys()].join(", ")}; add one with --reviewer-config or ${defaultConfigPath()})`);
  return s;
}

// ── Expansion ──────────────────────────────────────────────────────────────

export function finalTextFrom(spec: ReviewerSpec): FinalTextFrom {
  if (spec.finalTextFrom) return spec.finalTextFrom;
  if (spec.events === "text") return "stdout";
  if (spec.events === "none") return "file";
  return "events-text";
}

export const usageExposed = (spec: ReviewerSpec): boolean => !!spec.usagePaths && Object.keys(spec.usagePaths).length > 0;

/** The model as this CLI spells it. */
export function cliModel(spec: ReviewerSpec, model: string): string {
  if (!model || !spec.modelPrefix || model.startsWith(spec.modelPrefix)) return model;
  return `${spec.modelPrefix}${model}`;
}

/**
 * Expand an argv template. A string element, or a group, that references a
 * placeholder with no value is dropped whole — `["--model", "{model}"]` vanishes
 * when no model was given, rather than leaving a dangling flag.
 */
export function expandArgs(tpl: readonly ArgTemplate[], values: TemplateValues): string[] {
  const out: string[] = [];
  const refsMissing = (s: string): boolean => [...s.matchAll(/\{(\w+)\}/g)].some((m) => !values[m[1] as Placeholder]);
  const sub = (s: string): string => s.replace(/\{(\w+)\}/g, (_m, k: string) => values[k as Placeholder] ?? "");
  for (const el of tpl) {
    const group = typeof el === "string" ? [el] : el;
    if (group.some(refsMissing)) continue;
    out.push(...group.map(sub));
  }
  return out;
}

/** Arguments for a fresh run, or for a one-turn resume (null when the CLI cannot resume this session). */
export function buildArgs(spec: ReviewerSpec, values: TemplateValues, resume: boolean): string[] | null {
  const v = { ...values, model: cliModel(spec, values.model ?? "") };
  if (!resume) return expandArgs(spec.args, v);
  if (!spec.resumeArgs || !values.session) return null;
  return expandArgs(spec.resumeArgs, v);
}

/** The extra environment: templated `env` (empty entries dropped) plus `envPassthrough` from `base`. */
export function specEnv(spec: ReviewerSpec, values: TemplateValues, base: NodeJS.ProcessEnv): Record<string, string> {
  const out: Record<string, string> = {};
  for (const name of spec.envPassthrough ?? []) {
    const v = base[name];
    if (v !== undefined) out[name] = v;
  }
  const v = { ...values, model: cliModel(spec, values.model ?? "") };
  for (const [k, tpl] of Object.entries(spec.env ?? {})) {
    const [val] = expandArgs([tpl], v);
    if (val) out[k] = val;
  }
  return out;
}

// ── --models / --focus ─────────────────────────────────────────────────────

export interface ModelSpec {
  /** The reviewer entry (preset or config). */
  cli: string;
  model: string;
}

/**
 * Parse `reviewer:model[,reviewer:model…]`. The split is on the FIRST colon
 * only: model ids may carry one (`<provider>/<model>:<variant>`). Fail-closed
 * on an unknown reviewer — a typo that silently dropped one would read as
 * "that model found nothing".
 */
export function parseModelList(raw: string, flag: string, reg: ReviewerRegistry): ModelSpec[] {
  const out: ModelSpec[] = [];
  for (const part of raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)) {
    const at = part.indexOf(":");
    const cli = at < 0 ? part : part.slice(0, at);
    const model = at < 0 ? "" : part.slice(at + 1).trim();
    if (!reg.specs.has(cli))
      throw new Error(
        `${flag}: unknown reviewer "${cli}" in "${part}" (known: ${[...reg.specs.keys()].join(", ")}; define it with --reviewer-config <file.json> or in ${defaultConfigPath()})`,
      );
    out.push({ cli, model });
  }
  if (!out.length) throw new Error(`${flag}: no reviewer:model entry`);
  return out;
}

export interface Reviewer extends ModelSpec {
  /** Stable name: the entry, suffixed `-2`, `-3` when the same entry appears twice. */
  name: string;
  focus?: string;
}

/** Name each model spec, and attach its `--focus` area. */
export function reviewersFrom(specs: ModelSpec[], focus: Record<string, string> = {}): Reviewer[] {
  const seen = new Map<string, number>();
  return specs.map((s) => {
    const n = (seen.get(s.cli) ?? 0) + 1;
    seen.set(s.cli, n);
    const name = n === 1 ? s.cli : `${s.cli}-${n}`;
    const f = Object.hasOwn(focus, name) ? focus[name] : undefined;
    return { ...s, name, ...(f ? { focus: f } : {}) };
  });
}

/** `--focus "<reviewer>=src/api;<reviewer>=src/web"` → by reviewer name. */
export function parseFocus(raw: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!raw) return out;
  for (const part of raw.split(";")) {
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    const area = part.slice(eq + 1).trim();
    if (name && area) out[name] = area;
  }
  return out;
}

/**
 * Is `bin` an executable on PATH (or, when it has a slash, at that path)? A
 * filesystem probe, NOT a spawn: `council` without `--models` promises to call
 * nothing, and `--version` on some CLIs phones home for an upgrade check.
 */
export function onPath(bin: string, path = process.env.PATH ?? ""): string | undefined {
  const exts = process.platform === "win32" ? ["", ".exe", ".cmd"] : [""];
  const dirs = bin.includes("/") ? [""] : path.split(delimiter).filter(Boolean);
  for (const dir of dirs) {
    for (const ext of exts) {
      const p = dir ? join(dir, bin + ext) : bin + ext;
      try {
        accessSync(p, constants.X_OK);
        return p;
      } catch {
        /* not here */
      }
    }
  }
  return undefined;
}

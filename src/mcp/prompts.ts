import { TOOLS, WRITE_TOOLS } from "./tools.js";

// The workflows, as MCP prompts.
//
// Tools are the half of this skill a client can discover on its own. The other
// half is the thesis the whole engine rests on: it finds CANDIDATES, and you
// decide whether each is really reachable and exploitable. A model handed a
// path list and no protocol reports all of them as vulnerabilities — which is
// the single worst outcome a security tool can produce, because a report full
// of false positives gets the real finding ignored along with the rest.
//
// Each prompt says three things, in this order: the contract, the exact tool
// sequence, and what the gate does on failure.

export interface PromptArgument {
  name: string;
  description: string;
  required?: boolean;
}

export interface PromptDecl {
  name: string;
  title?: string;
  description: string;
  arguments: PromptArgument[];
}

export interface PromptMessage {
  role: "user" | "assistant";
  content: { type: "text"; text: string };
}

export interface PromptResult {
  description: string;
  messages: PromptMessage[];
}

export class PromptError extends Error {}

const repoArg: PromptArgument = { name: "repo", description: "Absolute path to the repository root.", required: true };

export const PROMPTS: PromptDecl[] = [
  {
    name: "audit_repo",
    title: "Audit a repository, end to end",
    description:
      "The full audit workflow: scan for candidates, triage the noise out, judge what survives against the real code, adversarially verify it, and gate " +
      "every citation. Produces findings you can defend, not a scanner dump.",
    arguments: [repoArg, { name: "scope", description: "Restrict the audit to a subtree, for a large repo.", required: false }],
  },
  {
    name: "judge_finding",
    title: "Judge one candidate finding",
    description:
      "The adjudication workflow for a single candidate: read the real code along its taint path, decide whether the input is genuinely attacker-controlled " +
      "and genuinely reaches the sink, and record a verdict you could defend to the maintainer.",
    arguments: [repoArg, { name: "id", description: "The finding id, from ultrasec_paths.", required: true }],
  },
  {
    name: "write_narrative",
    title: "Write the audit report",
    description:
      "The reporting workflow: turn verified findings into a report that a maintainer can act on — what is exploitable, how, what it costs, and what to fix " +
      "first — with every claim citing a real line.",
    arguments: [repoArg],
  },
];

export function getPrompt(name: string, args: Record<string, unknown> = {}): PromptResult {
  const decl = PROMPTS.find((p) => p.name === name);
  if (!decl) throw new PromptError(`unknown prompt: ${name || "(none given)"}`);

  for (const arg of decl.arguments) {
    if (arg.required && !str(args[arg.name])) throw new PromptError(`\`${arg.name}\` is required for prompt "${name}"`);
  }

  const text = name === "audit_repo" ? auditRepo(args) : name === "judge_finding" ? judgeFinding(args) : writeNarrative(args);
  return { description: decl.description, messages: [{ role: "user", content: { type: "text", text } }] };
}

// The division of labour the whole skill rests on. Stated once, quoted into
// each prompt, so the two can never drift apart.
const CORE_RULE = `The engine finds CANDIDATES; you decide. A taint path is a hypothesis — that some input reaches some sink — not a vulnerability. Read the real code along it before calling anything a finding. Every claim cites a [file:line] that resolves.`;

const GATE = `\`ultrasec_check\` returning \`ok: false\` is a VERDICT, not a tool failure. A citation that does not resolve is an invented finding, and that is exactly what the gate exists to catch. Fix it or drop it, and check again.`;

const FP_RULE = `**A false positive is not a harmless mistake here.** A report a maintainer stops trusting is worse than no report: the real finding gets dismissed with the noise around it. When you cannot establish exploitability, say so and mark it needs-human — an honest "I could not determine this" is a usable result; a confident wrong one is not.`;

function auditRepo(args: Record<string, unknown>): string {
  const repo = str(args.repo)!;
  const scope = str(args.scope);

  return `Audit \`${repo}\` for real, exploitable security bugs${scope ? `, scoped to \`${scope}\`` : ""}.

${CORE_RULE}

**Sequence:**

1. \`ultrasec_map\`${scope ? ` with \`scope: ["${scope}"]\`` : ""} — cheap recon first. Where does untrusted input enter, and what dangerous sinks exist? On a large repo this is what tells you where a scan is worth spending time.
2. \`ultrasec_scan\`${scope ? ` with the same scope` : ""}. It defaults to \`budget: "quick"\` here because higher budgets run for minutes; raise it when the map says the surface is bigger than that.
3. \`ultrasec_paths\` — the candidate chains, in severity order. This is your work-queue.
4. \`ultrasec_triage\` — first pass: mark the obvious noise as noise before spending real effort. Most candidates are not bugs.
5. For each survivor: \`ultrasec_dossier\` on its id, read the real code, and judge it. \`ultrasec_graph\` when the path stops short and you need to see whether the data really arrives. \`ultrasec_read\` for the full context around a line.
6. \`ultrasec_investigate\` — the classes taint analysis CANNOT see: broken authorization and IDOR, business logic, auth and JWT handling, crypto misuse, races. The engine can only tell you where to look; the finding is yours.
7. \`ultrasec_verify\` — the adversarial pass. Try to REFUTE each surviving finding. What survives a genuine attempt to kill it is what you report.
8. \`ultrasec_check\`, then \`ultrasec_render\`.

${FP_RULE}

${GATE}`;
}

function judgeFinding(args: Record<string, unknown>): string {
  const repo = str(args.repo)!;
  const id = str(args.id)!;

  return `Judge candidate finding \`${id}\` in \`${repo}\`.

${CORE_RULE}

**Sequence:**

1. \`ultrasec_dossier\` on \`${id}\` — the code along the taint path, plus what the engine believes about it.
2. \`ultrasec_read\` the full function at each end of the path. An excerpt hides the guard clause that makes the whole thing safe.
3. \`ultrasec_graph\` on the source and the sink if the path has gaps — a chain the engine drew through a dynamic dispatch may not exist at runtime.
4. Decide, and say which of these it is.

**The three questions, in order.** Is the input genuinely attacker-controlled, or does it come from config, a constant, or another trusted service? Does it genuinely REACH the sink — same variable, no validation, no encoding, no parameterisation in between? And is the sink genuinely dangerous AS CALLED — a shell command with a fixed argv is not command injection.

**Any "no" makes it noise. All three "yes" makes it a finding**, and then say what an attacker actually does with it: the input they control, the value they send, and what they get. If you cannot write that sentence, you have not established exploitability yet.

${FP_RULE}

Record the verdict, then re-run \`ultrasec_check\`.`;
}

function writeNarrative(args: Record<string, unknown>): string {
  const repo = str(args.repo)!;

  return `Write the audit report for \`${repo}\`.

${CORE_RULE}

**Sequence:**

1. \`ultrasec_paths\` and \`ultrasec_check\` — take stock of what survived verification, and confirm every citation still resolves before writing a word.
2. \`ultrasec_dossier\` on each finding you intend to report, to get its citations exactly right.
3. Write the narrative: per finding, what an attacker does, what they get, and the specific fix. Ordered by real risk, not by the scanner's severity label.
4. \`ultrasec_render\` to produce SUMMARY.md, REPORT.md and the self-contained HTML.

**Write for the maintainer who has to act.** A finding without a concrete attack is a lint warning; a fix without a file and line is homework. Severity is about what the attacker gains and how reachable it is — an unauthenticated RCE on a public endpoint and the same class of bug behind an admin login are not the same finding.

**Report what you could NOT determine, in its own section.** Coverage the scan did not reach, findings you left needs-human, classes you did not look for. A report that is silent about its own limits reads as a clean bill of health for everything it never examined.

${GATE}`;
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() !== "" ? v : undefined;
}

// Every tool a prompt tells the model to call must actually be declared —
// otherwise a prompt survives a tool rename as a set of instructions that
// cannot be followed. Exported so the test can assert it.
const DECLARED = new Set([...TOOLS, ...WRITE_TOOLS].map((t) => t.name));

export function toolNamesReferencedBy(text: string): string[] {
  const found = new Set<string>();
  for (const m of text.matchAll(/ultrasec_[a-z_]+/g)) if (DECLARED.has(m[0])) found.add(m[0]);
  return [...found].sort();
}

export function unknownToolNamesIn(text: string): string[] {
  const bad = new Set<string>();
  for (const m of text.matchAll(/ultrasec_[a-z_]+/g)) if (!DECLARED.has(m[0])) bad.add(m[0]);
  return [...bad].sort();
}

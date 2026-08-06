import { join } from "node:path";
import { readText, walk } from "./walk.js";
import type { Finding } from "./types.js";
import { makeToolFinding } from "./tools/normalize.js";

// Auditing the CI workflows that hand a coding agent the keys.
//
// A workflow that invokes Claude Code Action / Gemini CLI / Codex / GitHub AI
// Inference turns the repository's own event data into a prompt. `github.event.*`
// is attacker-typed on any public repo — an issue title, a PR body, a comment —
// and a model cannot separate instructions from data. So the workflow is a taint
// path like any other, except that the sink is a prompt and the blast radius is
// whatever the job's token can reach.
//
// This is a LINE-ORIENTED scan, not a YAML parse: no dependency may enter the
// bundle, and the shapes below are all recognizable per line. That is a real
// limit — a prompt assembled across an anchor or a multi-document file will be
// missed — and it is why every finding here is a candidate the auditor reads,
// exactly like a taint candidate.

/** Actions that put a model in the loop. Substring-matched against `uses:`. */
const AI_ACTIONS = [
  "anthropics/claude-code-action",
  "anthropics/claude-code-base-action",
  "google-github-actions/run-gemini-cli",
  "google-gemini/gemini-cli-action",
  "openai/codex-action",
  "actions/ai-inference",
  "github/ai-inference",
];

/** Fields whose value becomes model input. */
const PROMPT_KEY = /^\s*(?:-\s+)?(?:direct_)?(?:prompt|prompt_file|instructions|user_prompt|query|input|system_prompt|message)\s*:/i;

/** Attacker-typed context on any repo that accepts outside contributions. */
const UNTRUSTED_CTX =
  /\$\{\{\s*(?:github\.event\.[a-z_.]*(?:title|body|name|label|ref|login|message|comment)|github\.head_ref|github\.event\.issue|github\.event\.comment|github\.event\.pull_request|inputs\.)/i;

/** Sandbox opt-outs that hand the model the whole machine. */
const DANGEROUS_MODE =
  /danger-full-access|--yolo|--dangerously-skip-permissions|dangerously_skip|permission[_-]mode\s*:\s*['"]?(?:bypassPermissions|acceptEdits)|Bash\(\s*\*\s*\)|allowed_tools\s*:\s*['"]?\s*\*/i;

/** "Anyone may drive this action." */
const WILDCARD_ALLOWLIST = /(?:allowed_non_write_users|allow[_-]users|allowed_bots)\s*:\s*['"]?\*/i;

const WORKFLOW = /^\.github\/workflows\/[^/]+\.ya?ml$/;

export interface ActionsVector {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium";
  note: string;
}

/** The nine shapes, kept as data so the reference doc and the engine cannot drift. */
export const VECTORS: Record<string, ActionsVector> = {
  A: {
    id: "A",
    title: "Untrusted event data reaches the prompt through an `env:` block",
    severity: "critical",
    note: "The prompt field looks clean — no `${{ }}` in it at all — because the attacker-controlled value is bound to an environment variable first and interpolated by the shell. This is the shape surface review misses, and the reason it is worth auditing workflows mechanically.",
  },
  B: {
    id: "B",
    title: "Untrusted event data interpolated directly into the prompt",
    severity: "critical",
    note: "`${{ github.event.* }}` inside a prompt field. Whoever opens the issue or PR writes part of the model's instructions.",
  },
  C: {
    id: "C",
    title: "The prompt tells the agent to fetch the event data itself",
    severity: "high",
    note: "`gh issue view` / `gh api` inside a prompt reaches the same attacker-controlled text one indirection later, and no expression scanner will see it.",
  },
  D: {
    id: "D",
    title: "`pull_request_target` combined with a checkout of the PR head",
    severity: "critical",
    note: "`pull_request_target` runs with the base repo's secrets and write token; checking out the PR head then executes a fork's code with them. Long-standing, still common.",
  },
  G: {
    id: "G",
    title: "Model output is executed",
    severity: "critical",
    note: "`eval`/`exec`/backticks over an AI step's output. Prompt injection becomes code execution in the runner with whatever the job token holds.",
  },
  H: {
    id: "H",
    title: "Agent sandbox disabled",
    severity: "high",
    note: "`danger-full-access`, `--yolo`, `Bash(*)` or a wildcard tool allow-list removes the boundary that makes an injected instruction survivable.",
  },
  I: {
    id: "I",
    title: "Wildcard user allow-list",
    severity: "high",
    note: "Any account — including a first-time contributor — can trigger the agent.",
  },
};

interface Line {
  n: number;
  text: string;
}

function lines(content: string): Line[] {
  return content.split(/\r?\n/).map((text, i) => ({ n: i + 1, text }));
}

/** Env keys in this file bound to attacker-typed context: `NAME: ${{ github.event.… }}`. */
function taintedEnvKeys(ls: Line[]): Map<string, number> {
  const out = new Map<string, number>();
  for (const l of ls) {
    const m = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+)$/.exec(l.text);
    if (m && UNTRUSTED_CTX.test(m[2]!)) out.set(m[1]!, l.n);
  }
  return out;
}

/**
 * Step ids of AI actions, so vector G can tell whose output is being executed.
 *
 * Resolved per STEP rather than line by line: `id:` normally comes *after*
 * `uses:`, so a forward-only scan that remembers the last id seen finds nothing
 * on the ordering everybody actually writes — and, worse, can carry an id across
 * a step boundary and attribute it to the wrong action.
 */
function aiStepIds(ls: Line[]): Set<string> {
  const ids = new Set<string>();
  let start = -1;
  let dashIndent = -1;

  const flush = (end: number): void => {
    if (start < 0) return;
    const step = ls.slice(start, end);
    const usesAi = step.some((l) => /^\s*-?\s*uses\s*:/.test(l.text) && AI_ACTIONS.some((a) => l.text.includes(a)));
    if (!usesAi) return;
    for (const l of step) {
      const m = /^\s*(?:-\s+)?id\s*:\s*['"]?([\w-]+)/.exec(l.text);
      if (m) ids.add(m[1]!);
    }
  };

  for (let i = 0; i < ls.length; i++) {
    const m = /^(\s*)-\s/.exec(ls[i]!.text);
    if (!m) continue;
    const indent = m[1]!.length;
    // A dash at the same or shallower indentation ends the current step; a deeper
    // one is a nested list inside it.
    if (start >= 0 && indent <= dashIndent) {
      flush(i);
      start = -1;
    }
    if (start < 0) {
      start = i;
      dashIndent = indent;
    }
  }
  flush(ls.length);
  return ids;
}

/**
 * The prompt key's OWN value: the rest of its line, plus — when it opens a block
 * scalar (`|`, `>`) — the following lines indented deeper than the key.
 *
 * Bounding this matters more than it looks. A fixed lookahead window spills into
 * the next step, so one workflow with two prompts reports each finding twice and
 * attributes evidence to the wrong line.
 */
function promptValue(ls: Line[], start: number): string {
  const key = ls[start]!;
  const indent = key.text.length - key.text.trimStart().length;
  const parts = [key.text];
  if (/[|>][-+]?\s*$/.test(key.text)) {
    for (let i = start + 1; i < ls.length; i++) {
      const t = ls[i]!.text;
      if (t.trim() === "") {
        parts.push(t);
        continue;
      }
      if (t.length - t.trimStart().length <= indent) break;
      parts.push(t);
    }
  }
  return parts.join("\n");
}

function hit(rel: string, line: number, v: ActionsVector, evidence: string): Finding {
  return makeToolFinding({
    tool: "ultrasec",
    category: "config",
    ident: `agentic-ci:${v.id}:${rel}:${line}`,
    title: `Agentic CI — vector ${v.id}: ${v.title}`,
    severity: v.severity,
    message: `${v.note}\n\nEvidence: \`${evidence.trim().slice(0, 160)}\``,
    file: rel,
    line,
    cwe: "CWE-1427",
  });
}

/**
 * Audit every workflow that invokes a coding agent. Returns candidates: a
 * workflow on a repo that never accepts outside contributions is a different
 * risk from the same workflow on a public one, and only the auditor knows which
 * this is.
 */
export function auditAgenticWorkflows(repo: string): Finding[] {
  const findings: Finding[] = [];
  const files = walk(repo)
    .map((f) => f.rel)
    .filter((rel) => WORKFLOW.test(rel));

  for (const rel of files) {
    const content = readText(join(repo, rel));
    if (!content) continue;
    const usesAi = AI_ACTIONS.some((a) => content.includes(a));
    const ls = lines(content);

    // D and I are dangerous regardless of whether a model is in the loop.
    const prTarget = ls.find((l) => /^\s*(?:-\s+)?pull_request_target\s*:?/.test(l.text));
    if (prTarget) {
      const headCheckout = ls.find((l) => /^\s*ref\s*:.*(?:github\.event\.pull_request\.head|github\.head_ref)/.test(l.text));
      if (headCheckout) findings.push(hit(rel, headCheckout.n, VECTORS.D!, headCheckout.text));
    }
    for (const l of ls) if (WILDCARD_ALLOWLIST.test(l.text)) findings.push(hit(rel, l.n, VECTORS.I!, l.text));

    if (!usesAi) continue;

    const envKeys = taintedEnvKeys(ls);
    const aiIds = aiStepIds(ls);

    for (const l of ls) {
      if (DANGEROUS_MODE.test(l.text)) findings.push(hit(rel, l.n, VECTORS.H!, l.text));

      // Model output reaching a shell.
      if (/\b(?:eval|exec)\b|\$\(/.test(l.text)) {
        const m = /steps\.([\w-]+)\.outputs/.exec(l.text);
        if (m && aiIds.has(m[1]!)) findings.push(hit(rel, l.n, VECTORS.G!, l.text));
      }

      if (!PROMPT_KEY.test(l.text)) continue;
      const block = promptValue(ls, ls.indexOf(l));

      if (UNTRUSTED_CTX.test(block)) findings.push(hit(rel, l.n, VECTORS.B!, l.text));
      else if (/\bgh\s+(?:issue|pr|api)\b/.test(block)) findings.push(hit(rel, l.n, VECTORS.C!, l.text));
      else {
        // Vector A: no expression in the prompt at all — the value arrived via env.
        for (const [key, envLine] of envKeys) {
          if (new RegExp(`\\$\\{?${key}\\b|env\\.${key}\\b`).test(block)) {
            findings.push(hit(rel, l.n, VECTORS.A!, `${l.text}   (${key} bound at line ${envLine})`));
            break;
          }
        }
      }
    }
  }
  return findings;
}

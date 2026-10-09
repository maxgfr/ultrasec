import { join } from "node:path";
import type { BatchPlan, PhaseInfo } from "./orchestrate.js";
import { REVALIDATION_VERDICTS } from "./revalidate.js";
import { BROCARDS, CATEGORIES, SEVERITIES, VERDICTS } from "./types.js";
import { workPath } from "./runlayout.js";

// ---------------------------------------------------------------------------
// Templates for `ultrasec orchestrate` — the generator that turns the run's
// CURRENT worklists into a launchable multi-agent Workflow per phase, the
// dispatch contracts it references, and a sequential RUNBOOK fallback.
// Everything here is emitted by string concatenation with the run's constants
// injected as JSON literals, so the workflow runs as-is under the Workflow
// tool: `export const meta` stays a pure literal, and no emitted line ever
// calls Date.now()/Math.random()/new Date() (they throw in that harness).
// ---------------------------------------------------------------------------

/** Family-standard footer: subagents return fragments; the orchestrator is the sole writer. */
const ONE_WRITER_FOOTER = `
## Return, don't write

Return ONLY the structured output specified above. Do NOT write, edit, or delete any file; do NOT run any engine command that writes (\`scan\`, \`import\`, any stage's emit or \`--apply\` — \`verify\`, \`triage\`, \`revalidate\`, \`investigate\`, \`context\`, \`narrative\`, \`implement\`, \`render\`, \`clean\`, \`run\`, \`audit\`). The only engine commands you may run are the read-only ones: \`dossier\`, \`graph\`, \`paths\`, \`tools\`. The orchestrator is the sole writer — it merges your fragments into one apply file itself and runs the conservative \`--apply\` fold. Exception: if a justification is prose too large to return, write ONLY to \`<RUN>/.work/orchestration/out/<role>-<batch>.md\` (a file namespaced to you alone) and return its path.
`;

// Structured-output schemas the emitted workflows pass to agent(..., { schema }).
// They mirror the shapes the `--apply` parsers consume (`parseVerdicts`,
// `parseRevalidations`, `parseDiscoveries`), so a fragment that validates here is
// still re-checked (conservative status mapping, citation resolution) at fold time.
const VERDICT_SCHEMA = {
  type: "object",
  required: ["verdicts"],
  properties: {
    verdicts: {
      type: "array",
      items: {
        type: "object",
        required: ["id", "verdict", "note"],
        properties: {
          id: { type: "string" },
          verdict: { enum: [...VERDICTS] },
          note: { type: "string", description: "one line grounded in the source you read, citing [file:line]" },
          exploitPath: { type: "string", description: "REQUIRED for supported: who · what they send · what they get" },
          brocard: { enum: [...BROCARDS], description: "REQUIRED for refuted: the named ground of the dismissal (references/dismissal-brocards.md)" },
        },
      },
    },
  },
};

const REVALIDATE_SCHEMA = {
  type: "object",
  required: ["verdicts"],
  properties: {
    verdicts: {
      type: "array",
      items: {
        type: "object",
        required: ["id", "verdict", "note"],
        properties: {
          id: { type: "string" },
          verdict: { enum: [...REVALIDATION_VERDICTS] },
          fixedIn: { type: "string", description: "the fixing commit sha, when verdict is fixed (else inferred from the git facts)" },
          note: { type: "string", description: "one line grounded in the git facts / code you read" },
        },
      },
    },
  },
};

const INVESTIGATE_SCHEMA = {
  type: "object",
  required: ["discoveries"],
  properties: {
    discoveries: {
      type: "array",
      items: {
        type: "object",
        required: ["title", "category", "severity", "message", "file", "line"],
        properties: {
          title: { type: "string" },
          category: { enum: [...CATEGORIES] },
          severity: { enum: [...SEVERITIES] },
          cwe: { type: "string" },
          message: { type: "string", description: "the concrete attacker scenario: who · what they send · what they get" },
          file: { type: "string" },
          line: { type: "integer" },
          path: {
            type: "array",
            description: "optional cross-file hops, each resolvable",
            items: {
              type: "object",
              required: ["file", "line", "why"],
              properties: { file: { type: "string" }, line: { type: "integer" }, why: { type: "string" } },
            },
          },
          hunt: { type: "string", description: "the weakness-class hunt id this discovery answers, when it came from one" },
        },
      },
    },
    idioms: {
      type: "array",
      description: "weakness-class hunts only: each unsafe call and guard you recognized, as this repo writes it",
      items: {
        type: "object",
        required: ["class", "framework", "kind", "pattern", "file", "line"],
        properties: {
          hunt: { type: "string" },
          class: { type: "string" },
          framework: { type: "string" },
          kind: { enum: ["unsafe", "guard"] },
          pattern: { type: "string", description: "the idiom as it reads in the code" },
          regex: { type: "string", description: "optional proposed matcher (must compile)" },
          file: { type: "string" },
          line: { type: "integer" },
          note: { type: "string" },
        },
      },
    },
    hunted: { type: "array", items: { type: "string" }, description: "weakness-class hunt ids you worked, including those with no finding" },
  },
};

interface PhaseSpec {
  role: string;
  title: string;
  schema: unknown;
  description: (items: number) => string;
  /** The orchestrator's fold step, shown as a comment in the workflow tail + in the runbook. */
  applyHint: (engineAbs: string, worklist: string, runAbs: string) => string;
  /** What the orchestrator merges the returned fragments into before folding. */
  fragmentFile: (runAbs: string) => string;
}

// Each phase's merged fragment lives in its OWN out/<phase>/ dir: `verify --apply`
// serves two phases (adjudicate + verify), so a shared flat out/ would let a
// directory apply pick up the OTHER phase's fragments (readdir + a loose regex).
const PHASE_SPECS: Record<string, PhaseSpec> = {
  adjudicate: {
    role: "analyzer",
    title: "Adjudicate",
    schema: VERDICT_SCHEMA,
    description: (n) => `Adjudicate the ${n} open candidate(s) of an ultrasec audit from dossier evidence (analyzer fan-out, conservative fold)`,
    applyHint: (engine, _worklist, run) => `node ${engine} verify --apply ${workPath(run, "orchestration", "out", "adjudicate", "verdicts.json")} --run ${run}`,
    fragmentFile: (run) => workPath(run, "orchestration", "out", "adjudicate", "verdicts.json"),
  },
  verify: {
    role: "skeptic",
    title: "Verify",
    schema: VERDICT_SCHEMA,
    description: (n) => `Adversarially verify the ${n} pending finding(s) of an ultrasec audit (skeptic fan-out, conservative fold)`,
    applyHint: (engine, _worklist, run) => `node ${engine} verify --apply ${workPath(run, "orchestration", "out", "verify", "verdicts.json")} --run ${run}`,
    fragmentFile: (run) => workPath(run, "orchestration", "out", "verify", "verdicts.json"),
  },
  revalidate: {
    role: "revalidator",
    title: "Revalidate",
    schema: REVALIDATE_SCHEMA,
    description: (n) => `Revalidate the ${n} confirmed/needs-human finding(s) against git history (false-positive cut, conservative fold)`,
    applyHint: (engine, _worklist, run) =>
      `node ${engine} revalidate --apply ${workPath(run, "orchestration", "out", "revalidate", "REVALIDATE.json")} --run ${run}`,
    fragmentFile: (run) => workPath(run, "orchestration", "out", "revalidate", "REVALIDATE.json"),
  },
  investigate: {
    role: "hunter",
    title: "Investigate",
    schema: INVESTIGATE_SCHEMA,
    description: (n) => `Hunt authz/IDOR, business-logic and multi-hop bugs across ${n} attack-surface region(s) (hunter fan-out, citation-checked ingest)`,
    applyHint: (engine, _worklist, run) =>
      `node ${engine} investigate --apply ${workPath(run, "orchestration", "out", "investigate", "INVESTIGATE.json")} --run ${run}`,
    fragmentFile: (run) => workPath(run, "orchestration", "out", "investigate", "INVESTIGATE.json"),
  },
};

export function phaseSpec(name: string): PhaseSpec {
  const spec = PHASE_SPECS[name];
  if (!spec) throw new Error(`no phase spec for "${name}"`);
  return spec;
}

/** Chunk worklist ids into batches, one subagent per batch (order-preserving,
 *  deterministic). The fallback when no family plan is given. */
export function toBatches(ids: string[], batchSize: number): string[][] {
  const out: string[][] = [];
  for (let i = 0; i < ids.length; i += batchSize) out.push(ids.slice(i, i + batchSize));
  return out;
}

/** Comment-safe interpolation: a path containing a newline would otherwise spill
 *  the rest of an emitted `//` comment onto a bare code line and break the script. */
function oneLine(s: string): string {
  return s.replace(/[\r\n\u2028\u2029]+/g, " ");
}

/**
 * The items one agent is handed, as text: compact JSON lines, grouped by
 * family for the finding phases. This replaces `ITEMS=<ids>` plus a worklist
 * every agent had to open and search — the lines ARE the worklist rows.
 */
export function batchText(phase: string, families: readonly string[][], lines: Readonly<Record<string, string>>, header?: string): string {
  const n = families.reduce((k, g) => k + g.length, 0);
  const line = (id: string) => lines[id] ?? JSON.stringify({ id });
  if (phase === "investigate")
    return [
      ...(header ? [`Hunt prompt — every region below unless it carries its own \`prompt\`: ${header}`] : []),
      `Your ${n} region(s), one compact JSON line each:`,
      ...families.flat().map(line),
    ].join("\n");
  const L = [
    `Your ${n} item(s), one compact JSON line each, in ${families.length} famil${families.length === 1 ? "y" : "ies"}. A family is ONE judgment: read its first member in depth, the others for their location only (\`dossier <id>,<id>,… --brief --no-context\` prints exactly that). Still ONE verdict row per id.`,
  ];
  families.forEach((g, i) => {
    L.push(`# family ${i + 1} (${g.length})`);
    for (const id of g) L.push(line(id));
  });
  return L.join("\n");
}

export interface WorkflowExtras {
  /** The family plan (else ids are chunked by `batchSize`, one line each). */
  plan?: BatchPlan;
  /** CONTEXT.md, compacted — printed once per agent prompt. */
  context?: string;
}

export function phaseWorkflowScript(ph: PhaseInfo, runAbs: string, engineAbs: string, batchSize: number, extras: WorkflowExtras = {}): string {
  const spec = phaseSpec(ph.name);
  const scriptPath = workPath(runAbs, "orchestration", `${ph.name}.workflow.mjs`);
  const meta = { name: `ultrasec-${ph.name}`, description: spec.description(ph.items), phases: [{ title: spec.title }] };
  const fragmentKey = ph.name === "investigate" ? "discoveries" : "verdicts";
  const plan = extras.plan ?? { batches: toBatches(ph.ids, batchSize).map((b) => b.map((id) => [id])), lines: {} };
  const batches = plan.batches.map((fams) => fams.flat());
  const texts = plan.batches.map((fams) => batchText(ph.name, fams, plan.lines, plan.header));
  return [
    `export const meta = ${JSON.stringify(meta)}`,
    ``,
    `// NOT a plain Node script: launch via the Workflow tool — Workflow({ scriptPath: ${JSON.stringify(scriptPath)} }).`,
    `// Emitted by \`ultrasec orchestrate\` from the CURRENT worklist. The worklist is the source`,
    `// of truth: if it changes, re-run \`orchestrate --phase ${ph.name}\` before launching.`,
    ``,
    `// Constants for THIS run (injected at emit time; no Date.now/Math.random in this harness).`,
    `const RUN = ${JSON.stringify(runAbs)}`,
    `const ENGINE = ${JSON.stringify(engineAbs)}`,
    `// The worklist the items came from — for the orchestrator's merge, never handed to an agent.`,
    `const WORKLIST = ${JSON.stringify(ph.worklist)}`,
    `const AGENTS = RUN + '/.work/orchestration/agents'`,
    `// The ids each agent rules on (families kept whole, the agent count capped), and the`,
    `// items themselves as compact JSON lines — the agent opens no worklist.`,
    `const BATCHES = ${JSON.stringify(batches)}`,
    `const ITEMS = ${JSON.stringify(texts)}`,
    `const CONTEXT = ${JSON.stringify(extras.context ?? "")}`,
    `const SCHEMA = ${JSON.stringify(spec.schema)}`,
    ``,
    `function contract(name, extra) {`,
    `  return 'Read and follow the dispatch contract at ' + AGENTS + '/' + name + '.md VERBATIM.\\n'`,
    `    + 'Constants: RUN=' + RUN + '  ENGINE=' + ENGINE + '.\\n'`,
    `    + 'Invoke the engine only by its ABSOLUTE path: node ' + ENGINE + ' <cmd> — read-only commands only; dossier always with --brief --no-context.'`,
    `    + (CONTEXT ? '\\nProject context (CONTEXT.md, compacted — background for judging reachability, never a verdict):\\n' + CONTEXT : '')`,
    `    + (extra ? '\\n' + extra : '')`,
    `}`,
    ``,
    `log('ultrasec ${ph.name}: ' + ${JSON.stringify(String(ph.items))} + ' item(s) across ' + BATCHES.length + ' agent(s)')`,
    ``,
    `phase(${JSON.stringify(spec.title)})`,
    `const results = await pipeline(BATCHES, (batch, _item, i) =>`,
    `  agent(contract('${spec.role}', ITEMS[i]), { label: '${ph.name}:' + (i + 1), phase: ${JSON.stringify(spec.title)}, agentType: 'general-purpose', schema: SCHEMA }))`,
    ``,
    `// One-writer rule: this workflow only COLLECTS ${fragmentKey} fragments. The main agent merges`,
    `// the returned \`${fragmentKey}\` arrays into ${oneLine(spec.fragmentFile(runAbs))}${ph.name === "investigate" ? " (and the `idioms`/`hunted` arrays of weakness-class hunts under the same keys)" : ""}, then runs the conservative fold:`,
    `//   ${oneLine(spec.applyHint(engineAbs, ph.worklist, runAbs))}`,
    `return { phase: ${JSON.stringify(ph.name)}, worklist: WORKLIST, results: results.filter(Boolean) }`,
    ``,
  ].join("\n");
}

export function agentContracts(runAbs: string, engineAbs: string, repoAbs: string): Record<string, string> {
  const footer = ONE_WRITER_FOOTER.replaceAll("<RUN>", runAbs);
  return {
    analyzer: `# Contract: analyzer

You are auditing ONE batch of candidates of an ultrasec security review — the OPEN candidates the deterministic engine enumerated. They are recall-oriented: many are false positives by design; you decide, from the real code.

Your items are in your prompt: one compact JSON line per candidate (\`id\`, \`severity\`, \`title\`, \`cwe\`, \`category\`, \`claim\`, \`files[]\`, and \`proposed\` / \`reachability\` when the engine has them), grouped by family. Repo root: \`${repoAbs}\`. If an id is no longer in the worklist — \`dossier\` cannot find it — skip it and say so in your note.

For EACH family:

1. Run \`node ${engineAbs} dossier <id>,<id>,… --run ${runAbs} --brief --no-context\` (read-only) — ONE call per family: the first member's grounding packet in full, then one line and a ±3-line window per other member. The project context is already in your prompt; do not reprint it.
2. Read the code along EVERY hop of the first member's path (open a cited file only when the packet cannot decide). Decide: is the SOURCE attacker-controlled? does the value reach the SINK through every hop unchanged? is there a sanitizer/validator/authz guard on the path? is the SINK exploitable with the value that arrives (write the PoC)? For each other member, check only that its window has the same shape; a member that differs gets its own reading.
3. Rule EVERY id:
   - \`supported\` — the flow is real and exploitable. REQUIRES \`exploitPath\` (who · what they send · what they get).
   - \`partial\` — a real issue, but weaker or narrower than claimed.
   - \`unsupported\` — the evidence does not establish the claim.
   - \`refuted\` — the source positively contradicts the claim (name the guard/sanitizer \`[file:line]\`, and the ground in \`brocard\` — exactly one of ${BROCARDS.map((b) => `\`${b}\``).join(" · ")}; the reasoning goes in \`note\`).
   Default to the harsher verdict ONLY when you can disprove it; otherwise mark \`partial\`/leave it for a human.
4. Be conservative. The fold never auto-dismisses a high/critical finding on anything short of an explicit \`refuted\` — an uncertain high-severity finding stays **needs-human**, never dropped. Every claim in your \`note\` must cite resolvable \`[file:line]\` hops you actually read.

Return (structured output): \`{ "verdicts": [{ "id", "verdict", "note", "exploitPath", "brocard" }] }\` — one row per id in your prompt, family members included.
${footer}`,
    skeptic: `# Contract: skeptic

You are an adversarial skeptic verifying the pending findings of an ultrasec audit. Assume each claim is wrong until the source proves it — try to REFUTE it.

Your items are in your prompt: one compact JSON line per finding (\`id\`, \`severity\`, \`cwe\`, \`title\`, \`category\`, \`claim\`, \`files[]\`), grouped by family. Repo root: \`${repoAbs}\`. If an id is no longer in the worklist — \`dossier\` cannot find it — skip it and say so in your note.

For EACH family:

1. Run \`node ${engineAbs} dossier <id>,<id>,… --run ${runAbs} --brief --no-context\` (read-only) — the first member's cross-file packet in full, a ±3-line window per other member. Open a cited \`file:line\` only when the packet cannot decide.
2. Judge the first member's claim against the source — is the flow **real and exploitable**? Then check each other member's window has the same shape (a member that differs gets its own reading):
   - \`supported\` — real and exploitable exactly as claimed (include \`exploitPath\`).
   - \`partial\` — a real issue, but the claim overstates it (wrong hop, narrower reach, weaker impact).
   - \`unsupported\` — the source does not establish the claim.
   - \`refuted\` — the source contradicts the claim (name the guard/sanitizer \`[file:line]\`, and the ground in \`brocard\` — exactly one of ${BROCARDS.map((b) => `\`${b}\``).join(" · ")}; the reasoning goes in \`note\`).
3. Be skeptical, but do NOT dismiss a high/critical finding unless you can positively **refute** it — the fold sends an \`unsupported\`/\`partial\` high-severity finding to **needs-human**, never auto-dropped. Uncertain ⇒ leave it for a human.
4. \`note\` is REQUIRED — one line grounded in what you read, citing resolvable \`[file:line]\`. If the entry carries a \`priorSignal\`, it is a HINT, never a verdict — adjudicate yourself.

Return (structured output): \`{ "verdicts": [{ "id", "verdict", "note", "exploitPath", "brocard" }] }\` — one row per id in your prompt.
${footer}`,
    revalidator: `# Contract: revalidator

You revalidate findings already ranked real (confirmed / needs-human) against git history — the false-positive cut.

Your items are in your prompt: one compact JSON line per finding (\`id\`, \`severity\`, \`title\`, \`at\`, plus git facts: \`fileExists\`, \`currentLine\`, \`commitsSinceFinding\`, \`lineLastChanged\`, \`renamedTo\`), grouped by family. Repo root: \`${repoAbs}\`. If an id is no longer in the worklist, skip it and say so in your note.

For EACH of your entries:

1. Read the git facts; open the cited file at HEAD (\`at\`, or \`renamedTo\` when the file moved) only when they cannot settle whether the vulnerable code is still there.
2. Decide whether the issue is still live:
   - \`still-valid\` — the cited code is still vulnerable at HEAD.
   - \`fixed\` — the code was corrected; include \`fixedIn\` (the fixing commit sha — else the fold infers it from \`lineLastChanged\`).
   - \`false-positive\` — the finding was never a real issue (say why, grounded).
   - \`uncertain\` — the facts cannot settle it. A valid, honest verdict.
3. The fold is conservative: \`fixed\` → dismissed recording the fixing commit; a high/critical \`false-positive\` → **needs-human** (never auto-dismissed); \`uncertain\`/unknown → needs-human; \`still-valid\` keeps the finding (flagged if the cited location drifted at HEAD).
4. \`note\` is REQUIRED — one line grounded in the git facts / code you read, citing resolvable \`[file:line]\`.

Return (structured output): \`{ "verdicts": [{ "id", "verdict", "fixedIn", "note" }] }\` — one row per id in your prompt.
${footer}`,
    hunter: `# Contract: hunter

You hunt the bugs the deterministic engine can't enumerate — missing/incorrect **authz** & **IDOR**, **business-logic** flaws, and multi-hop taint — one attack-surface region at a time.

Your regions are in your prompt: one compact JSON line each (\`region\`, \`files[]\`, \`neighbors[]\`, and \`prompt\` when it differs from the shared hunt prompt printed above them; paths are relative to the repo root \`${repoAbs}\`). If a region is no longer in the worklist, skip it and say so in your note.

For EACH of your regions:

1. Read the region's \`files[]\` and \`neighbors[]\` (read-only; \`node ${engineAbs} graph <file> --repo ${repoAbs}\` shows the cross-file links). Follow the region's \`prompt\`.
2. Hunt what the deterministic pass can't see: missing/incorrect authorization & IDOR, business-logic flaws, feature abuse, and multi-hop taint that crosses these files.
3. Only report what you can exploit — a concrete attacker scenario (who · what they send · what they get), not "potentially". A defense-in-depth gap another layer already prevents is a hardening note, not a Discovery.
4. Every citation must resolve: the ingest REJECTS a Discovery whose \`[file:line]\` doesn't exist, and a Discovery at an existing finding's location folds into its \`sources\` (no duplicate). Discoveries land as \`ultrasec-ai\` **open** candidates and are adjudicated like any other — an uncertain high-severity one stays needs-human downstream, never dropped — so ground every claim, then don't fear reporting it.

5. An item whose \`region\` starts with \`hunt:\` is a **weakness-class hunt**, not a region: its \`hunt\` object carries the class invariant, a valid guard, examples, and the framework/version no pack covers. Find how THIS repo writes the class: every break is a Discovery with \`"hunt": "<id>"\`; every unsafe call and guard you recognize goes to \`idioms[]\` (\`{hunt, class, framework, kind: unsafe|guard, pattern, regex?, file, line, note}\`, citation-checked); list the hunt id in \`hunted[]\` even when you found nothing.

Return (structured output): \`{ "discoveries": [{ "title", "category", "severity", "cwe", "message", "file", "line", "path", "hunt"? }], "idioms": [...], "hunted": [...] }\` — your regions only.

> **Merge before you fold (orchestrator).** Regions overlap, so two hunters routinely report ONE bug from two angles — the same missing check cited at the guard and at the call it fails to protect. The mechanical dedup on ingest only collapses an EXACT \`category + cwe/title + file:line\` match, so a same-bug-different-line pair survives as two findings and the report reads as twice the problem. Merge near-duplicates into one Discovery (keep the most precise citation, put the others in \`path\`) BEFORE running \`--apply\`, and do it before any false-positive pass: a de-duplication that runs after adjudication has already inflated the count it was meant to fix.
${footer}`,
  };
}

export function runbookMd(phases: PhaseInfo[], runAbs: string, engineAbs: string, repoAbs: string): string {
  const status = phases
    .map((p) => `| ${p.name} | \`${p.worklist}\` | ${p.ready ? `ready (${p.items} item(s))` : "not ready"} | \`${p.prerequisite}\` |`)
    .join("\n");
  const engine = `node ${engineAbs}`;
  const agents = (role: string) => workPath(runAbs, "orchestration", "agents", `${role}.md`);
  const frag = (name: string) => phaseSpec(name).fragmentFile(runAbs);
  return `# ultrasec — sequential RUNBOOK (eco / no-subagent fallback)

Run: \`${runAbs}\` · Repo: \`${repoAbs}\` · Engine: \`${engine}\`

Generated by \`ultrasec orchestrate\` from the CURRENT run state. This sequential path is
correctness-identical to the multi-agent workflows — same worklists, same contracts, same
conservative folds; only wall-clock differs. Fan-out is an optimization, not a requirement.

## Phase status

| Phase | Worklist | Status | Produce it with |
|---|---|---|---|
${status}

## The loop (play every role yourself, one item at a time)

1. **Scan** (if not done): \`${engine} scan --repo ${repoAbs} --out ${runAbs}\` → \`${join(runAbs, "findings.json")}\` (+ optionally prime \`${engine} context\`).
2. **Investigate the attack surface** (discovery) — \`${engine} investigate --run ${runAbs}\` writes \`${join(runAbs, "INVESTIGATE.todo.json")}\`. For EVERY region, apply \`${agents("hunter")}\` yourself; merge the grounded Discovery[] into \`${frag("investigate")}\`. Then ingest (citation-checked): \`${phaseSpec("investigate").applyHint(engineAbs, "", runAbs)}\`.
3. **Adjudicate the open candidates** — the worklist is \`${join(runAbs, "findings.json")}\` itself (every \`status: "open"\` candidate). For EVERY open id, apply \`${agents("analyzer")}\` yourself, one family at a time — same category, CWE, sink and title under the same path root (\`${engine} dossier <id>,<id>,… --run ${runAbs} --brief --no-context\`, read every hop of the first member, the others for their location; one verdict per id, supported/partial/unsupported/refuted + note, exploitPath when supported, brocard when refuted); merge the verdicts into \`${frag("adjudicate")}\`. Then fold, conservatively: \`${phaseSpec("adjudicate").applyHint(engineAbs, "", runAbs)}\`.
4. **Verify adversarially** — \`${engine} verify --run ${runAbs}\` writes \`${join(runAbs, "VERIFY.todo.json")}\` (the still-pending findings). For EVERY entry, apply \`${agents("skeptic")}\` yourself (try to REFUTE; uncertain high-severity stays needs-human); merge into \`${frag("verify")}\`. Then: \`${phaseSpec("verify").applyHint(engineAbs, "", runAbs)}\`.
5. **Revalidate against git history** — \`${engine} revalidate --run ${runAbs}\` writes \`${join(runAbs, "REVALIDATE.todo.json")}\`. For EVERY entry, apply \`${agents("revalidator")}\` yourself (still-valid/fixed/false-positive/uncertain + note, fixedIn when fixed); merge into \`${frag("revalidate")}\`. Then: \`${phaseSpec("revalidate").applyHint(engineAbs, "", runAbs)}\`.
6. **Gate**: \`${engine} check --run ${runAbs} --semantic\` must exit 0 before presenting anything.
7. **Render**: \`${engine} render --run ${runAbs}\` (optionally author the narrative first: \`${engine} narrative --run ${runAbs}\`). Loop from step 2 on a new sub-question until a round surfaces nothing new.

With subagents available, prefer the emitted workflows instead: \`orchestrate --run ${runAbs} --phase <p>\` then \`Workflow({ scriptPath: "${workPath(runAbs, "orchestration", "<p>.workflow.mjs")}" })\` — you stay the sole writer either way.
`;
}

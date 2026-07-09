import { join } from "node:path";
import type { PhaseInfo } from "./orchestrate.js";
import { REVALIDATION_VERDICTS } from "./revalidate.js";
import { CATEGORIES, SEVERITIES, VERDICTS } from "./types.js";

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

Return ONLY the structured output specified above. Do NOT write, edit, or delete any file; do NOT run any engine command that writes (\`scan\`, \`import\`, any stage's emit or \`--apply\` — \`verify\`, \`triage\`, \`revalidate\`, \`investigate\`, \`context\`, \`narrative\`, \`implement\`, \`render\`, \`clean\`, \`run\`). The only engine commands you may run are the read-only ones: \`dossier\`, \`graph\`, \`paths\`, \`tools\`. The orchestrator is the sole writer — it merges your fragments into one apply file itself and runs the conservative \`--apply\` fold. Exception: if a justification is prose too large to return, write ONLY to \`<RUN>/orchestration/out/<role>-<batch>.md\` (a file namespaced to you alone) and return its path.
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
        },
      },
    },
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
    applyHint: (engine, _worklist, run) => `node ${engine} verify --apply ${join(run, "orchestration", "out", "adjudicate", "verdicts.json")} --run ${run}`,
    fragmentFile: (run) => join(run, "orchestration", "out", "adjudicate", "verdicts.json"),
  },
  verify: {
    role: "skeptic",
    title: "Verify",
    schema: VERDICT_SCHEMA,
    description: (n) => `Adversarially verify the ${n} pending finding(s) of an ultrasec audit (skeptic fan-out, conservative fold)`,
    applyHint: (engine, _worklist, run) => `node ${engine} verify --apply ${join(run, "orchestration", "out", "verify", "verdicts.json")} --run ${run}`,
    fragmentFile: (run) => join(run, "orchestration", "out", "verify", "verdicts.json"),
  },
  revalidate: {
    role: "revalidator",
    title: "Revalidate",
    schema: REVALIDATE_SCHEMA,
    description: (n) => `Revalidate the ${n} confirmed/needs-human finding(s) against git history (false-positive cut, conservative fold)`,
    applyHint: (engine, _worklist, run) =>
      `node ${engine} revalidate --apply ${join(run, "orchestration", "out", "revalidate", "REVALIDATE.json")} --run ${run}`,
    fragmentFile: (run) => join(run, "orchestration", "out", "revalidate", "REVALIDATE.json"),
  },
  investigate: {
    role: "hunter",
    title: "Investigate",
    schema: INVESTIGATE_SCHEMA,
    description: (n) => `Hunt authz/IDOR, business-logic and multi-hop bugs across ${n} attack-surface region(s) (hunter fan-out, citation-checked ingest)`,
    applyHint: (engine, _worklist, run) =>
      `node ${engine} investigate --apply ${join(run, "orchestration", "out", "investigate", "INVESTIGATE.json")} --run ${run}`,
    fragmentFile: (run) => join(run, "orchestration", "out", "investigate", "INVESTIGATE.json"),
  },
};

export function phaseSpec(name: string): PhaseSpec {
  const spec = PHASE_SPECS[name];
  if (!spec) throw new Error(`no phase spec for "${name}"`);
  return spec;
}

/** Chunk worklist ids into batches, one subagent per batch (order-preserving, deterministic). */
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

export function phaseWorkflowScript(ph: PhaseInfo, runAbs: string, engineAbs: string, batchSize: number): string {
  const spec = phaseSpec(ph.name);
  const scriptPath = join(runAbs, "orchestration", `${ph.name}.workflow.mjs`);
  const meta = { name: `ultrasec-${ph.name}`, description: spec.description(ph.items), phases: [{ title: spec.title }] };
  const fragmentKey = ph.name === "investigate" ? "discoveries" : "verdicts";
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
    `const WORKLIST = ${JSON.stringify(ph.worklist)}`,
    `const AGENTS = RUN + '/orchestration/agents'`,
    `const BATCHES = ${JSON.stringify(toBatches(ph.ids, batchSize))}`,
    `const SCHEMA = ${JSON.stringify(spec.schema)}`,
    ``,
    `function contract(name, extra) {`,
    `  return 'Read and follow the dispatch contract at ' + AGENTS + '/' + name + '.md VERBATIM.\\n'`,
    `    + 'Constants: RUN=' + RUN + '  ENGINE=' + ENGINE + '  WORKLIST=' + WORKLIST + '.\\n'`,
    `    + 'Invoke the engine only by its ABSOLUTE path: node ' + ENGINE + ' <cmd> — read-only commands only.'`,
    `    + (extra ? '\\n' + extra : '')`,
    `}`,
    ``,
    `log('ultrasec ${ph.name}: ' + ${JSON.stringify(String(ph.items))} + ' item(s) across ' + BATCHES.length + ' agent(s)')`,
    ``,
    `phase(${JSON.stringify(spec.title)})`,
    `const results = await pipeline(BATCHES, (batch, _item, i) =>`,
    `  agent(contract('${spec.role}', 'ITEMS=' + batch.join(',')), { label: '${ph.name}:' + (i + 1), phase: ${JSON.stringify(spec.title)}, agentType: 'general-purpose', schema: SCHEMA }))`,
    ``,
    `// One-writer rule: this workflow only COLLECTS ${fragmentKey} fragments. The main agent merges`,
    `// the returned \`${fragmentKey}\` arrays into ${oneLine(spec.fragmentFile(runAbs))}, then runs the conservative fold:`,
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

Worklist: \`${join(runAbs, "findings.json")}\` (the audit dossier's candidate list; repo root: \`${repoAbs}\`). Handle ONLY the findings whose \`id\` is named in your prompt (\`ITEMS=<id,…>\`). If an \`ITEMS\` id is no longer in the worklist, skip it and say so in your note.

For EACH of your candidate ids:

1. Run \`node ${engineAbs} dossier <id> --run ${runAbs}\` (read-only) — the grounding packet: the real code along the cross-file path, graph neighbours, and how to verify.
2. Read the code along EVERY hop of the printed path (open the cited files when the excerpts alone cannot decide). Decide: is the SOURCE attacker-controlled? does the value reach the SINK through every hop unchanged? is there a sanitizer/validator/authz guard on the path? is the SINK exploitable with the value that arrives (write the PoC)?
3. Rule it:
   - \`supported\` — the flow is real and exploitable. REQUIRES \`exploitPath\` (who · what they send · what they get).
   - \`partial\` — a real issue, but weaker or narrower than claimed.
   - \`unsupported\` — the evidence does not establish the claim.
   - \`refuted\` — the source positively contradicts the claim (name the guard/sanitizer \`[file:line]\`).
   Default to the harsher verdict ONLY when you can disprove it; otherwise mark \`partial\`/leave it for a human.
4. Be conservative. The fold never auto-dismisses a high/critical finding on anything short of an explicit \`refuted\` — an uncertain high-severity finding stays **needs-human**, never dropped. Every claim in your \`note\` must cite resolvable \`[file:line]\` hops you actually read.

Return (structured output): \`{ "verdicts": [{ "id", "verdict", "note", "exploitPath" }] }\` — your ITEMS only.
${footer}`,
    skeptic: `# Contract: skeptic

You are an adversarial skeptic verifying the pending findings of an ultrasec audit. Assume each claim is wrong until the source proves it — try to REFUTE it.

Worklist: \`${join(runAbs, "VERIFY.todo.json")}\` (a JSON array; each entry has \`id\`, \`severity\`, \`cwe\`, \`title\`, \`category\`, \`claim\`, \`files[]\`; repo root: \`${repoAbs}\`). Handle ONLY the entries whose \`id\` is named in your prompt (\`ITEMS=<id,…>\`). If an \`ITEMS\` id is no longer in the worklist, skip it and say so in your note.

For EACH of your entries:

1. Open every cited \`file:line\` in \`files[]\` and read it in context; run \`node ${engineAbs} dossier <id> --run ${runAbs}\` (read-only) for the full cross-file packet.
2. Judge the claim against the source — is the flow **real and exploitable**?
   - \`supported\` — real and exploitable exactly as claimed (include \`exploitPath\`).
   - \`partial\` — a real issue, but the claim overstates it (wrong hop, narrower reach, weaker impact).
   - \`unsupported\` — the source does not establish the claim.
   - \`refuted\` — the source contradicts the claim (name the guard/sanitizer \`[file:line]\`).
3. Be skeptical, but do NOT dismiss a high/critical finding unless you can positively **refute** it — the fold sends an \`unsupported\`/\`partial\` high-severity finding to **needs-human**, never auto-dropped. Uncertain ⇒ leave it for a human.
4. \`note\` is REQUIRED — one line grounded in what you read, citing resolvable \`[file:line]\`. If the entry carries a \`priorSignal\`, it is a HINT, never a verdict — adjudicate yourself.

Return (structured output): \`{ "verdicts": [{ "id", "verdict", "note", "exploitPath" }] }\` — your ITEMS only.
${footer}`,
    revalidator: `# Contract: revalidator

You revalidate findings already ranked real (confirmed / needs-human) against git history — the false-positive cut.

Worklist: \`${join(runAbs, "REVALIDATE.todo.json")}\` (a JSON array; each entry has \`id\`, \`severity\`, \`title\`, \`at\`, plus compact git facts: \`fileExists\`, \`currentLine\`, \`commitsSinceFinding\`, \`lineLastChanged\`, \`renamedTo\`; repo root: \`${repoAbs}\`). Handle ONLY the entries whose \`id\` is named in your prompt (\`ITEMS=<id,…>\`). If an \`ITEMS\` id is no longer in the worklist, skip it and say so in your note.

For EACH of your entries:

1. Read the git facts, then open the cited file at HEAD (\`at\`, or \`renamedTo\` when the file moved) and check whether the vulnerable code is still there.
2. Decide whether the issue is still live:
   - \`still-valid\` — the cited code is still vulnerable at HEAD.
   - \`fixed\` — the code was corrected; include \`fixedIn\` (the fixing commit sha — else the fold infers it from \`lineLastChanged\`).
   - \`false-positive\` — the finding was never a real issue (say why, grounded).
   - \`uncertain\` — the facts cannot settle it. A valid, honest verdict.
3. The fold is conservative: \`fixed\` → dismissed recording the fixing commit; a high/critical \`false-positive\` → **needs-human** (never auto-dismissed); \`uncertain\`/unknown → needs-human; \`still-valid\` keeps the finding (flagged if the cited location drifted at HEAD).
4. \`note\` is REQUIRED — one line grounded in the git facts / code you read, citing resolvable \`[file:line]\`.

Return (structured output): \`{ "verdicts": [{ "id", "verdict", "fixedIn", "note" }] }\` — your ITEMS only.
${footer}`,
    hunter: `# Contract: hunter

You hunt the bugs the deterministic engine can't enumerate — missing/incorrect **authz** & **IDOR**, **business-logic** flaws, and multi-hop taint — one attack-surface region at a time.

Worklist: \`${join(runAbs, "INVESTIGATE.todo.json")}\` (a JSON array; each entry has \`region\`, \`files[]\`, \`neighbors[]\`, \`prompt\`; paths are relative to the repo root \`${repoAbs}\`). Handle ONLY the regions named in your prompt (\`ITEMS=<region,…>\`). If an \`ITEMS\` region is no longer in the worklist, skip it and say so in your note.

For EACH of your regions:

1. Read the region's \`files[]\` and \`neighbors[]\` (read-only; \`node ${engineAbs} graph <file> --repo ${repoAbs}\` shows the cross-file links). Follow the region's \`prompt\`.
2. Hunt what the deterministic pass can't see: missing/incorrect authorization & IDOR, business-logic flaws, feature abuse, and multi-hop taint that crosses these files.
3. Only report what you can exploit — a concrete attacker scenario (who · what they send · what they get), not "potentially". A defense-in-depth gap another layer already prevents is a hardening note, not a Discovery.
4. Every citation must resolve: the ingest REJECTS a Discovery whose \`[file:line]\` doesn't exist, and a Discovery at an existing finding's location folds into its \`sources\` (no duplicate). Discoveries land as \`ultrasec-ai\` **open** candidates and are adjudicated like any other — an uncertain high-severity one stays needs-human downstream, never dropped — so ground every claim, then don't fear reporting it.

Return (structured output): \`{ "discoveries": [{ "title", "category", "severity", "cwe", "message", "file", "line", "path" }] }\` — your ITEMS' regions only.
${footer}`,
  };
}

export function runbookMd(phases: PhaseInfo[], runAbs: string, engineAbs: string, repoAbs: string): string {
  const status = phases
    .map((p) => `| ${p.name} | \`${p.worklist}\` | ${p.ready ? `ready (${p.items} item(s))` : "not ready"} | \`${p.prerequisite}\` |`)
    .join("\n");
  const engine = `node ${engineAbs}`;
  const agents = (role: string) => join(runAbs, "orchestration", "agents", `${role}.md`);
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
3. **Adjudicate the open candidates** — the worklist is \`${join(runAbs, "findings.json")}\` itself (every \`status: "open"\` candidate). For EVERY open id, apply \`${agents("analyzer")}\` yourself (\`${engine} dossier <id> --run ${runAbs}\`, read every hop, verdict supported/partial/unsupported/refuted + note, exploitPath when supported); merge the verdicts into \`${frag("adjudicate")}\`. Then fold, conservatively: \`${phaseSpec("adjudicate").applyHint(engineAbs, "", runAbs)}\`.
4. **Verify adversarially** — \`${engine} verify --run ${runAbs}\` writes \`${join(runAbs, "VERIFY.todo.json")}\` (the still-pending findings). For EVERY entry, apply \`${agents("skeptic")}\` yourself (try to REFUTE; uncertain high-severity stays needs-human); merge into \`${frag("verify")}\`. Then: \`${phaseSpec("verify").applyHint(engineAbs, "", runAbs)}\`.
5. **Revalidate against git history** — \`${engine} revalidate --run ${runAbs}\` writes \`${join(runAbs, "REVALIDATE.todo.json")}\`. For EVERY entry, apply \`${agents("revalidator")}\` yourself (still-valid/fixed/false-positive/uncertain + note, fixedIn when fixed); merge into \`${frag("revalidate")}\`. Then: \`${phaseSpec("revalidate").applyHint(engineAbs, "", runAbs)}\`.
6. **Gate**: \`${engine} check --run ${runAbs} --semantic\` must exit 0 before presenting anything.
7. **Render**: \`${engine} render --run ${runAbs}\` (optionally author the narrative first: \`${engine} narrative --run ${runAbs}\`). Loop from step 2 on a new sub-question until a round surfaces nothing new.

With subagents available, prefer the emitted workflows instead: \`orchestrate --run ${runAbs} --phase <p>\` then \`Workflow({ scriptPath: "${join(runAbs, "orchestration", "<p>.workflow.mjs")}" })\` — you stay the sole writer either way.
`;
}

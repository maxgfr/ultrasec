# Agents in CI — the nine injection vectors

A workflow that invokes a coding agent (Claude Code Action, Gemini CLI, Codex, GitHub AI
Inference) turns the repository's own event data into a **prompt**. On any repo that accepts
outside contributions, `github.event.*` is attacker-typed: an issue title, a PR body, a comment.
A model cannot separate instructions from data, so the workflow is a taint path like any other —
except the sink is a prompt and the blast radius is whatever the job's token can reach.

`scan` audits this automatically (it reads only `.github/workflows/*.yml`, costs nothing when
there are none). Findings land as `config` / CWE-1427 candidates and are adjudicated like anything
else — a private repo with no external contributors is a different risk from a public one, and only
you know which this is.

## The vectors

| | shape | why it matters |
|---|---|---|
| **A** | `github.event.*` → `env:` → prompt | **The one review misses.** The prompt field contains no `${{ }}` at all; the value arrives through an environment variable and is interpolated by the shell. A reviewer reading the prompt sees nothing wrong. |
| **B** | `${{ github.event.* }}` directly in a prompt field | Whoever opens the issue writes part of the model's instructions |
| **C** | the prompt tells the agent to run `gh issue view` / `gh api` | reaches the same attacker text one indirection later; no expression scanner sees it |
| **D** | `pull_request_target` + checkout of the PR head | runs a fork's code with the base repo's secrets and write token |
| **E** | CI logs or `workflow_dispatch` inputs fed to the agent | log content is attacker-influenced whenever a build step echoes user data |
| **F** | tool allow-list entries that expand `$()` | `Bash(git log --format=$())` is not the constrained tool it looks like |
| **G** | `eval` / `exec` over an AI step's output | prompt injection becomes code execution in the runner |
| **H** | sandbox disabled — `danger-full-access`, `--yolo`, `Bash(*)` | removes the boundary that makes an injected instruction survivable |
| **I** | wildcard allow-list — `allowed_non_write_users: "*"` | any first-time contributor can drive the agent |
| **J** | `uses: owner/repo@v1` — a movable tag or branch, not a 40-hex commit SHA | whoever controls (or compromises) the upstream repository replaces what runs in this job, with this job's token; applies to every workflow, agent or not |
| **K** | no `permissions:` block, or `permissions: write-all` | the GITHUB_TOKEN carries the repository default — historically write to contents, packages, pull requests — for every step, injected instruction or compromised action included |

**A, B, C, D, G, H, I, J and K are detected mechanically** (J and K on every workflow in the tree,
filed under CWE-829 and CWE-250 rather than prompt injection). E and F need judgment: whether a log line
carries user data, and whether a permitted command can be made to expand a subshell, are questions
about the rest of the repo.

## What the engine cannot see here

The audit is **line-oriented, not a YAML parse** — no dependency may enter the bundle. So it will
miss a prompt assembled through a YAML anchor, a composite action defined in another repository,
or a prompt built by a script the workflow calls. When a workflow uses any of those, read it by
hand and say so in the report's coverage notes.

## Judging one

Ask, in order:

1. **Is the event reachable by an outsider?** `issues`, `issue_comment`, `pull_request_target`,
   `fork` — yes on a public repo. `push` to a protected branch — no.
2. **What does the token hold?** `permissions:` at the job or workflow level. A read-only token
   makes injection an annoyance; `contents: write` plus a release step makes it supply-chain
   compromise.
3. **What may the agent do with it?** The tool allow-list is the real boundary. `Bash(*)` or
   `danger-full-access` means the answer is "everything".
4. **Does anything execute the output?** Vector G turns a text-level problem into RCE.

Severity follows (2) and (3), not the injection itself. An agent with a read-only token and a
`Read`-only tool list is a hardening note; the same prompt with `contents: write` and `Bash(*)` is
critical.

## Fixing it

- Never interpolate event context into a prompt, directly or through `env:`. Pass it as a **file**
  the agent reads, so it arrives as data rather than as instructions — and say so in the prompt.
- Use `pull_request` (not `pull_request_target`) for anything that checks out a fork's code. If
  you genuinely need the base token, do not check out the head.
- Set `permissions:` explicitly, at the job level, to the minimum. The default is too much.
- Keep the tool allow-list specific and free of `*` and `$()`.
- Never `eval` an agent's output. Have it write a file you validate, or emit structured output
  against a schema.
- Gate on author association (`OWNER`, `MEMBER`, `COLLABORATOR`) rather than `*`.

import type { Finding } from "../types.js";
import type { ToolAdapter } from "./run.js";
import { makeToolFinding } from "./normalize.js";

// TruffleHog → secrets that are LIVE.
//
// gitleaks and kingfisher answer "does this look like a credential?". TruffleHog
// answers the question that decides what happens next: it calls the provider and
// asks whether the key still works. A verified AWS key is an incident with a
// clock on it; the same string already rotated is a hygiene note. Reporting both
// at "high" is how a rotation backlog buries a live breach.
//
// `--only-verified` is deliberate. Unverified candidates are already covered by
// two other adapters, and TruffleHog's unverified output is its noisiest tier —
// running it in that mode would triple the secret findings without adding a fact
// the auditor did not already have. What is unique here is the verification.
//
// Output is JSON Lines (one object per finding), not a JSON document.
export const trufflehog: ToolAdapter = {
  name: "trufflehog",
  category: "secret",
  dockerImage: "trufflesecurity/trufflehog:latest",
  network: true, // verification calls the provider — skipped under --offline
  argv: (target) => ["filesystem", target, "--json", "--only-verified", "--no-update"],
  parse(raw): Finding[] {
    const out: Finding[] = [];
    for (const line of (raw || "").split("\n")) {
      const t = line.trim();
      if (!t || !t.startsWith("{")) continue;
      let d: any;
      try {
        d = JSON.parse(t);
      } catch {
        continue; // progress/log lines share the stream
      }
      const detector = d.DetectorName ?? d.DetectorType ?? "secret";
      const meta = d.SourceMetadata?.Data?.Filesystem ?? {};
      const file = meta.file ?? d.SourceName ?? "";
      if (!file) continue;
      const line1 = Number(meta.line ?? 0) + 1; // TruffleHog's filesystem line is 0-based
      out.push(
        makeToolFinding({
          tool: "trufflehog",
          category: "secret",
          ident: `${detector}:${file}:${line1}`,
          title: `Verified live secret — ${detector}`,
          // Verified means the credential answered. That is not the same class of
          // problem as a string that looks like one.
          severity: "critical",
          message: `TruffleHog verified this ${detector} credential is CURRENTLY VALID against the provider. Treat as an active exposure: rotate first, then find how it got committed (history, CI logs, images) — the file is where it was found, not necessarily where it leaked.`,
          file,
          line: line1,
          cwe: "CWE-798",
          verified: true,
        }),
      );
    }
    return out;
  },
};

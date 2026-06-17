import type { Finding } from "../types.js";
import type { ToolAdapter } from "./run.js";
import { parseSarif } from "./sarif.js";

// Kingfisher → secret scanner with offline, checksum-aware + entropy + language-
// aware pre-filtering (fewer false positives than pure regex) and 950+ rules over
// the working tree AND git history. `--no-validate` keeps it fully offline and
// deterministic (the default here, honoring ultrasec's no-network contract); live
// credential validation is opt-in network and out of scope for the static pass.
// Emits SARIF, so the shared parser handles it. CWE-798 (hardcoded credentials).
export const kingfisher: ToolAdapter = {
  name: "kingfisher",
  category: "secret",
  argv: (target) => ["scan", target, "--format", "sarif", "--no-validate"],
  parse: (raw): Finding[] => parseSarif(raw, { tool: "kingfisher", category: "secret", defaultCwe: "CWE-798", defaultSeverity: "high" }),
};

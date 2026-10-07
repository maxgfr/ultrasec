import type { Pack } from "../types.js";
import { XFF, XFF_LOOKBACK } from "./shared.js";

// Idioms that read the same in every language the engine parses. Kept as one
// pack rather than copied into each ecosystem's, which is exactly the
// duplication the pack model exists to avoid.

/** `.split(",")[0]` / `.shift()` / `.at(0)` — the first comma-separated entry. */
const FIRST_HOP = /\.split\(\s*(["'])\s*,\s*\1\s*\)\s*(?:\[\s*0\s*\]|\.shift\(\s*\)|\.at\(\s*0\s*\))/;

export const COMMON_PACK: Pack = {
  id: "common",
  ecosystem: "*",
  classes: {
    "client-ip-first-xff": {
      rules: [
        {
          id: "split-first",
          kind: "line",
          languages: ["javascript", "python", "go", "java", "kotlin", "scala", "php", "ruby", "csharp"],
          match: FIRST_HOP,
          context: { re: XFF, before: XFF_LOOKBACK },
          emit: "webconfig/xff-first-hop",
        },
      ],
    },
  },
};

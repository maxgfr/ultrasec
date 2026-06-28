import { defineConfig } from "tsup";

// Bundles the TypeScript engine into a single, dependency-free ESM script
// (scripts/ultrasec.mjs) that any agent sandbox can run with `node` — no
// `npm install` required at skill-use time. The build then mirrors the bundle
// into skills/ultrasec/scripts/ (via scripts/copy-bundle.mjs) so `npx skills
// add` installs the engine next to SKILL.md. The committed bundle is verified
// reproducible — and the embedded copy byte-identical — in CI via
// `pnpm run check:build`.
export default defineConfig({
  entry: { ultrasec: "src/cli.ts" },
  outDir: "scripts",
  format: ["esm"],
  outExtension: () => ({ js: ".mjs" }),
  target: "node18",
  platform: "node",
  bundle: true,
  clean: false,
  minify: false,
  splitting: false,
  sourcemap: false,
  banner: { js: "#!/usr/bin/env node" },
});

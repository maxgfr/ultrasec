import { defineConfig } from "tsup";

// Bundles the TypeScript engine into a single, dependency-free ESM script
// (scripts/ultrasec.mjs) that any agent sandbox can run with `node` — no
// `npm install` required at skill-use time. SKILL.md sits at the repo root and
// `files` ships `scripts/`, so the skill installs standalone with its bundle.
// The committed bundle is verified reproducible in CI via `pnpm run check:build`.
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

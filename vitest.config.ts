import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Tests write audit dossiers into temp dirs, and fixtures are deliberately
    // vulnerable sample apps (some carry their own committed `.ultrasec/`
    // output) — never collect tests from those trees.
    exclude: [...configDefaults.exclude, "**/.ultrasec/**", "tests/fixtures/**"],
  },
});

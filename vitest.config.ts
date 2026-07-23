import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Tests write audit dossiers into temp dirs, and fixtures are deliberately
    // vulnerable sample apps (some carry their own committed `.ultrasec/`
    // output) — never collect tests from those trees.
    exclude: [...configDefaults.exclude, "**/.ultrasec/**", "tests/fixtures/**"],
    env: {
      // The package-checker adapter resolves upstream latest over the network
      // by default (src/tools/package-checker.ts). Pin it to the vendored
      // copy for the whole suite so tests stay deterministic/offline; the
      // handful of tests that exercise real resolution unset this themselves.
      ULTRASEC_PACKAGE_CHECKER_PINNED: "1",
    },
  },
});

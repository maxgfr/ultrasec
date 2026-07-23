import { describe, it, expect } from "vitest";
import { inferOrigin } from "../src/tools/origin.js";
import { TOOLS, type ToolSpec } from "../src/tools/registry.js";

// Pure path-heuristic coverage: every branch of inferOrigin (src/tools/origin.ts),
// driven with fabricated paths + an explicit OriginContext so nothing here ever
// touches the real filesystem, environment, or a subprocess (no `brew`, `dpkg`,
// `which`, real $HOME/$GOPATH — every real-world default is overridden).

describe("inferOrigin — npm/pnpm/yarn (name-based, before any path check)", () => {
  it("npm always self-upgrades, regardless of where its binary lives", () => {
    const o = inferOrigin("/opt/homebrew/Cellar/node/22.0.0/bin/npm", "npm");
    expect(o.manager).toBe("npm");
    expect(o.upgradeArgv).toEqual([["npm", "install", "-g", "npm@latest"]]);
  });

  it("pnpm is always corepack-managed, even under a Homebrew-shaped path", () => {
    const o = inferOrigin("/opt/homebrew/bin/pnpm", "pnpm");
    expect(o.manager).toBe("corepack");
    expect(o.upgradeArgv).toEqual([["corepack", "up"]]);
  });

  it("yarn is always corepack-managed", () => {
    const o = inferOrigin("/usr/local/bin/yarn", "yarn");
    expect(o.manager).toBe("corepack");
    expect(o.upgradeArgv).toEqual([["corepack", "up"]]);
  });

  it("a corepack shim path also resolves to corepack for any tool name", () => {
    const o = inferOrigin("/opt/homebrew/lib/node_modules/corepack/shims/some-tool", "some-tool");
    expect(o.manager).toBe("corepack");
    expect(o.upgradeArgv).toEqual([["corepack", "up"]]);
  });
});

describe("inferOrigin — brew", () => {
  it("/opt/homebrew/ is unambiguous on its own", () => {
    const o = inferOrigin("/opt/homebrew/bin/trivy", "trivy");
    expect(o.manager).toBe("brew");
    expect(o.upgradeArgv).toEqual([["brew", "upgrade", "trivy"]]);
  });

  it("/usr/local/Cellar/ is unambiguous on its own", () => {
    const o = inferOrigin("/usr/local/Cellar/gitleaks/8.30.1/bin/gitleaks", "gitleaks");
    expect(o.manager).toBe("brew");
    expect(o.upgradeArgv).toEqual([["brew", "upgrade", "gitleaks"]]);
  });

  it("bare /usr/local/bin/ counts as brew only when brewPresent is confirmed", () => {
    const withBrew = inferOrigin("/usr/local/bin/hadolint", "hadolint", { brewPresent: true });
    expect(withBrew.manager).toBe("brew");
    expect(withBrew.upgradeArgv).toEqual([["brew", "upgrade", "hadolint"]]);

    const withoutBrew = inferOrigin("/usr/local/bin/hadolint", "hadolint", { brewPresent: false });
    expect(withoutBrew.manager).toBe("unknown");
    expect(withoutBrew.upgradeArgv).toBeUndefined();
  });

  it("uses the registry's brew packageId override when one is declared (none exist today, but the lookup path is exercised via a fake entry)", () => {
    const fake: ToolSpec = {
      name: "zzz-fake-brew-tool",
      category: "sast",
      description: "d",
      languages: ["*"],
      install: { brew: "brew install real-formula-name" },
      runHint: "n/a",
      packageIds: { brew: "real-formula-name" },
    };
    TOOLS.push(fake);
    try {
      const o = inferOrigin("/opt/homebrew/bin/zzz-fake-brew-tool", "zzz-fake-brew-tool");
      expect(o.upgradeArgv).toEqual([["brew", "upgrade", "real-formula-name"]]);
    } finally {
      TOOLS.pop();
    }
  });
});

describe("inferOrigin — pipx", () => {
  it("~/.local/pipx/venvs/<pkg>/bin/<tool> shape", () => {
    const o = inferOrigin("/home/me/.local/pipx/venvs/semgrep/bin/semgrep", "semgrep");
    expect(o.manager).toBe("pipx");
    expect(o.upgradeArgv).toEqual([["pipx", "upgrade", "semgrep"]]);
  });

  it("older ~/.local/share/pipx/venvs/<pkg>/bin/<tool> shape", () => {
    const o = inferOrigin("/home/me/.local/share/pipx/venvs/bandit/bin/bandit", "bandit");
    expect(o.manager).toBe("pipx");
    expect(o.upgradeArgv).toEqual([["pipx", "upgrade", "bandit"]]);
  });
});

describe("inferOrigin — go", () => {
  it("$GOPATH/bin when GOPATH is set", () => {
    const o = inferOrigin("/fake/gopath/bin/govulncheck", "govulncheck", { gopath: "/fake/gopath" });
    expect(o.manager).toBe("go");
    // registry packageId override for govulncheck already carries @latest.
    expect(o.upgradeArgv).toEqual([["go", "install", "golang.org/x/vuln/cmd/govulncheck@latest"]]);
  });

  it("falls back to ~/go/bin when GOPATH is unset", () => {
    const o = inferOrigin("/fake/home/go/bin/gosec", "gosec", { home: "/fake/home", gopath: undefined });
    expect(o.manager).toBe("go");
    expect(o.upgradeArgv).toEqual([["go", "install", "github.com/securego/gosec/v2/cmd/gosec@latest"]]);
  });

  it("appends @latest when the registry has no packageId override for a go-managed tool", () => {
    const fake: ToolSpec = {
      name: "zzz-fake-go-tool",
      category: "sast",
      description: "d",
      languages: ["go"],
      install: { go: "go install example.com/zzz-fake-go-tool@latest" },
      runHint: "n/a",
    };
    TOOLS.push(fake);
    try {
      const o = inferOrigin("/fake/home/go/bin/zzz-fake-go-tool", "zzz-fake-go-tool", { home: "/fake/home" });
      expect(o.upgradeArgv).toEqual([["go", "install", "zzz-fake-go-tool@latest"]]);
    } finally {
      TOOLS.pop();
    }
  });

  it("a GOPATH set to something unrelated doesn't false-positive a non-go path", () => {
    const o = inferOrigin("/opt/homebrew/bin/govulncheck", "govulncheck", { gopath: "/fake/gopath" });
    expect(o.manager).toBe("brew"); // /opt/homebrew/ still wins — go check never even matches
  });
});

describe("inferOrigin — cargo", () => {
  it("~/.cargo/bin", () => {
    const o = inferOrigin("/fake/home/.cargo/bin/cargo-audit", "cargo-audit", { home: "/fake/home" });
    expect(o.manager).toBe("cargo");
    expect(o.upgradeArgv).toEqual([["cargo", "install", "cargo-audit", "--force"]]);
  });
});

describe("inferOrigin — apt (Linux only, print-only, never sudo)", () => {
  it("a dpkg-owned /usr/bin/* binary on Linux ⇒ apt, no upgradeArgv", () => {
    const o = inferOrigin("/usr/bin/trivy", "trivy", { platform: "linux", aptOwned: true });
    expect(o.manager).toBe("apt");
    expect(o.upgradeArgv).toBeUndefined();
  });

  it("a /usr/bin/* binary NOT owned by dpkg falls through to unknown", () => {
    const o = inferOrigin("/usr/bin/trivy", "trivy", { platform: "linux", aptOwned: false });
    expect(o.manager).toBe("unknown");
  });

  it("the same /usr/bin/* path on a non-Linux platform never hits the apt branch", () => {
    const o = inferOrigin("/usr/bin/trivy", "trivy", { platform: "darwin", aptOwned: true });
    expect(o.manager).toBe("unknown");
  });
});

describe("inferOrigin — unknown", () => {
  it("a path matching no known manager shape ⇒ unknown, no upgradeArgv", () => {
    const o = inferOrigin("/some/random/place/mytool", "mytool", { platform: "darwin" });
    expect(o.manager).toBe("unknown");
    expect(o.upgradeArgv).toBeUndefined();
  });
});

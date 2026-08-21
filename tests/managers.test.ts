import { describe, expect, it } from "bun:test";

import type { PackageManager } from "../src/domain";
import { CONFIG_MANAGER_NAMES, profileFor } from "../src/managers/profile";

describe("manager profiles", () => {
  it("keeps the config manager set stable", () => {
    const expected: PackageManager[] = [
      "bun",
      "bundler",
      "cargo",
      "composer",
      "npm",
      "pnpm",
      "uv",
      "yarn",
    ];
    expect([...CONFIG_MANAGER_NAMES].toSorted()).toEqual(expected.toSorted());
  });
  it("marks python legacy managers as non-config", () => {
    for (const name of ["poetry", "pip", "pipenv"] as const) {
      const p = profileFor(name);
      expect(p.kind).toBe("python-legacy");
      expect(p.auditArgv).toBeNull();
      expect(p.upgradeArgv).toBeNull();
    }
  });
  it("keeps audit argvs byte-identical to the old table", () => {
    expect(profileFor("yarn").auditArgv).toEqual([
      "yarn",
      "npm",
      "audit",
      "--json",
    ]);
    expect(profileFor("uv").auditArgv).toEqual([
      "uv",
      "audit",
      "--output-format",
      "json",
      "--frozen",
    ]);
    expect(profileFor("composer").auditArgv).toEqual([
      "composer",
      "audit",
      "--format",
      "json",
      "--locked",
    ]);
    expect(profileFor("bundler").auditArgv).toEqual([
      "bundle-audit",
      "check",
      "--format",
      "json",
    ]);
  });
  it("keeps upgrade argvs identical", () => {
    expect(profileFor("npm").upgradeArgv?.("left-pad", "1.3.0")).toEqual([
      "npm",
      "install",
      "left-pad@1.3.0",
      "--save-exact",
    ]);
    expect(profileFor("pnpm").upgradeArgv?.("left-pad", "1.3.0")).toEqual([
      "pnpm",
      "add",
      "left-pad@1.3.0",
    ]);
    expect(profileFor("uv").upgradeArgv?.("requests", "2.0.0")).toEqual([
      "uv",
      "lock",
      "--upgrade-package",
      "requests",
    ]);
    expect(profileFor("bundler").upgradeArgv).toBeNull();
  });
  it("keeps lockfile and config names", () => {
    expect(profileFor("bun").lockfileNames).toEqual(["bun.lock", "bun.lockb"]);
    expect(profileFor("cargo").configNames).toEqual([
      ".cargo/config.toml",
      ".cargo/config",
    ]);
    expect(profileFor("uv").configNames).toEqual(["uv.toml", "pyproject.toml"]);
    expect(profileFor("pnpm").writeConfigName).toBe("pnpm-workspace.yaml");
  });
});

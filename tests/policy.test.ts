import { expect, test } from "bun:test";

import { loadPolicy, policyForRepo, resolveSettings } from "../src/policy";

test("defaults to standard preset when no config given", () => {
  const policy = loadPolicy({});
  expect(policy.preset).toBe("standard");
  expect(policy.enabledManagers).toEqual([
    "npm",
    "pnpm",
    "yarn",
    "bun",
    "uv",
    "bundler",
    "cargo",
    "composer",
  ]);
});

test("repo config overrides user preset and flags override repo", () => {
  const policy = loadPolicy({
    flags: { preset: "standard" },
    repoToml: `preset = "strict"\n`,
    userToml: `preset = "relaxed"\n`,
  });
  expect(policy.preset).toBe("standard");
});

test("per-manager table overrides only that manager", () => {
  const policy = loadPolicy({
    repoToml: `
preset = "standard"
[pnpm]
ignoreScripts = false
`,
  });
  expect(policy.preset).toBe("standard");
  expect(policy.perManager.pnpm?.ignoreScripts).toBe(false);
  expect(policy.perManager.npm).toBeUndefined();
});

test("scan layer overrides user and loses to repo", () => {
  const scanWins = loadPolicy({
    scanToml: `preset = "strict"\n`,
    userToml: `preset = "relaxed"\n`,
  });
  expect(scanWins.preset).toBe("strict");

  const repoWins = loadPolicy({
    repoToml: `preset = "standard"\n`,
    scanToml: `preset = "strict"\n`,
    userToml: `preset = "relaxed"\n`,
  });
  expect(repoWins.preset).toBe("standard");
});

test("later global overrides win and merge with earlier keys", () => {
  const policy = loadPolicy({
    repoToml: `minReleaseAgeDays = 14\n`,
    scanToml: `ignoreScripts = true\n`,
    userToml: `ignoreScripts = false\nminReleaseAgeDays = 0\n`,
  });
  expect(policy.overrides.ignoreScripts).toBe(true);
  expect(policy.overrides.minReleaseAgeDays).toBe(14);
});

test("flag overrides win over per-manager tables", () => {
  const policy = loadPolicy({
    flags: { overrides: { ignoreScripts: true } },
    repoToml: `
[pnpm]
ignoreScripts = false
`,
  });
  expect(policy.overrides.ignoreScripts).toBe(true);
  expect(policy.perManager.pnpm?.ignoreScripts).toBe(true);
});

test("invalid TOML in a layer is skipped so later layers still apply", () => {
  const policy = loadPolicy({
    repoToml: `preset = "strict"\n`,
    userToml: `preset = "relaxed"\nthis is not toml [[[`,
  });
  expect(policy.preset).toBe("strict");
});

test("invalid TOML as the only layer leaves standard defaults", () => {
  const policy = loadPolicy({
    userToml: `preset = "strict"\n[[[`,
  });
  expect(policy.preset).toBe("standard");
  expect(policy.enabledManagers).toEqual([
    "npm",
    "pnpm",
    "yarn",
    "bun",
    "uv",
    "bundler",
    "cargo",
    "composer",
  ]);
});

test("composer per-manager table is accepted", () => {
  const policy = loadPolicy({
    repoToml: `
[composer]
ignoreScripts = false
`,
  });
  expect(policy.perManager.composer?.ignoreScripts).toBe(false);
});

test("rejects poetry pip and pipenv as per-manager tables", () => {
  const policy = loadPolicy({
    repoToml: `
[poetry]
ignoreScripts = false
[pip]
ignoreScripts = false
[pipenv]
ignoreScripts = false
[pnpm]
ignoreScripts = false
`,
  });
  expect(policy.perManager.poetry).toBeUndefined();
  expect(policy.perManager.pip).toBeUndefined();
  expect(policy.perManager.pipenv).toBeUndefined();
  expect(policy.perManager.pnpm?.ignoreScripts).toBe(false);
});

test("policyForRepo: repo beats scan beats user for preset", () => {
  const layers = {
    scanToml: `preset = "standard"\n`,
    userToml: `preset = "relaxed"\n`,
  };
  expect(policyForRepo(layers).preset).toBe("standard");
  expect(policyForRepo(layers, `preset = "strict"\n`).preset).toBe("strict");
});

test("policyForRepo: repo beats scan beats user for a per-manager table key", () => {
  const layers = {
    scanToml: `[pnpm]\nminReleaseAgeDays = 7\n`,
    userToml: `[pnpm]\nminReleaseAgeDays = 1\n`,
  };
  expect(policyForRepo(layers).perManager.pnpm?.minReleaseAgeDays).toBe(7);
  expect(
    policyForRepo(layers, `[pnpm]\nminReleaseAgeDays = 14\n`).perManager.pnpm
      ?.minReleaseAgeDays
  ).toBe(14);
});

test("policyForRepo: flags beat repo for preset and a per-manager table key", () => {
  const layers = {
    flags: {
      overrides: { ignoreScripts: true },
      preset: "relaxed" as const,
    },
  };
  const policy = policyForRepo(
    layers,
    `preset = "strict"\n[pnpm]\nignoreScripts = false\n`
  );
  expect(policy.preset).toBe("relaxed");
  expect(policy.perManager.pnpm?.ignoreScripts).toBe(true);
});

test("resolveSettings falls back to preset defaults when override types do not match", () => {
  const policy = loadPolicy({
    flags: {
      overrides: {
        auditLevel: 1,
        ignoreScripts: "yes",
        minReleaseAgeDays: "7",
        requireLockfile: 1,
        requirePmPin: "true",
      },
    },
  });
  expect(resolveSettings(policy, "npm")).toEqual({
    agentic: true,
    applyAgentic: false,
    auditLevel: "high",
    ignoreScripts: true,
    minReleaseAgeDays: 1,
    registry: null,
    requireLockfile: true,
    requirePmPin: true,
  });
});

test("resolveSettings defaults agentic on and applyAgentic off", () => {
  const settings = resolveSettings(loadPolicy({}), "npm");
  expect(settings.agentic).toBe(true);
  expect(settings.applyAgentic).toBe(false);
});

test("resolveSettings reads agentic and applyAgentic from config", () => {
  const settings = resolveSettings(
    loadPolicy({
      repoToml: `
agentic = false
applyAgentic = true
`,
    }),
    "npm"
  );
  expect(settings.agentic).toBe(false);
  expect(settings.applyAgentic).toBe(true);
});

test("resolveSettings uses a typed per-manager value over the global override", () => {
  const policy = loadPolicy({
    repoToml: `
ignoreScripts = true
[pnpm]
ignoreScripts = false
`,
  });
  expect(resolveSettings(policy, "pnpm").ignoreScripts).toBe(false);
  expect(resolveSettings(policy, "npm").ignoreScripts).toBe(true);
});

test("resolveSettings defaults registry to unset", () => {
  expect(resolveSettings(loadPolicy({}), "npm").registry).toBeNull();
});

test("resolveSettings reads a global registry string", () => {
  const settings = resolveSettings(
    loadPolicy({
      repoToml: `registry = "https://npm.corp.example/"\n`,
    }),
    "npm"
  );
  expect(settings.registry).toBe("https://npm.corp.example/");
});

test("resolveSettings uses a per-manager registry over the global one", () => {
  const policy = loadPolicy({
    repoToml: `
registry = "https://npm.corp.example/"
[yarn]
registry = "https://yarn.corp.example/"
`,
  });
  expect(resolveSettings(policy, "npm").registry).toBe(
    "https://npm.corp.example/"
  );
  expect(resolveSettings(policy, "yarn").registry).toBe(
    "https://yarn.corp.example/"
  );
});

test("resolveSettings treats empty or non-string registry as unset", () => {
  const empty = resolveSettings(
    loadPolicy({ repoToml: `registry = "  "\n` }),
    "npm"
  );
  expect(empty.registry).toBeNull();

  const wrongType = resolveSettings(
    loadPolicy({
      flags: { overrides: { registry: true } },
    }),
    "npm"
  );
  expect(wrongType.registry).toBeNull();
});

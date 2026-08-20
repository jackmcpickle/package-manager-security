import { expect, test } from "bun:test";
import { loadPolicy } from "../src/policy";

test("defaults to standard preset when no config given", () => {
  const policy = loadPolicy({});
  expect(policy.preset).toBe("standard");
  expect(policy.enabledManagers).toEqual(["npm", "pnpm", "yarn", "bun", "uv"]);
});

test("repo config overrides user preset and flags override repo", () => {
  const policy = loadPolicy({
    userToml: `preset = "relaxed"\n`,
    repoToml: `preset = "strict"\n`,
    flags: { preset: "standard" },
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
    userToml: `preset = "relaxed"\n`,
    scanToml: `preset = "strict"\n`,
  });
  expect(scanWins.preset).toBe("strict");

  const repoWins = loadPolicy({
    userToml: `preset = "relaxed"\n`,
    scanToml: `preset = "strict"\n`,
    repoToml: `preset = "standard"\n`,
  });
  expect(repoWins.preset).toBe("standard");
});

test("later global overrides win and merge with earlier keys", () => {
  const policy = loadPolicy({
    userToml: `ignoreScripts = false\nminReleaseAgeDays = 0\n`,
    scanToml: `ignoreScripts = true\n`,
    repoToml: `minReleaseAgeDays = 14\n`,
  });
  expect(policy.overrides.ignoreScripts).toBe(true);
  expect(policy.overrides.minReleaseAgeDays).toBe(14);
});

test("flag overrides win over per-manager tables", () => {
  const policy = loadPolicy({
    repoToml: `
[pnpm]
ignoreScripts = false
`,
    flags: { overrides: { ignoreScripts: true } },
  });
  expect(policy.overrides.ignoreScripts).toBe(true);
  expect(policy.perManager.pnpm?.ignoreScripts).toBe(true);
});

test("invalid TOML in a layer is skipped so later layers still apply", () => {
  const policy = loadPolicy({
    userToml: `preset = "relaxed"\nthis is not toml [[[`,
    repoToml: `preset = "strict"\n`,
  });
  expect(policy.preset).toBe("strict");
});

test("invalid TOML as the only layer leaves standard defaults", () => {
  const policy = loadPolicy({
    userToml: `preset = "strict"\n[[[`,
  });
  expect(policy.preset).toBe("standard");
  expect(policy.enabledManagers).toEqual(["npm", "pnpm", "yarn", "bun", "uv"]);
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

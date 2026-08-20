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

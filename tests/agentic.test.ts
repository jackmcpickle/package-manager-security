import { expect, test } from "bun:test";

import { applySettings } from "../src/apply-settings";
import type { PackageManager, Project } from "../src/domain";
import { loadPolicy } from "../src/policy";
import { auditSettings } from "../src/settings";

const CONFIG_NAME: Partial<Record<PackageManager, string>> = {
  bun: "bunfig.toml",
  npm: ".npmrc",
  pnpm: "pnpm-workspace.yaml",
  uv: "pyproject.toml",
  yarn: ".yarnrc.yml",
};

const LOCK_NAME: Partial<Record<PackageManager, string>> = {
  bun: "bun.lock",
  npm: "package-lock.json",
  pnpm: "pnpm-lock.yaml",
  uv: "uv.lock",
  yarn: "yarn.lock",
};

const project = (name: PackageManager, root = "/p"): Project => ({
  gitRoot: root,
  managers: [
    {
      configPath: `${root}/${CONFIG_NAME[name]}`,
      lockfilePath: `${root}/${LOCK_NAME[name]}`,
      manifestPath:
        name === "uv" ? `${root}/pyproject.toml` : `${root}/package.json`,
      name,
      role: "primary",
    },
  ],
  root,
});

const findings = (
  name: PackageManager,
  files: Record<string, string>,
  policy = loadPolicy({})
) =>
  auditSettings(project(name), policy, {
    readFile: (p) => files[p] ?? null,
  });

const find = (
  name: PackageManager,
  files: Record<string, string>,
  code: string,
  policy = loadPolicy({})
) => findings(name, files, policy).find((row) => row.code === code);

const npmSecure = (
  extraRc = "",
  manifest = '{"name":"x","packageManager":"npm@11.0.0"}'
) => ({
  "/p/.npmrc": `ignore-scripts=true\nallow-scripts-pin=true\naudit=true\naudit-level=high\nmin-release-age=1\nregistry=https://registry.npmjs.org/\n${extraRc}`,
  "/p/package-lock.json": `{"lockfileVersion":3}`,
  "/p/package.json": manifest,
});

const pnpmSecure = (
  yaml = "",
  manifest = '{"name":"x","packageManager":"pnpm@11.7.0"}'
) => ({
  "/p/package.json": manifest,
  "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
  "/p/pnpm-workspace.yaml": `registry: "https://registry.npmjs.org/"\naudit: true\nauditLevel: high\ntrustPolicy: no-downgrade\nverifyDepsBeforeRun: error\nminimumReleaseAge: 1440\nallowBuilds: {}\n${yaml}`,
});

const yarnSecure = (
  yaml = "",
  manifest = '{"name":"x","packageManager":"yarn@4.15.0"}'
) => ({
  "/p/.yarnrc.yml": `npmRegistryServer: "https://registry.npmjs.org/"\nenableScripts: false\nnpmMinimalAgeGate: 7d\napprovedGitRepositories: []\nnodeLinker: node-modules\n${yaml}`,
  "/p/package.json": manifest,
  "/p/yarn.lock": "",
});

const bunSecure = (install = "", extraToml = "") => ({
  "/p/bun.lock": `{"lockfileVersion":1}`,
  "/p/bunfig.toml": `trustedDependencies = ["foo"]\n\n[install]\nregistry = "https://registry.npmjs.org/"\nminimumReleaseAge = 86400\n${install}\n${extraToml}`,
  "/p/package.json": `{"name":"x","trustedDependencies":["foo"]}`,
});

test("npm overrides emit overrides.present as info and not fixable", () => {
  const files = npmSecure(
    "",
    '{"name":"x","packageManager":"npm@11.0.0","overrides":{"lodash":"4.17.21"}}'
  );
  const finding = find("npm", files, "overrides.present");
  expect(finding?.severity).toBe("info");
  expect(finding?.fixable).toBe(false);
  expect(finding?.fix).toBeUndefined();
});

test("agentic = false suppresses override warnings", () => {
  const files = npmSecure(
    "",
    '{"name":"x","packageManager":"npm@11.0.0","overrides":{"lodash":"4.17.21"}}'
  );
  const policy = loadPolicy({ repoToml: "agentic = false\n" });
  expect(find("npm", files, "overrides.present", policy)).toBeUndefined();
});

test("applyAgentic still does not attach a fix for overrides", () => {
  const files = npmSecure(
    "",
    '{"name":"x","packageManager":"npm@11.0.0","overrides":{"lodash":"4.17.21"}}'
  );
  const policy = loadPolicy({ repoToml: "applyAgentic = true\n" });
  const finding = find("npm", files, "overrides.present", policy);
  expect(finding?.fixable).toBe(false);
  expect(finding?.fix).toBeUndefined();
});

test("yarn resolutions emit overrides.present", () => {
  const files = yarnSecure(
    "",
    '{"name":"x","packageManager":"yarn@4.15.0","resolutions":{"lodash":"4.17.21"}}'
  );
  expect(find("yarn", files, "overrides.present")).toBeDefined();
});

test("pnpm workspace overrides emit overrides.present", () => {
  const files = pnpmSecure("overrides:\n  lodash: 4.17.21\n");
  expect(find("pnpm", files, "overrides.present")).toBeDefined();
});

test("pnpm 11 package.json#pnpm.overrides is overrides.legacy-location", () => {
  const files = pnpmSecure(
    "",
    '{"name":"x","packageManager":"pnpm@11.7.0","pnpm":{"overrides":{"lodash":"4.17.21"}}}'
  );
  const finding = find("pnpm", files, "overrides.legacy-location");
  expect(finding?.severity).toBe("info");
  expect(finding?.fixable).toBe(false);
});

test("a committed npm cache path emits cache.path-committed", () => {
  const files = npmSecure("cache=/Users/me/.npm\n");
  const finding = find("npm", files, "cache.path-committed");
  expect(finding?.severity).toBe("info");
  expect(finding?.fixable).toBe(false);
  expect(finding?.fix).toBeUndefined();
});

test("applyAgentic makes a committed cache path fixable by unsetting it", () => {
  const files = npmSecure("cache=/Users/me/.npm\n");
  const policy = loadPolicy({ repoToml: "applyAgentic = true\n" });
  const finding = find("npm", files, "cache.path-committed", policy);
  expect(finding?.fixable).toBe(true);
  expect(finding?.fix?.edits).toEqual([{ key: "cache", op: "unset" }]);
});

test("pnpm storeDir emits cache.path-committed", () => {
  const files = pnpmSecure("storeDir: /Users/me/Library/pnpm/store\n");
  expect(find("pnpm", files, "cache.path-committed")).toBeDefined();
});

test("yarn cacheFolder emits cache.path-committed", () => {
  const files = yarnSecure("cacheFolder: /tmp/yarn-cache\n");
  expect(find("yarn", files, "cache.path-committed")).toBeDefined();
});

test("bun install.cache.dir emits cache.path-committed", () => {
  const files = bunSecure("", '[install.cache]\ndir = "/tmp/bun-cache"\n');
  expect(find("bun", files, "cache.path-committed")).toBeDefined();
});

test("uv cache-dir emits cache.path-committed", () => {
  const files = {
    "/p/pyproject.toml": `[tool.uv]\nexclude-newer = 30\ncache-dir = "/tmp/uv-cache"\n\n[tool.uv.audit]\nmalware-check = true\n`,
    "/p/uv.lock": `version = 1\n`,
  };
  expect(find("uv", files, "cache.path-committed")).toBeDefined();
});

test("yarn enableGlobalCache false emits agentic.cache-disabled", () => {
  const files = yarnSecure("enableGlobalCache: false\n");
  const finding = find("yarn", files, "agentic.cache-disabled");
  expect(finding?.severity).toBe("info");
  expect(finding?.fixable).toBe(false);
});

test("applyAgentic can restore enableGlobalCache", () => {
  const files = yarnSecure("enableGlobalCache: false\n");
  const policy = loadPolicy({ repoToml: "applyAgentic = true\n" });
  const finding = find("yarn", files, "agentic.cache-disabled", policy);
  expect(finding?.fixable).toBe(true);
  expect(finding?.fix?.edits).toEqual([
    { key: "enableGlobalCache", op: "set", value: true },
  ]);
});

test("pnpm shamefullyHoist emits layout.shamefully-hoist", () => {
  const files = pnpmSecure("shamefullyHoist: true\n");
  expect(find("pnpm", files, "layout.shamefully-hoist")).toBeDefined();
});

test("pnpm publicHoistPattern star emits layout.shamefully-hoist", () => {
  const files = pnpmSecure("publicHoistPattern:\n  - '*'\n");
  expect(find("pnpm", files, "layout.shamefully-hoist")).toBeDefined();
});

test("yarn nodeLinker pnp emits layout.pnp", () => {
  const files = yarnSecure("nodeLinker: pnp\n");
  expect(find("yarn", files, "layout.pnp")).toBeDefined();
});

test("yarn missing nodeLinker emits layout.pnp because pnp is the default", () => {
  const files = {
    "/p/.yarnrc.yml": `npmRegistryServer: "https://registry.npmjs.org/"\nenableScripts: false\nnpmMinimalAgeGate: 7d\napprovedGitRepositories: []\n`,
    "/p/package.json": `{"name":"x","packageManager":"yarn@4.15.0"}`,
    "/p/yarn.lock": "",
  };
  expect(find("yarn", files, "layout.pnp")).toBeDefined();
});

test("pnpm nodeLinker pnp emits layout.pnp", () => {
  const files = pnpmSecure("nodeLinker: pnp\n");
  expect(find("pnpm", files, "layout.pnp")).toBeDefined();
});

test("apply without applyAgentic leaves a committed cache path in place", () => {
  const files = npmSecure("cache=/Users/me/.npm\n");
  const target = project("npm");
  const policy = loadPolicy({});
  const rows = auditSettings(target, policy, {
    readFile: (p) => files[p] ?? null,
  });
  applySettings(target, rows, policy, {
    commit: false,
    force: false,
    gitStatus: () => "clean",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
  });
  expect(files["/p/.npmrc"]).toContain("cache=/Users/me/.npm");
});

test("apply with applyAgentic unsets a committed cache path", () => {
  const files = npmSecure("cache=/Users/me/.npm\n");
  const target = project("npm");
  const policy = loadPolicy({ repoToml: "applyAgentic = true\n" });
  const rows = auditSettings(target, policy, {
    readFile: (p) => files[p] ?? null,
  });
  applySettings(target, rows, policy, {
    commit: false,
    force: false,
    gitStatus: () => "clean",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
  });
  expect(files["/p/.npmrc"]).not.toContain("cache=");
});

test("a secure baseline emits no agentic findings", () => {
  expect(
    findings("npm", npmSecure()).filter(
      (row) =>
        row.code.startsWith("overrides") ||
        row.code.startsWith("cache.") ||
        row.code.startsWith("layout.") ||
        row.code.startsWith("agentic.")
    )
  ).toEqual([]);
  expect(
    findings("pnpm", pnpmSecure()).filter(
      (row) =>
        row.code.startsWith("overrides") ||
        row.code.startsWith("cache.") ||
        row.code.startsWith("layout.") ||
        row.code.startsWith("agentic.")
    )
  ).toEqual([]);
  expect(
    findings("yarn", yarnSecure()).filter(
      (row) =>
        row.code.startsWith("overrides") ||
        row.code.startsWith("cache.") ||
        row.code.startsWith("layout.") ||
        row.code.startsWith("agentic.")
    )
  ).toEqual([]);
});

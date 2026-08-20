import { expect, test } from "bun:test";

import { applySettings } from "../src/apply-settings";
import type { PackageManager, Project } from "../src/domain";
import { loadPolicy } from "../src/policy";
import { auditSettings } from "../src/settings";

const CONFIG_NAME: Record<string, string> = {
  bun: "bunfig.toml",
  npm: ".npmrc",
  pnpm: "pnpm-workspace.yaml",
  uv: "pyproject.toml",
  yarn: ".yarnrc.yml",
};

const LOCK_NAME: Record<string, string> = {
  bun: "bun.lock",
  npm: "package-lock.json",
  pnpm: "pnpm-lock.yaml",
  uv: "uv.lock",
  yarn: "yarn.lock",
};

const project = (name: PackageManager, root = "/p"): Project => {
  const manifest = name === "uv" ? "pyproject.toml" : "package.json";
  return {
    gitRoot: root,
    managers: [
      {
        configPath: `${root}/${CONFIG_NAME[name]}`,
        lockfilePath: `${root}/${LOCK_NAME[name]}`,
        manifestPath: `${root}/${manifest}`,
        name,
        role: "primary",
      },
    ],
    root,
  };
};

const codes = (
  name: PackageManager,
  files: Record<string, string>,
  policy = loadPolicy({})
): string[] =>
  auditSettings(project(name), policy, {
    readFile: (p) => files[p] ?? null,
  }).map((f) => f.code);

const find = (
  name: PackageManager,
  files: Record<string, string>,
  code: string,
  policy = loadPolicy({})
) =>
  auditSettings(project(name), policy, {
    readFile: (p) => files[p] ?? null,
  }).find((f) => f.code === code);

/** A pnpm project whose only interesting content is the workspace yaml. */
const pnpmFiles = (version: string, yaml: string): Record<string, string> => ({
  "/p/package.json": `{"name":"x","packageManager":"pnpm@${version}"}`,
  "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
  "/p/pnpm-workspace.yaml": `registry: "https://registry.npmjs.org/"\naudit: true\nauditLevel: high\n${yaml}`,
});

const yarnFiles = (version: string, yaml: string): Record<string, string> => ({
  "/p/.yarnrc.yml": `npmRegistryServer: "https://registry.npmjs.org/"\n${yaml}`,
  "/p/package.json": `{"name":"x","packageManager":"yarn@${version}"}`,
  "/p/yarn.lock": "",
});

const bunFiles = (install: string): Record<string, string> => ({
  "/p/bun.lock": `{"lockfileVersion":1}`,
  "/p/bunfig.toml": `trustedDependencies = ["foo"]\n\n[install]\nregistry = "https://registry.npmjs.org/"\n${install}`,
  "/p/package.json": `{"name":"x","trustedDependencies":["foo"]}`,
});

const npmFiles = (manifest: string, npmrc: string): Record<string, string> => ({
  "/p/.npmrc": `audit=true\naudit-level=high\nmin-release-age=7\nregistry=https://registry.npmjs.org/\n${npmrc}`,
  "/p/package-lock.json": `{"lockfileVersion":3}`,
  "/p/package.json": manifest,
});

// --- pnpm 11 build settings -------------------------------------------------

test("pnpm 11 allowBuilds satisfies the script check", () => {
  const files = pnpmFiles(
    "11.7.0",
    "minimumReleaseAge: 10080\nallowBuilds:\n  esbuild: true\n"
  );
  expect(codes("pnpm", files)).toEqual([]);
});

test("pnpm 11 flags the removed onlyBuiltDependencies family", () => {
  const files = pnpmFiles(
    "11.7.0",
    "minimumReleaseAge: 10080\nonlyBuiltDependencies:\n  - esbuild\n"
  );
  const finding = find("pnpm", files, "scripts.legacy-config");
  expect(finding?.severity).toBe("high");
  expect(finding?.message).toContain("onlyBuiltDependencies");
});

test("pnpm 10 still accepts the legacy build allowlist", () => {
  const files = pnpmFiles(
    "10.0.0",
    "minimumReleaseAge: 10080\nonlyBuiltDependencies:\n  - esbuild\n"
  );
  expect(codes("pnpm", files)).toEqual([]);
});

test("pnpm dangerouslyAllowAllBuilds is high regardless of version", () => {
  const files = pnpmFiles(
    "11.7.0",
    "minimumReleaseAge: 10080\ndangerouslyAllowAllBuilds: true\n"
  );
  expect(find("pnpm", files, "scripts.unrestricted")?.severity).toBe("high");
});

test("pnpm relying on the safe build default is info, not high", () => {
  const files = pnpmFiles("11.7.0", "minimumReleaseAge: 10080\n");
  const finding = find("pnpm", files, "scripts.unrestricted");
  expect(finding?.severity).toBe("info");
  expect(finding?.fixable).toBe(true);
});

test("pnpm 9 without any allowlist is still high", () => {
  const files = pnpmFiles("9.0.0", "minimumReleaseAge: 10080\n");
  expect(find("pnpm", files, "scripts.unrestricted")?.severity).toBe("high");
});

test("pnpm strictDepBuilds: false is flagged", () => {
  const files = pnpmFiles(
    "11.7.0",
    "minimumReleaseAge: 10080\nallowBuilds: {}\nstrictDepBuilds: false\n"
  );
  expect(codes("pnpm", files)).toContain("scripts.non-strict");
});

test("pnpm blockExoticSubdeps: false is flagged", () => {
  const files = pnpmFiles(
    "11.7.0",
    "minimumReleaseAge: 10080\nallowBuilds: {}\nblockExoticSubdeps: false\n"
  );
  expect(codes("pnpm", files)).toContain("source.non-registry");
});

// --- release-age gates ------------------------------------------------------

test("pnpm 11 inherits minimumReleaseAge 1440, which clears a 1-day bar", () => {
  const files = pnpmFiles("11.7.0", "allowBuilds: {}\n");
  const policy = loadPolicy({ flags: { overrides: { minReleaseAgeDays: 1 } } });
  expect(codes("pnpm", files, policy)).toEqual([]);
});

test("pnpm 11 default of 1440 minutes does not clear the standard 7-day bar", () => {
  const files = pnpmFiles("11.7.0", "allowBuilds: {}\n");
  expect(codes("pnpm", files)).toContain("min-age.disabled");
});

test("pnpm minimumReleaseAgeStrict: false is flagged", () => {
  const files = pnpmFiles(
    "11.7.0",
    "allowBuilds: {}\nminimumReleaseAge: 10080\nminimumReleaseAgeStrict: false\n"
  );
  expect(codes("pnpm", files)).toContain("min-age.non-strict");
});

test("a wildcard minimumReleaseAgeExclude voids the gate", () => {
  const files = pnpmFiles(
    "11.7.0",
    'allowBuilds: {}\nminimumReleaseAge: 10080\nminimumReleaseAgeExclude:\n  - "*"\n'
  );
  expect(codes("pnpm", files)).toContain("min-age.exclude-all");
});

test("a named minimumReleaseAgeExclude is left alone", () => {
  const files = pnpmFiles(
    "11.7.0",
    "allowBuilds: {}\nminimumReleaseAge: 10080\nminimumReleaseAgeExclude:\n  - typescript\n"
  );
  expect(codes("pnpm", files)).not.toContain("min-age.exclude-all");
});

test("strict preset wants minimumReleaseAgeIgnoreMissingTime off", () => {
  const files = pnpmFiles(
    "11.7.0",
    "allowBuilds: {}\nminimumReleaseAge: 20160\n"
  );
  const strict = loadPolicy({ flags: { preset: "strict" } });
  expect(codes("pnpm", files, strict)).toContain("min-age.missing-time");
  expect(codes("pnpm", files)).not.toContain("min-age.missing-time");
});

test("relaxed preset skips every release-age check", () => {
  const files = pnpmFiles(
    "11.7.0",
    'allowBuilds: {}\nminimumReleaseAge: 0\nminimumReleaseAgeStrict: false\nminimumReleaseAgeExclude:\n  - "*"\n'
  );
  const relaxed = loadPolicy({ flags: { preset: "relaxed" } });
  expect(
    codes("pnpm", files, relaxed).filter((c) => c.startsWith("min-age"))
  ).toEqual([]);
});

// --- yarn -------------------------------------------------------------------

test("yarn 4.15 relying on the enableScripts default is info, not high", () => {
  const files = yarnFiles("4.15.0", "npmMinimalAgeGate: 10080\n");
  const finding = find("yarn", files, "scripts.unrestricted");
  expect(finding?.severity).toBe("info");
  expect(finding?.fixable).toBe(true);
});

test("yarn enableScripts: true is high even on 4.15", () => {
  const files = yarnFiles(
    "4.15.0",
    "npmMinimalAgeGate: 10080\nenableScripts: true\n"
  );
  expect(find("yarn", files, "scripts.unrestricted")?.severity).toBe("high");
});

test("yarn 4.13 predates the scripts-off default so an absent key is high", () => {
  const files = yarnFiles("4.13.0", "npmMinimalAgeGate: 10080\n");
  expect(find("yarn", files, "scripts.unrestricted")?.severity).toBe("high");
});

test("yarn npmMinimalAgeGate accepts duration strings", () => {
  const files = yarnFiles(
    "4.15.0",
    "enableScripts: false\nnpmMinimalAgeGate: 7d\n"
  );
  expect(codes("yarn", files)).toEqual([]);
});

test("yarn 4.15 inherits a 1w gate, which clears the standard bar but not strict", () => {
  const files = yarnFiles("4.15.0", "enableScripts: false\n");
  expect(codes("yarn", files)).not.toContain("min-age.disabled");
  const strict = loadPolicy({ flags: { preset: "strict" } });
  expect(codes("yarn", files, strict)).toContain("min-age.disabled");
});

test("yarn 4.11 predates the gate so an absent key fails", () => {
  const files = yarnFiles("4.11.0", "enableScripts: false\n");
  expect(codes("yarn", files)).toContain("min-age.disabled");
});

test("a wildcard npmPreapprovedPackages voids the gate", () => {
  const files = yarnFiles(
    "4.15.0",
    'enableScripts: false\nnpmPreapprovedPackages:\n  - "*"\n'
  );
  expect(codes("yarn", files)).toContain("min-age.exclude-all");
});

test("yarn checksumBehavior other than throw is flagged", () => {
  const files = yarnFiles(
    "4.15.0",
    "enableScripts: false\nchecksumBehavior: update\n"
  );
  expect(codes("yarn", files)).toContain("integrity.checksum-relaxed");
});

test("yarn enableStrictSsl: false and enableHardenedMode: false are flagged", () => {
  const files = yarnFiles(
    "4.15.0",
    "enableScripts: false\nenableStrictSsl: false\nenableHardenedMode: false\n"
  );
  const found = codes("yarn", files);
  expect(found).toContain("integrity.strict-ssl");
  expect(found).toContain("integrity.hardened-mode");
});

// --- bun --------------------------------------------------------------------

test("bun minimumReleaseAge is read as seconds", () => {
  expect(codes("bun", bunFiles("minimumReleaseAge = 604800\n"))).toEqual([]);
  // 10080 would be seven days in minutes, but bun counts seconds.
  expect(codes("bun", bunFiles("minimumReleaseAge = 10080\n"))).toContain(
    "min-age.disabled"
  );
});

test("bun with no minimumReleaseAge is flagged", () => {
  expect(codes("bun", bunFiles(""))).toContain("min-age.disabled");
});

test("a wildcard minimumReleaseAgeExcludes voids the bun gate", () => {
  const files = bunFiles(
    'minimumReleaseAge = 604800\nminimumReleaseAgeExcludes = ["*"]\n'
  );
  expect(codes("bun", files)).toContain("min-age.exclude-all");
});

// --- npm --------------------------------------------------------------------

test("an enforced allowScripts policy replaces blanket ignore-scripts", () => {
  const files = npmFiles(
    `{"name":"x","packageManager":"npm@11.17.0","allowScripts":{"esbuild@0.2.5":true}}`,
    "strict-allow-scripts=true\n"
  );
  expect(codes("npm", files)).toEqual([]);
});

test("allowScripts without strict-allow-scripts is only advisory", () => {
  const files = npmFiles(
    `{"name":"x","allowScripts":{"esbuild@0.2.5":true}}`,
    ""
  );
  const found = codes("npm", files);
  expect(found).toContain("scripts.unrestricted");
  expect(found).toContain("scripts.allowlist-advisory");
});

test("ignore-scripts masking an allowScripts policy is reported", () => {
  const files = npmFiles(
    `{"name":"x","allowScripts":{"esbuild@0.2.5":true}}`,
    "ignore-scripts=true\n"
  );
  const found = codes("npm", files);
  expect(found).not.toContain("scripts.unrestricted");
  expect(found).toContain("scripts.allowlist-masked");
});

test("npm allow-git=all is flagged", () => {
  const files = npmFiles(
    `{"name":"x","packageManager":"npm@11.17.0"}`,
    "ignore-scripts=true\nallow-git=all\n"
  );
  expect(codes("npm", files)).toContain("source.non-registry");
});

// --- uv ---------------------------------------------------------------------

const uvFiles = (toolUv: string): Record<string, string> => ({
  "/p/pyproject.toml": `[project]\nname = "x"\n\n[tool.uv]\n${toolUv}`,
  "/p/uv.lock": "version = 1\n",
});

test("uv exclude-newer accepts uv's own duration spelling", () => {
  expect(codes("uv", uvFiles(`exclude-newer = "7 days"\n`))).toEqual([]);
  expect(codes("uv", uvFiles(`exclude-newer = "1 week"\n`))).toEqual([]);
  expect(codes("uv", uvFiles(`exclude-newer = "2 days"\n`))).toContain(
    "min-age.disabled"
  );
});

test("a wildcard exclude-newer-package voids the uv gate", () => {
  const files = uvFiles(
    `exclude-newer = "7 days"\n\n[tool.uv.exclude-newer-package]\n"*" = false\n`
  );
  expect(codes("uv", files)).toContain("min-age.exclude-all");
});

// --- apply ------------------------------------------------------------------

test("apply migrates the pnpm legacy build allowlist into allowBuilds", () => {
  const files = pnpmFiles(
    "11.7.0",
    "minimumReleaseAge: 10080\nonlyBuiltDependencies:\n  - esbuild\nneverBuiltDependencies:\n  - core-js\n"
  );
  const target = project("pnpm");
  const findings = auditSettings(target, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  applySettings(target, findings, loadPolicy({}), {
    commit: false,
    force: false,
    gitStatus: () => "clean",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
  });
  const written = files["/p/pnpm-workspace.yaml"] ?? "";
  expect(written).toContain("esbuild: true");
  expect(written).toContain("core-js: false");
  expect(written).not.toContain("onlyBuiltDependencies");
  expect(written).not.toContain("neverBuiltDependencies");
});

test("apply strips wildcard entries from a pnpm exclude list", () => {
  const files = pnpmFiles(
    "11.7.0",
    'allowBuilds: {}\nminimumReleaseAge: 10080\nminimumReleaseAgeExclude:\n  - "*"\n  - typescript\n'
  );
  const target = project("pnpm");
  const findings = auditSettings(target, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  applySettings(target, findings, loadPolicy({}), {
    commit: false,
    force: false,
    gitStatus: () => "clean",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
  });
  const written = files["/p/pnpm-workspace.yaml"] ?? "";
  expect(written).toContain("typescript");
  expect(written).not.toContain('"*"');
});

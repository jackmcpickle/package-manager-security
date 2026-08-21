import { afterAll, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { auditAdvisories } from "../src/advisories";
import { applySettings } from "../src/apply-settings";
import { parseBundleConfig } from "../src/bundle-config";
import { createFsCache } from "../src/cache";
import { discoverProjects } from "../src/discover";
import type { Policy, Project } from "../src/domain";
import { loadPolicy } from "../src/policy";
import { auditSettings } from "../src/settings";
import { memoryFs } from "./helpers/memory-fs";

const cacheRoot = mkdtempSync(path.join(tmpdir(), "mailclad-test-bundler-"));

afterAll(() => {
  rmSync(cacheRoot, { force: true, recursive: true });
});

const bundlerProject = (
  configPath: string | null = "/r/.bundle/config"
): Project => ({
  gitRoot: "/r",
  managers: [
    {
      configPath,
      lockfilePath: "/r/Gemfile.lock",
      manifestPath: "/r/Gemfile",
      name: "bundler",
      role: "primary",
    },
  ],
  root: "/r",
});

const bundlerBase = (): Record<string, string> => ({
  "/r/Gemfile": 'source "https://rubygems.org"\n',
  "/r/Gemfile.lock": "GEM\n",
});

const bundlerFiles = (config: string): Record<string, string> => ({
  ...bundlerBase(),
  "/r/.bundle/config": config,
});

const codes = (
  files: Record<string, string>,
  policy: Policy = loadPolicy({}),
  configPath: string | null = "/r/.bundle/config"
): string[] =>
  auditSettings(bundlerProject(configPath), policy, {
    readFile: (p) => files[p] ?? null,
  }).map((f) => f.code);

const apply = (
  files: Record<string, string>,
  policy: Policy = loadPolicy({}),
  configPath: string | null = "/r/.bundle/config"
) => {
  const project = bundlerProject(configPath);
  const findings = auditSettings(project, policy, {
    readFile: (p) => files[p] ?? null,
  });
  const result = applySettings(project, findings, policy, {
    commit: false,
    force: false,
    gitStatus: () => "clean",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, body) => {
      files[p] = body;
    },
  });
  return { files, result };
};

// --- audit: BUNDLE_COOLDOWN -------------------------------------------------

test("bundler BUNDLE_COOLDOWN meeting the preset is quiet", () => {
  expect(codes(bundlerFiles('---\nBUNDLE_COOLDOWN: "1"\n'))).toEqual([]);
});

test("bundler without a .bundle/config emits min-age.disabled", () => {
  expect(codes(bundlerBase())).toContain("min-age.disabled");
});

test("bundler BUNDLE_COOLDOWN below the preset emits min-age.disabled", () => {
  expect(codes(bundlerFiles('---\nBUNDLE_COOLDOWN: "0"\n'))).toContain(
    "min-age.disabled"
  );
});

test("bundler non-numeric BUNDLE_COOLDOWN emits min-age.disabled", () => {
  expect(codes(bundlerFiles('---\nBUNDLE_COOLDOWN: "soon"\n'))).toContain(
    "min-age.disabled"
  );
});

test("bundler unquoted BUNDLE_COOLDOWN is read as a number", () => {
  expect(codes(bundlerFiles("---\nBUNDLE_COOLDOWN: 7\n"))).toEqual([]);
});

test("bundler min-age is not checked under the relaxed preset", () => {
  const relaxed = loadPolicy({ flags: { preset: "relaxed" } });
  expect(codes(bundlerBase(), relaxed)).toEqual([]);
});

test("bundler min-age uses the strict preset's 14-day threshold", () => {
  const strict = loadPolicy({ flags: { preset: "strict" } });
  expect(codes(bundlerFiles('---\nBUNDLE_COOLDOWN: "7"\n'), strict)).toContain(
    "min-age.disabled"
  );
  expect(codes(bundlerFiles('---\nBUNDLE_COOLDOWN: "14"\n'), strict)).toEqual(
    []
  );
});

test("bundler falls back to .bundle/config when no configPath was detected", () => {
  const findings = auditSettings(bundlerProject(null), loadPolicy({}), {
    readFile: (p) => bundlerBase()[p] ?? null,
  });
  const minAge = findings.find((f) => f.code === "min-age.disabled");
  expect(minAge?.path).toBe("/r/.bundle/config");
});

// --- audit: lockfile --------------------------------------------------------

test("bundler without Gemfile.lock emits lockfile.missing", () => {
  const files = { "/r/Gemfile": 'source "https://rubygems.org"\n' };
  expect(codes(files)).toContain("lockfile.missing");
});

// --- apply ------------------------------------------------------------------

test("apply creates .bundle/config with the preset cooldown", () => {
  const { files, result } = apply(bundlerBase(), loadPolicy({}), null);
  expect(result.skipped).toBeNull();
  expect(result.written).toContain("/r/.bundle/config");
  expect(files["/r/.bundle/config"]).toContain('BUNDLE_COOLDOWN: "1"');
});

test("apply writes the strict preset cooldown in days", () => {
  const strict = loadPolicy({ flags: { preset: "strict" } });
  const { files } = apply(bundlerBase(), strict);
  expect(files["/r/.bundle/config"]).toContain('BUNDLE_COOLDOWN: "14"');
});

test("apply preserves unrelated .bundle/config keys", () => {
  const { files } = apply(
    bundlerFiles(
      '---\nBUNDLE_PATH: "vendor/bundle"\nBUNDLE_WITHOUT: "development:test"\nBUNDLE_COOLDOWN: "0"\n'
    )
  );
  const config = parseBundleConfig(files["/r/.bundle/config"] as string);
  expect(config).toEqual({
    BUNDLE_COOLDOWN: "1",
    BUNDLE_PATH: "vendor/bundle",
    BUNDLE_WITHOUT: "development:test",
  });
});

test("apply preserves a BUNDLE_MIRROR__ key that contains colons", () => {
  const { files } = apply(
    bundlerFiles(
      '---\nBUNDLE_MIRROR__HTTPS://RUBYGEMS.ORG/: "https://mirror.internal"\nBUNDLE_COOLDOWN: "0"\n'
    )
  );
  const config = parseBundleConfig(files["/r/.bundle/config"] as string);
  expect(config).toEqual({
    BUNDLE_COOLDOWN: "1",
    "BUNDLE_MIRROR__HTTPS://RUBYGEMS.ORG/": "https://mirror.internal",
  });
});

test("apply reads a CRLF .bundle/config without duplicating keys", () => {
  const { files } = apply(
    bundlerFiles(
      '---\r\nBUNDLE_PATH: "vendor/bundle"\r\nBUNDLE_COOLDOWN: "0"\r\n'
    )
  );
  const config = parseBundleConfig(files["/r/.bundle/config"] as string);
  expect(config).toEqual({
    BUNDLE_COOLDOWN: "1",
    BUNDLE_PATH: "vendor/bundle",
  });
});

test("apply never writes a lockfile for bundler lockfile.missing", () => {
  const files: Record<string, string> = {
    "/r/.bundle/config": '---\nBUNDLE_COOLDOWN: "1"\n',
    "/r/Gemfile": 'source "https://rubygems.org"\n',
  };
  const { result } = apply(files);
  expect(result.written).toEqual([]);
  expect(files["/r/Gemfile.lock"]).toBeUndefined();
});

test("apply is idempotent for bundler", () => {
  const files = bundlerBase();
  apply(files);
  const first = files["/r/.bundle/config"];
  apply(files);
  expect(files["/r/.bundle/config"]).toBe(first as string);
});

// --- discover ---------------------------------------------------------------

test("a Gemfile.lock without a Gemfile is not a bundler project", () => {
  const projects = discoverProjects(
    "/rb",
    memoryFs({
      "/rb/Gemfile.lock": "GEM\n",
      "/rb/package-lock.json": `{"lockfileVersion":3}`,
      "/rb/package.json": `{"name":"app","packageManager":"npm@10.9.0"}`,
    })
  );
  expect(projects[0]?.managers.some((m) => m.name === "bundler")).toBe(false);
});

test("bundler configPath is null when .bundle/config is absent", () => {
  const projects = discoverProjects(
    "/rb",
    memoryFs({
      "/rb/Gemfile": 'source "https://rubygems.org"\n',
      "/rb/Gemfile.lock": "GEM\n",
    })
  );
  const bundler = projects[0]?.managers.find((m) => m.name === "bundler");
  expect(bundler?.configPath).toBeNull();
  expect(bundler?.lockfilePath).toBe("/rb/Gemfile.lock");
});

test("bundler coexists with a JS primary in the same root", () => {
  const projects = discoverProjects(
    "/app",
    memoryFs({
      "/app/Gemfile": 'source "https://rubygems.org"\n',
      "/app/Gemfile.lock": "GEM\n",
      "/app/package-lock.json": `{"lockfileVersion":3}`,
      "/app/package.json": `{"name":"app","packageManager":"npm@10.9.0"}`,
    })
  );
  const names = projects[0]?.managers
    .filter((m) => m.role === "primary")
    .map((m) => m.name)
    .toSorted();
  expect(names).toEqual(["bundler", "npm"]);
});

// --- advisories -------------------------------------------------------------

const advisoryProject: Project = {
  gitRoot: "/rb",
  managers: [
    {
      configPath: "/rb/.bundle/config",
      lockfilePath: "/rb/Gemfile.lock",
      manifestPath: "/rb/Gemfile",
      name: "bundler",
      role: "primary",
    },
  ],
  root: "/rb",
};

const runBundleAudit = (
  slot: string,
  stdout: string,
  code = 1
): ReturnType<typeof auditAdvisories> =>
  auditAdvisories(advisoryProject, loadPolicy({}), {
    cache: createFsCache(path.join(cacheRoot, slot), () => 1000, 86_400_000),
    digest: () => `bundler-${slot}`,
    now: () => 1000,
    readFile: () => "lock",
    run: () => Promise.resolve({ code, stderr: "", stdout }),
  });

test("bundle-audit with no results yields no advisory findings", async () => {
  const result = await runBundleAudit(
    "clean",
    JSON.stringify({ results: [], version: "0.9.3" }),
    0
  );
  expect(result.findings.filter((f) => f.kind === "advisory")).toEqual([]);
});

test("bundle-audit reports every vulnerable gem in results", async () => {
  const result = await runBundleAudit(
    "many",
    JSON.stringify({
      results: [
        {
          advisory: {
            criticality: "high",
            id: "CVE-2015-7576",
            patched_versions: [">= 4.2.5.1"],
            title: "Possible XSS in rails",
          },
          gem: { name: "rails", version: "4.2.0" },
          type: "unpatched_gem",
        },
        {
          advisory: {
            criticality: "medium",
            id: "CVE-2020-8130",
            patched_versions: [">= 13.0.1"],
            title: "Command injection in rake",
          },
          gem: { name: "rake", version: "12.3.0" },
          type: "unpatched_gem",
        },
      ],
      version: "0.9.3",
    })
  );
  const advisories = result.findings
    .filter((f) => f.kind === "advisory")
    .map((f) => `${f.package}@${f.currentVersion}:${f.severity}`)
    .toSorted();
  expect(advisories).toEqual(["rails@4.2.0:high", "rake@12.3.0:moderate"]);
});

test("bundle-audit unsupported gem versions do not become a fixVersion", async () => {
  const result = await runBundleAudit(
    "nofix",
    JSON.stringify({
      results: [
        {
          advisory: {
            criticality: "high",
            id: "CVE-2099-0001",
            patched_versions: [],
            title: "No patch available",
          },
          gem: { name: "nokogiri", version: "1.10.0" },
          type: "unpatched_gem",
        },
      ],
      version: "0.9.3",
    })
  );
  const advisory = result.findings.find((f) => f.kind === "advisory");
  expect(advisory?.package).toBe("nokogiri");
  expect(advisory?.fixVersion).toBeUndefined();
});

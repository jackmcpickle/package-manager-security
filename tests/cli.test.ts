import { afterAll, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { applySettings } from "../src/apply-settings";
import { auditPath } from "../src/audit";
import { createFsCache } from "../src/cache";
import { createLineReader, run } from "../src/cli";
import type { DetectedManager, Finding, Project } from "../src/domain";
import { loadPolicy } from "../src/policy";

const cacheDir = mkdtempSync(join(tmpdir(), "pmsec-task10-cache-"));
afterAll(() => {
  rmSync(cacheDir, { recursive: true, force: true });
});

const CRITICAL_NPM_AUDIT = JSON.stringify({
  advisories: {
    "1": {
      module_name: "left-pad",
      severity: "critical",
      github_advisory_id: "GHSA-crit",
      title: "critical left-pad advisory",
      findings: [{ version: "1.0.0" }],
    },
  },
});

const CLEAN_NPM_FILES: Record<string, string> = {
  "/p/package.json": `{"name":"x","packageManager":"npm@10.9.0"}`,
  "/p/package-lock.json": `{"lockfileVersion":3}`,
  "/p/.npmrc":
    "ignore-scripts=true\naudit=true\naudit-level=high\nmin-release-age=7\nregistry=https://registry.npmjs.org/\n",
};

const POETRY_FILES: Record<string, string> = {
  "/py/pyproject.toml": `[tool.poetry]\nname = "x"\nversion = "0.1.0"\n`,
  "/py/poetry.lock": "# poetry lock\n",
};

function memoryFs(
  files: Record<string, string>,
  extraDirs: string[] = [],
): {
  readDir: (dir: string) => string[];
  readFile: (path: string) => string | null;
  isDir: (path: string) => boolean;
} {
  const dirs = new Set<string>(["/", ...extraDirs]);
  const addDir = (dir: string) => {
    let current = dir;
    while (current && current !== "/") {
      dirs.add(current);
      current = dirname(current);
    }
  };
  for (const file of Object.keys(files)) addDir(dirname(file));
  for (const dir of extraDirs) addDir(dir);

  return {
    readDir(dir: string): string[] {
      const prefix = dir.endsWith("/") ? dir : `${dir}/`;
      const names = new Set<string>();
      for (const path of [...dirs, ...Object.keys(files)]) {
        if (!path.startsWith(prefix)) continue;
        const name = path.slice(prefix.length).split("/")[0];
        if (name) names.add(name);
      }
      return [...names];
    },
    readFile(path: string): string | null {
      return files[path] ?? null;
    },
    isDir(path: string): boolean {
      return dirs.has(path);
    },
  };
}

function emptyAuditRun() {
  return async () => ({ code: 0, stdout: `{"advisories":{}}`, stderr: "" });
}

test("pmsec with no args prints usage and exits 2", async () => {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const result = await run([], {
    stdout: { write: (s: string) => stdout.push(s) },
    stderr: { write: (s: string) => stderr.push(s) },
    cwd: process.cwd(),
    env: {},
  });
  expect(result.exitCode).toBe(2);
  expect(stderr.join("")).toContain("Usage: pmsec");
});

test("audit of a fixture repo with open npm scripts exits 1 and lists the finding", async () => {
  const root = join(import.meta.dir, "fixtures/discover/many-repos/alpha");
  const stdout: string[] = [];
  const stderr: string[] = [];
  const result = await run(["audit", root], {
    stdout: { write: (s: string) => stdout.push(s) },
    stderr: { write: (s: string) => stderr.push(s) },
    cwd: import.meta.dir,
    env: { HOME: join(import.meta.dir, "fixtures/empty-home") },
    run: emptyAuditRun(),
    which: () => "/usr/bin/npm",
    cache: createFsCache(join(cacheDir, "alpha"), () => 1_000, 86_400_000),
  });
  expect(result.exitCode).toBe(1);
  expect(stdout.join("")).toContain("scripts.unrestricted");
});

test("CLI --preset wins over repo .pmsec.toml preset", async () => {
  const root = join(import.meta.dir, "fixtures/audit/flag-wins");
  const stdout: string[] = [];
  const stderr: string[] = [];
  const result = await run(["audit", root, "--preset", "relaxed"], {
    stdout: { write: (s: string) => stdout.push(s) },
    stderr: { write: (s: string) => stderr.push(s) },
    cwd: import.meta.dir,
    env: { HOME: join(import.meta.dir, "fixtures/empty-home") },
    run: emptyAuditRun(),
    which: () => "/usr/bin/npm",
    cache: createFsCache(join(cacheDir, "flag-wins"), () => 1_000, 86_400_000),
  });
  expect(stdout.join("")).not.toContain("scripts.unrestricted");
  expect(result.exitCode).toBe(0);
});

test("--refresh and --no-cache bypass the lockfile digest cache", async () => {
  const root = join(import.meta.dir, "fixtures/discover/many-repos/alpha");
  const cache = createFsCache(join(cacheDir, "cache-flags"), () => 1_000, 86_400_000);
  let auditCalls = 0;
  const depsFor = () => ({
    stdout: { write: () => undefined },
    stderr: { write: () => undefined },
    cwd: import.meta.dir,
    env: { HOME: join(import.meta.dir, "fixtures/empty-home") },
    run: async () => {
      auditCalls += 1;
      return { code: 0, stdout: `{"advisories":{}}`, stderr: "" };
    },
    which: () => "/usr/bin/npm",
    cache,
  });

  await run(["audit", root], depsFor());
  expect(auditCalls).toBe(1);
  await run(["audit", root], depsFor());
  expect(auditCalls).toBe(1);

  await run(["audit", root, "--refresh"], depsFor());
  expect(auditCalls).toBe(2);
  await run(["audit", root, "--no-cache"], depsFor());
  expect(auditCalls).toBe(3);

  // --refresh re-primed the cache; --no-cache must not have written it.
  await run(["audit", root], depsFor());
  expect(auditCalls).toBe(3);
});

test("auditPath critical npm audit JSON is an advisory and exits 1", async () => {
  const fs = memoryFs(CLEAN_NPM_FILES, ["/p/.git"]);
  const result = await auditPath("/p", {
    policy: loadPolicy({}),
    apply: false,
    applyAdvisories: false,
    interactive: false,
    concurrency: 4,
    deps: {
      ...fs,
      which: () => "/usr/bin/npm",
      run: async () => ({ code: 1, stdout: CRITICAL_NPM_AUDIT, stderr: "" }),
      cache: createFsCache(cacheDir, () => 1_000, 86_400_000),
      now: () => 1_000,
      digest: () => "npm-critical",
    },
  });
  const findings = result.projects.flatMap((row) => row.findings);
  expect(result.exitCode).toBe(1);
  expect(findings.some((finding) => finding.kind === "advisory")).toBe(true);
});

test("auditPath missing binary skips advisories and exits 0 when settings are clean", async () => {
  const fs = memoryFs(CLEAN_NPM_FILES, ["/p/.git"]);
  let ran = 0;
  const result = await auditPath("/p", {
    policy: loadPolicy({}),
    apply: false,
    applyAdvisories: false,
    interactive: false,
    concurrency: 4,
    deps: {
      ...fs,
      which: () => null,
      run: async () => {
        ran += 1;
        return { code: 1, stdout: CRITICAL_NPM_AUDIT, stderr: "" };
      },
      cache: createFsCache(join(cacheDir, "missing"), () => 1_000, 86_400_000),
      now: () => 1_000,
      digest: () => "npm-missing",
    },
  });
  const findings = result.projects.flatMap((row) => row.findings);
  expect(ran).toBe(0);
  expect(result.exitCode).toBe(0);
  expect(findings.some((finding) => finding.code === "pm.missing-binary")).toBe(true);
  expect(findings.some((finding) => finding.kind === "advisory")).toBe(false);
});

test("auditPath runOsv high advisory exits 1", async () => {
  const fs = memoryFs(POETRY_FILES, ["/py/.git"]);
  const osvFinding: Finding = {
    kind: "advisory",
    code: "GHSA-osv",
    message: "osv high advisory",
    severity: "high",
    path: "/py/poetry.lock",
    fixable: false,
    manager: "poetry",
  };
  const result = await auditPath("/py", {
    policy: loadPolicy({}),
    apply: false,
    applyAdvisories: false,
    interactive: false,
    concurrency: 4,
    deps: {
      ...fs,
      which: () => null,
      run: emptyAuditRun(),
      runOsv: async () => [osvFinding],
      cache: createFsCache(join(cacheDir, "osv"), () => 1_000, 86_400_000),
      now: () => 1_000,
      digest: () => "poetry-osv",
    },
  });
  const findings = result.projects.flatMap((row) => row.findings);
  expect(result.exitCode).toBe(1);
  expect(findings.some((finding) => finding.kind === "advisory" && finding.severity === "high")).toBe(
    true,
  );
});

test("--json prints the full result object with advisory findings", async () => {
  mkdirSync(join(import.meta.dir, "fixtures/discover/many-repos/alpha/.git"), { recursive: true });
  const root = join(import.meta.dir, "fixtures/discover/many-repos/alpha");
  const stdout: string[] = [];
  const stderr: string[] = [];
  const result = await run(["audit", root, "--json"], {
    stdout: { write: (s: string) => stdout.push(s) },
    stderr: { write: (s: string) => stderr.push(s) },
    cwd: import.meta.dir,
    env: { HOME: join(import.meta.dir, "fixtures/empty-home") },
    run: async () => ({ code: 1, stdout: CRITICAL_NPM_AUDIT, stderr: "" }),
    which: () => "/usr/bin/npm",
    cache: createFsCache(join(cacheDir, "json"), () => 1_000, 86_400_000),
  });
  const parsed = JSON.parse(stdout.join("")) as {
    exitCode: number;
    projects: Array<{ findings: Array<{ kind: string }> }>;
  };
  expect(result.exitCode).toBe(1);
  expect(parsed.exitCode).toBe(1);
  expect(parsed.projects.length).toBeGreaterThan(0);
  expect(parsed.projects.some((row) => row.findings.some((finding) => finding.kind === "advisory"))).toBe(
    true,
  );
});

test("--json --sarif --report emit the same finalized finding codes", async () => {
  mkdirSync(join(import.meta.dir, "fixtures/discover/many-repos/alpha/.git"), { recursive: true });
  const root = join(import.meta.dir, "fixtures/discover/many-repos/alpha");
  const home = { HOME: join(import.meta.dir, "fixtures/empty-home") };
  const cache = createFsCache(join(cacheDir, "reports"), () => 1_000, 86_400_000);
  const written: Record<string, string> = {};
  const jsonOut: string[] = [];
  const sarifOut: string[] = [];
  const mdOut: string[] = [];

  await run(["audit", root, "--json"], {
    stdout: { write: (s: string) => jsonOut.push(s) },
    stderr: { write: () => undefined },
    cwd: import.meta.dir,
    env: home,
    run: emptyAuditRun(),
    which: () => "/usr/bin/npm",
    cache,
    writeFile: (path, body) => {
      written[path] = body;
    },
  });
  await run(["audit", root, "--sarif"], {
    stdout: { write: (s: string) => sarifOut.push(s) },
    stderr: { write: () => undefined },
    cwd: import.meta.dir,
    env: home,
    run: emptyAuditRun(),
    which: () => "/usr/bin/npm",
    cache,
    writeFile: (path, body) => {
      written[path] = body;
    },
  });
  await run(["audit", root, "--report", "/out/report.md"], {
    stdout: { write: (s: string) => mdOut.push(s) },
    stderr: { write: () => undefined },
    cwd: import.meta.dir,
    env: home,
    run: emptyAuditRun(),
    which: () => "/usr/bin/npm",
    cache,
    writeFile: (path, body) => {
      written[path] = body;
    },
  });

  expect(jsonOut.join("")).toContain("scripts.unrestricted");
  expect(sarifOut.join("")).toContain("scripts.unrestricted");
  expect(written["/out/report.md"]).toContain("scripts.unrestricted");
  expect(Object.keys(written).filter((path) => path.endsWith(".md"))).toEqual(["/out/report.md"]);
  expect(mdOut.join("")).not.toMatch(/^# /);
});

test("interactive fake prompt can choose settings only", async () => {
  mkdirSync(join(import.meta.dir, "fixtures/discover/many-repos/alpha/.git"), { recursive: true });
  const root = join(import.meta.dir, "fixtures/discover/many-repos/alpha");
  const written: Record<string, string> = {};
  const prompts: Array<{ settingsCount: number; advisoryCount: number }> = [];
  const installCalls: string[][] = [];
  const result = await run(["audit", root, "-i"], {
    stdout: { write: () => undefined },
    stderr: { write: () => undefined },
    cwd: import.meta.dir,
    env: { HOME: join(import.meta.dir, "fixtures/empty-home") },
    run: async (argv) => {
      if (!argv.includes("audit")) installCalls.push(argv);
      return { code: 0, stdout: `{"advisories":{}}`, stderr: "" };
    },
    which: () => "/usr/bin/npm",
    cache: createFsCache(join(cacheDir, "interactive"), () => 1_000, 86_400_000),
    writeFile: (path, body) => {
      written[path] = body;
    },
    gitStatus: () => "clean",
    prompt: async ({ project, settingsCount, advisoryCount }) => {
      expect(project.root).toContain("alpha");
      prompts.push({ settingsCount, advisoryCount });
      return "settings" as const;
    },
  });
  expect(prompts).toHaveLength(1);
  expect(prompts[0]!.settingsCount).toBeGreaterThan(0);
  expect(Object.values(written).some((body) => body.includes("ignore-scripts=true"))).toBe(true);
  expect(installCalls).toEqual([]);
  expect(result.exitCode).not.toBe(2);
});

test("interactive -i uses default stdin prompt when none is injected", async () => {
  mkdirSync(join(import.meta.dir, "fixtures/discover/many-repos/alpha/.git"), { recursive: true });
  const root = join(import.meta.dir, "fixtures/discover/many-repos/alpha");
  const written: Record<string, string> = {};
  const stdout: string[] = [];
  const result = await run(["audit", root, "-i"], {
    stdout: { write: (s: string) => stdout.push(s) },
    stderr: { write: () => undefined },
    cwd: import.meta.dir,
    env: { HOME: join(import.meta.dir, "fixtures/empty-home") },
    run: emptyAuditRun(),
    which: () => "/usr/bin/npm",
    cache: createFsCache(join(cacheDir, "default-prompt"), () => 1_000, 86_400_000),
    writeFile: (path, body) => {
      written[path] = body;
    },
    gitStatus: () => "clean",
    readLine: async () => "settings",
  });
  expect(stdout.join("")).toMatch(/settings|advisories|both|skip/i);
  expect(Object.values(written).some((body) => body.includes("ignore-scripts=true"))).toBe(true);
  expect(result.exitCode).not.toBe(2);
});

test("auditPath advisory runner dying yields exit code 2 (incomplete)", async () => {
  const fs = memoryFs(CLEAN_NPM_FILES, ["/p/.git"]);
  const result = await auditPath("/p", {
    policy: loadPolicy({}),
    apply: false,
    applyAdvisories: false,
    interactive: false,
    concurrency: 4,
    deps: {
      ...fs,
      which: () => "/usr/bin/npm",
      run: async () => ({ code: 2, stdout: "", stderr: "audit engine crashed" }),
      cache: createFsCache(join(cacheDir, "incomplete"), () => 1_000, 86_400_000),
      now: () => 1_000,
      digest: () => "npm-incomplete",
    },
  });
  expect(result.exitCode).toBe(2);
});

test("auditPath below-gate advisory does not fail the standard preset gate", async () => {
  const fs = memoryFs(CLEAN_NPM_FILES, ["/p/.git"]);
  const LOW_NPM_AUDIT = JSON.stringify({
    advisories: {
      "1": {
        module_name: "left-pad",
        severity: "low",
        github_advisory_id: "GHSA-low",
        title: "left-pad low advisory",
        findings: [{ version: "1.0.0" }],
      },
    },
  });
  const result = await auditPath("/p", {
    policy: loadPolicy({}),
    apply: false,
    applyAdvisories: false,
    interactive: false,
    concurrency: 4,
    deps: {
      ...fs,
      which: () => "/usr/bin/npm",
      run: async () => ({ code: 1, stdout: LOW_NPM_AUDIT, stderr: "" }),
      cache: createFsCache(join(cacheDir, "below-gate"), () => 1_000, 86_400_000),
      now: () => 1_000,
      digest: () => "npm-below-gate",
    },
  });
  const findings = result.projects.flatMap((row) => row.findings);
  expect(findings.some((finding) => finding.kind === "advisory" && finding.severity === "low")).toBe(
    true,
  );
  expect(result.exitCode).toBe(0);
});

test("audit of a directory with zero discovered projects exits 2", async () => {
  const root = join(import.meta.dir, "fixtures/empty-root");
  const stdout: string[] = [];
  const stderr: string[] = [];
  const result = await run(["audit", root], {
    stdout: { write: (s: string) => stdout.push(s) },
    stderr: { write: (s: string) => stderr.push(s) },
    cwd: import.meta.dir,
    env: { HOME: join(import.meta.dir, "fixtures/empty-home") },
    run: emptyAuditRun(),
    which: () => "/usr/bin/npm",
    cache: createFsCache(join(cacheDir, "empty-root"), () => 1_000, 86_400_000),
  });
  expect(result.exitCode).toBe(2);
});

test("applySettings with --commit calls gitCommit exactly once with the repo root", () => {
  const project: Project = {
    root: "/repo",
    gitRoot: "/repo",
    managers: [
      {
        name: "npm",
        role: "primary",
        manifestPath: "/repo/package.json",
        lockfilePath: "/repo/package-lock.json",
        configPath: "/repo/.npmrc",
      } satisfies DetectedManager,
    ],
  };
  const finding: Finding = {
    kind: "settings",
    code: "scripts.unrestricted",
    message: "scripts are not restricted",
    severity: "high",
    path: "/repo/.npmrc",
    fixable: true,
    manager: "npm",
  };
  const written: Record<string, string> = {};
  const commitCalls: Array<{ root: string; message: string; files: string[] }> = [];
  const result = applySettings(project, [finding], loadPolicy({}), {
    readFile: (path) => (path === "/repo/.npmrc" ? "" : null),
    writeFile: (path, body) => {
      written[path] = body;
    },
    gitStatus: () => "clean",
    gitCommit: (root, message, files) => {
      commitCalls.push({ root, message, files });
      return true;
    },
    force: false,
    commit: true,
  });
  expect(result.committed).toBe(true);
  expect(commitCalls).toHaveLength(1);
  expect(commitCalls[0]!.root).toBe("/repo");
  expect(Object.keys(written)).toEqual(["/repo/.npmrc"]);
});

test("stdin line reader keeps leftover lines after the first newline", async () => {
  const chunks: Array<string | null> = ["settings\nskip\n"];
  const readLine = createLineReader(async () => chunks.shift() ?? null);
  expect(await readLine()).toBe("settings");
  expect(await readLine()).toBe("skip");
  expect(chunks).toEqual([]);
});

test("--apply on a dirty tree warns on stderr and exits 2", async () => {
  const root = join(import.meta.dir, "fixtures/discover/many-repos/alpha");
  const stdout: string[] = [];
  const stderr: string[] = [];
  const result = await run(["audit", root, "--apply"], {
    stdout: { write: (s: string) => stdout.push(s) },
    stderr: { write: (s: string) => stderr.push(s) },
    cwd: import.meta.dir,
    env: { HOME: join(import.meta.dir, "fixtures/empty-home") },
    run: emptyAuditRun(),
    which: () => "/usr/bin/npm",
    cache: createFsCache(join(cacheDir, "dirty-warn"), () => 1_000, 86_400_000),
    gitStatus: () => "dirty",
    writeFile: () => {
      throw new Error("must not write on a dirty tree");
    },
  });
  expect(result.exitCode).toBe(2);
  const err = stderr.join("");
  expect(err).toContain("apply skipped");
  expect(err).toContain("dirty");
  expect(err).toContain("--force");
  expect(err).toContain(root);
});

const INFO_ONLY_NPM: Record<string, string> = {
  "/p/package.json": `{"name":"x"}`,
  "/p/package-lock.json": `{"lockfileVersion":3}`,
  "/p/.npmrc":
    "ignore-scripts=true\naudit=true\naudit-level=high\nmin-release-age=7\n",
};

const CLEAN_UV_FILES: Record<string, string> = {
  "/uv/pyproject.toml": `[tool.uv]\nexclude-newer = 30\n`,
  "/uv/uv.lock": `version = 1\n`,
};

function advisoryJson(severity: string): string {
  return JSON.stringify({
    advisories: {
      "1": {
        module_name: "left-pad",
        severity,
        github_advisory_id: `GHSA-${severity}`,
        title: `${severity} left-pad advisory`,
        findings: [{ version: "1.0.0" }],
      },
    },
  });
}

test("info-only settings findings do not fail the standard gate", async () => {
  const fs = memoryFs(INFO_ONLY_NPM, ["/p/.git"]);
  const result = await auditPath("/p", {
    policy: loadPolicy({}),
    apply: false,
    applyAdvisories: false,
    interactive: false,
    concurrency: 4,
    deps: {
      ...fs,
      which: () => "/usr/bin/npm",
      run: emptyAuditRun(),
      cache: createFsCache(join(cacheDir, "info-only"), () => 1_000, 86_400_000),
      now: () => 1_000,
      digest: () => "npm-info-only",
    },
  });
  const findings = result.projects.flatMap((row) => row.findings);
  expect(findings.some((f) => f.code === "registry.unpinned" && f.severity === "info")).toBe(true);
  expect(findings.some((f) => f.code === "pm.unpinned" && f.severity === "info")).toBe(true);
  expect(result.exitCode).toBe(0);
});

test("standard lists a moderate advisory but does not fail; strict does", async () => {
  const fs = memoryFs(CLEAN_NPM_FILES, ["/p/.git"]);
  const moderate = advisoryJson("moderate");
  const standard = await auditPath("/p", {
    policy: loadPolicy({}),
    apply: false,
    applyAdvisories: false,
    interactive: false,
    concurrency: 4,
    deps: {
      ...fs,
      which: () => "/usr/bin/npm",
      run: async () => ({ code: 1, stdout: moderate, stderr: "" }),
      cache: createFsCache(join(cacheDir, "mod-std"), () => 1_000, 86_400_000),
      now: () => 1_000,
      digest: () => "npm-moderate-std",
    },
  });
  expect(
    standard.projects
      .flatMap((row) => row.findings)
      .some((f) => f.kind === "advisory" && f.severity === "moderate"),
  ).toBe(true);
  expect(standard.exitCode).toBe(0);

  const strict = await auditPath("/p", {
    policy: loadPolicy({ flags: { preset: "strict" } }),
    apply: false,
    applyAdvisories: false,
    interactive: false,
    concurrency: 4,
    deps: {
      ...fs,
      which: () => "/usr/bin/npm",
      run: async () => ({ code: 1, stdout: moderate, stderr: "" }),
      cache: createFsCache(join(cacheDir, "mod-strict"), () => 1_000, 86_400_000),
      now: () => 1_000,
      digest: () => "npm-moderate-strict",
    },
  });
  expect(strict.exitCode).toBe(1);
});

test("relaxed fails only critical advisories; a high advisory is listed and exits 0", async () => {
  const fs = memoryFs(CLEAN_NPM_FILES, ["/p/.git"]);
  const result = await auditPath("/p", {
    policy: loadPolicy({ flags: { preset: "relaxed" } }),
    apply: false,
    applyAdvisories: false,
    interactive: false,
    concurrency: 4,
    deps: {
      ...fs,
      which: () => "/usr/bin/npm",
      run: async () => ({ code: 1, stdout: advisoryJson("high"), stderr: "" }),
      cache: createFsCache(join(cacheDir, "relaxed-high"), () => 1_000, 86_400_000),
      now: () => 1_000,
      digest: () => "npm-relaxed-high",
    },
  });
  expect(
    result.projects
      .flatMap((row) => row.findings)
      .some((f) => f.kind === "advisory" && f.severity === "high"),
  ).toBe(true);
  expect(result.exitCode).toBe(0);
});

test("uv deprecation fails even under the relaxed preset", async () => {
  const fs = memoryFs(CLEAN_UV_FILES, ["/uv/.git"]);
  const result = await auditPath("/uv", {
    policy: loadPolicy({ flags: { preset: "relaxed" } }),
    apply: false,
    applyAdvisories: false,
    interactive: false,
    concurrency: 4,
    deps: {
      ...fs,
      which: (binary) => (binary === "uv" ? "/usr/bin/uv" : null),
      run: async () => ({
        code: 0,
        stdout: JSON.stringify([{ name: "oldpkg", version: "1.0.0", status: "deprecated" }]),
        stderr: "",
      }),
      cache: createFsCache(join(cacheDir, "uv-depr"), () => 1_000, 86_400_000),
      now: () => 1_000,
      digest: () => "uv-deprecated",
    },
  });
  expect(result.projects.flatMap((row) => row.findings).some((f) => f.kind === "deprecated")).toBe(
    true,
  );
  expect(result.exitCode).toBe(1);
});

test("interactive skip writes nothing", async () => {
  mkdirSync(join(import.meta.dir, "fixtures/discover/many-repos/alpha/.git"), { recursive: true });
  const root = join(import.meta.dir, "fixtures/discover/many-repos/alpha");
  const result = await run(["audit", root, "-i"], {
    stdout: { write: () => undefined },
    stderr: { write: () => undefined },
    cwd: import.meta.dir,
    env: { HOME: join(import.meta.dir, "fixtures/empty-home") },
    run: emptyAuditRun(),
    which: () => "/usr/bin/npm",
    cache: createFsCache(join(cacheDir, "interactive-skip"), () => 1_000, 86_400_000),
    writeFile: () => {
      throw new Error("skip must not write");
    },
    gitStatus: () => "clean",
    prompt: async () => "skip" as const,
  });
  expect(result.exitCode).toBe(1);
});

test("--apply on a poetry project never runs uv migrate commands", async () => {
  mkdirSync(join(import.meta.dir, "fixtures/discover/poetry-app/.git"), { recursive: true });
  const root = join(import.meta.dir, "fixtures/discover/poetry-app");
  const calls: string[][] = [];
  const written: string[] = [];
  await run(["audit", root, "--apply"], {
    stdout: { write: () => undefined },
    stderr: { write: () => undefined },
    cwd: import.meta.dir,
    env: { HOME: join(import.meta.dir, "fixtures/empty-home") },
    run: async (argv) => {
      calls.push(argv);
      return { code: 0, stdout: "{}", stderr: "" };
    },
    which: () => "/usr/bin/uv",
    cache: createFsCache(join(cacheDir, "no-migrate"), () => 1_000, 86_400_000),
    writeFile: (path) => {
      written.push(path);
    },
    gitStatus: () => "clean",
  });
  expect(calls.every((argv) => argv[0] !== "uv")).toBe(true);
  expect(written.some((path) => path.endsWith("uv.toml") || path.endsWith("uv.lock"))).toBe(false);
});

test("XDG_CONFIG_HOME wins over ~/.config/pmsec when CLI loads user config", async () => {
  mkdirSync(join(import.meta.dir, "fixtures/discover/many-repos/alpha/.git"), { recursive: true });
  const root = join(import.meta.dir, "fixtures/discover/many-repos/alpha");
  const home = mkdtempSync(join(tmpdir(), "pmsec-home-"));
  const xdg = mkdtempSync(join(tmpdir(), "pmsec-xdg-"));
  mkdirSync(join(home, ".config", "pmsec"), { recursive: true });
  mkdirSync(join(xdg, "pmsec"), { recursive: true });
  writeFileSync(join(home, ".config", "pmsec", "config.toml"), `preset = "standard"\n`);
  writeFileSync(join(xdg, "pmsec", "config.toml"), `preset = "relaxed"\n`);
  const stdout: string[] = [];
  const result = await run(["audit", root], {
    stdout: { write: (s: string) => stdout.push(s) },
    stderr: { write: () => undefined },
    cwd: import.meta.dir,
    env: { HOME: home, XDG_CONFIG_HOME: xdg },
    run: emptyAuditRun(),
    which: () => "/usr/bin/npm",
    cache: createFsCache(join(cacheDir, "xdg"), () => 1_000, 86_400_000),
  });
  expect(stdout.join("")).not.toContain("scripts.unrestricted");
  expect(result.exitCode).toBe(0);
  rmSync(home, { recursive: true, force: true });
  rmSync(xdg, { recursive: true, force: true });
});

test("omitting --report does not write a markdown file", async () => {
  mkdirSync(join(import.meta.dir, "fixtures/discover/many-repos/alpha/.git"), { recursive: true });
  const root = join(import.meta.dir, "fixtures/discover/many-repos/alpha");
  const written: string[] = [];
  await run(["audit", root], {
    stdout: { write: () => undefined },
    stderr: { write: () => undefined },
    cwd: import.meta.dir,
    env: { HOME: join(import.meta.dir, "fixtures/empty-home") },
    run: emptyAuditRun(),
    which: () => "/usr/bin/npm",
    cache: createFsCache(join(cacheDir, "no-report"), () => 1_000, 86_400_000),
    writeFile: (path) => {
      written.push(path);
    },
  });
  expect(written.filter((path) => path.endsWith(".md"))).toEqual([]);
});

test("--report creates missing parent directories and writes markdown", async () => {
  mkdirSync(join(import.meta.dir, "fixtures/discover/many-repos/alpha/.git"), { recursive: true });
  const root = join(import.meta.dir, "fixtures/discover/many-repos/alpha");
  const outDir = mkdtempSync(join(tmpdir(), "pmsec-report-"));
  const reportPath = join(outDir, "nested", "deep", "report.md");
  const result = await run(["audit", root, "--report", reportPath], {
    stdout: { write: () => undefined },
    stderr: { write: () => undefined },
    cwd: import.meta.dir,
    env: { HOME: join(import.meta.dir, "fixtures/empty-home") },
    run: emptyAuditRun(),
    which: () => "/usr/bin/npm",
    cache: createFsCache(join(cacheDir, "report-mkdir"), () => 1_000, 86_400_000),
  });
  expect(existsSync(reportPath)).toBe(true);
  expect(readFileSync(reportPath, "utf8")).toContain("scripts.unrestricted");
  expect(result.exitCode).toBe(1);
  rmSync(outDir, { recursive: true, force: true });
});

test("--concurrency 1 runs advisory audits serially; default and invalid values may overlap", async () => {
  mkdirSync(join(import.meta.dir, "fixtures/discover/many-repos/alpha/.git"), { recursive: true });
  mkdirSync(join(import.meta.dir, "fixtures/discover/many-repos/beta/.git"), { recursive: true });
  const root = join(import.meta.dir, "fixtures/discover/many-repos");

  const maxFor = async (extra: string[]) => {
    let inFlight = 0;
    let max = 0;
    await run(["audit", root, ...extra], {
      stdout: { write: () => undefined },
      stderr: { write: () => undefined },
      cwd: import.meta.dir,
      env: { HOME: join(import.meta.dir, "fixtures/empty-home") },
      run: async () => {
        inFlight += 1;
        max = Math.max(max, inFlight);
        await Bun.sleep(25);
        inFlight -= 1;
        return { code: 0, stdout: `{"advisories":{}}`, stderr: "" };
      },
      which: () => "/usr/bin/npm",
      cache: createFsCache(join(cacheDir, `conc-${extra.join("-") || "default"}`), () => 1_000, 86_400_000),
    });
    return max;
  };

  expect(await maxFor(["--concurrency", "1"])).toBe(1);
  expect(await maxFor([])).toBeGreaterThan(1);
  expect(await maxFor(["--concurrency", "0"])).toBeGreaterThan(1);
  expect(await maxFor(["--concurrency", "nope"])).toBeGreaterThan(1);
});

test("--apply --force --commit through run() writes on a dirty tree and commits", async () => {
  mkdirSync(join(import.meta.dir, "fixtures/discover/many-repos/alpha/.git"), { recursive: true });
  const root = join(import.meta.dir, "fixtures/discover/many-repos/alpha");
  const written: Record<string, string> = {};
  const commits: Array<{ root: string; files: string[] }> = [];
  const result = await run(["audit", root, "--apply", "--force", "--commit"], {
    stdout: { write: () => undefined },
    stderr: { write: () => undefined },
    cwd: import.meta.dir,
    env: { HOME: join(import.meta.dir, "fixtures/empty-home") },
    run: emptyAuditRun(),
    which: () => "/usr/bin/npm",
    cache: createFsCache(join(cacheDir, "force-commit"), () => 1_000, 86_400_000),
    writeFile: (path, body) => {
      written[path] = body;
    },
    gitStatus: () => "dirty",
    gitCommit: (gitRoot, _message, files) => {
      commits.push({ root: gitRoot, files });
      return true;
    },
  });
  expect(Object.values(written).some((body) => body.includes("ignore-scripts=true"))).toBe(true);
  expect(commits).toHaveLength(1);
  expect(commits[0]!.root).toBe(root);
  expect(result.exitCode).not.toBe(2);
});

test("two primaries with one missing binary still audit the other", async () => {
  const files: Record<string, string> = {
    ...CLEAN_NPM_FILES,
    "/p/pyproject.toml": `[tool.uv]\nexclude-newer = 30\n`,
    "/p/uv.lock": `version = 1\n`,
  };
  const fs = memoryFs(files, ["/p/.git"]);
  const calls: string[][] = [];
  const result = await auditPath("/p", {
    policy: loadPolicy({}),
    apply: false,
    applyAdvisories: false,
    interactive: false,
    concurrency: 4,
    deps: {
      ...fs,
      which: (binary) => (binary === "uv" ? "/usr/bin/uv" : null),
      run: async (argv) => {
        calls.push(argv);
        return {
          code: 0,
          stdout: JSON.stringify([{ name: "oldpkg", version: "1.0.0", status: "deprecated" }]),
          stderr: "",
        };
      },
      cache: createFsCache(join(cacheDir, "two-primary"), () => 1_000, 86_400_000),
      now: () => 1_000,
      digest: () => "two-primary",
    },
  });
  const findings = result.projects.flatMap((row) => row.findings);
  expect(findings.some((f) => f.code === "pm.missing-binary" && f.manager === "npm")).toBe(true);
  expect(findings.some((f) => f.kind === "deprecated")).toBe(true);
  expect(calls).toEqual([["uv", "audit", "--output-format", "json", "--frozen"]]);
});

test("stdout uses ANSI colors when color is enabled and none by default", async () => {
  const root = join(import.meta.dir, "fixtures/discover/many-repos/alpha");
  const colored: string[] = [];
  await run(["audit", root], {
    stdout: { write: (s: string) => colored.push(s) },
    stderr: { write: () => {} },
    cwd: import.meta.dir,
    env: { HOME: join(import.meta.dir, "fixtures/empty-home") },
    run: emptyAuditRun(),
    which: () => "/usr/bin/npm",
    cache: createFsCache(join(cacheDir, "color-on"), () => 1_000, 86_400_000),
    color: true,
  });
  expect(colored.join("")).toContain("\u001b[");
  expect(colored.join("")).toContain("scripts.unrestricted");

  const plain: string[] = [];
  await run(["audit", root], {
    stdout: { write: (s: string) => plain.push(s) },
    stderr: { write: () => {} },
    cwd: import.meta.dir,
    env: { HOME: join(import.meta.dir, "fixtures/empty-home") },
    run: emptyAuditRun(),
    which: () => "/usr/bin/npm",
    cache: createFsCache(join(cacheDir, "color-off"), () => 1_000, 86_400_000),
  });
  expect(plain.join("")).not.toContain("\u001b[");
});


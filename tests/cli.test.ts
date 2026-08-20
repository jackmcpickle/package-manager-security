import { afterAll, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { auditPath } from "../src/audit";
import { createFsCache } from "../src/cache";
import { createLineReader, run } from "../src/cli";
import type { Finding } from "../src/domain";
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
      return "settings";
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

test("stdin line reader keeps leftover lines after the first newline", async () => {
  const chunks: Array<string | null> = ["settings\nskip\n"];
  const readLine = createLineReader(async () => chunks.shift() ?? null);
  expect(await readLine()).toBe("settings");
  expect(await readLine()).toBe("skip");
  expect(chunks).toEqual([]);
});


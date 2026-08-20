import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import type { ApplyPrompt } from "./apply-advisories";
import { auditPath, defaultDigest, type AuditRun } from "./audit";
import { CACHE_TTL_MS, createFsCache, type Cache } from "./cache";
import type { ExitCode, Finding, PresetName } from "./domain";
import { loadPolicy } from "./policy";
import { formatHuman, formatJson, formatMarkdown, formatSarif } from "./report";

export async function run(
  argv: string[],
  deps?: {
    stdout: { write: (s: string) => unknown };
    stderr: { write: (s: string) => unknown };
    cwd: string;
    env: Record<string, string | undefined>;
    run?: AuditRun;
    runOsv?: (lockOrRequirements: string) => Promise<Finding[]>;
    which?: (binary: string) => string | null;
    cache?: Cache;
    now?: () => number;
    digest?: (lockfileBytes: string) => string;
    writeFile?: (path: string, body: string) => void;
    gitStatus?: (root: string) => "clean" | "dirty" | "not-git";
    gitCommit?: (root: string, message: string, files: string[]) => boolean;
    prompt?: ApplyPrompt;
    currentVersions?: Record<string, string>;
    fixVersions?: Record<string, string>;
  },
): Promise<{ exitCode: ExitCode }> {
  const stdout = deps?.stdout ?? process.stdout;
  const stderr = deps?.stderr ?? process.stderr;
  const cwd = deps?.cwd ?? process.cwd();
  const env = deps?.env ?? process.env;

  if (argv[0] !== "audit") {
    stderr.write("Usage: pmsec <command>\n");
    return { exitCode: 2 };
  }

  const flags = parseAuditArgs(argv.slice(1));

  const root = flags.path === undefined
    ? cwd
    : isAbsolute(flags.path)
      ? flags.path
      : join(cwd, flags.path);

  const policy = loadPolicy({
    userToml: readFile(userConfigPath(env)) ?? undefined,
    scanToml: readFile(join(root, ".pmsec.toml")) ?? undefined,
    flags: flags.preset === undefined ? undefined : { preset: flags.preset },
  });

  const now = deps?.now ?? Date.now;
  const result = await auditPath(root, {
    policy,
    apply: flags.apply,
    applyAdvisories: flags.applyAdvisories,
    interactive: flags.interactive,
    concurrency: flags.concurrency,
    flags: flags.preset === undefined ? undefined : { preset: flags.preset },
    force: flags.force,
    commit: flags.commit,
    allowMajors: flags.allowMajors,
    deps: {
      readFile,
      readDir,
      isDir,
      which: deps?.which ?? ((binary) => Bun.which(binary) ?? null),
      run: deps?.run ?? defaultRun,
      runOsv: deps?.runOsv ?? (async () => []),
      cache: deps?.cache ?? createFsCache(userCachePath(env), now, CACHE_TTL_MS),
      now,
      digest: deps?.digest ?? defaultDigest,
      writeFile: deps?.writeFile ?? writeFile,
      gitStatus: deps?.gitStatus ?? defaultGitStatus,
      gitCommit: deps?.gitCommit ?? defaultGitCommit,
      prompt: deps?.prompt,
      currentVersions: deps?.currentVersions,
      fixVersions: deps?.fixVersions,
    },
  });

  const write = deps?.writeFile ?? writeFile;
  if (flags.report !== undefined) {
    const reportPath = isAbsolute(flags.report) ? flags.report : join(cwd, flags.report);
    write(reportPath, formatMarkdown(result));
  }
  if (flags.json) stdout.write(formatJson(result));
  else if (flags.sarif) stdout.write(formatSarif(result));
  else stdout.write(formatHuman(result));
  return { exitCode: result.exitCode };
}

function parseAuditArgs(args: string[]): {
  path?: string;
  preset?: PresetName;
  apply: boolean;
  applyAdvisories: boolean;
  interactive: boolean;
  concurrency: number;
  json: boolean;
  sarif: boolean;
  report?: string;
  force: boolean;
  commit: boolean;
  allowMajors: boolean;
} {
  let path: string | undefined;
  let preset: PresetName | undefined;
  let apply = false;
  let applyAdvisories = false;
  let interactive = false;
  let concurrency = 4;
  let json = false;
  let sarif = false;
  let report: string | undefined;
  let force = false;
  let commit = false;
  let allowMajors = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === "--apply") {
      apply = true;
      continue;
    }
    if (arg === "--apply-advisories") {
      applyAdvisories = true;
      continue;
    }
    if (arg === "--force") {
      force = true;
      continue;
    }
    if (arg === "--commit") {
      commit = true;
      continue;
    }
    if (arg === "-i" || arg === "--interactive") {
      interactive = true;
      continue;
    }
    if (arg === "--preset") {
      const value = args[++i];
      if (isPresetName(value)) preset = value;
      continue;
    }
    if (arg.startsWith("--preset=")) {
      const value = arg.slice("--preset=".length);
      if (isPresetName(value)) preset = value;
      continue;
    }
    if (arg === "--concurrency") {
      const value = Number(args[++i]);
      if (Number.isFinite(value) && value >= 1) concurrency = value;
      continue;
    }
    if (arg.startsWith("--concurrency=")) {
      const value = Number(arg.slice("--concurrency=".length));
      if (Number.isFinite(value) && value >= 1) concurrency = value;
      continue;
    }
    if (arg === "--json") {
      json = true;
      continue;
    }
    if (arg === "--sarif") {
      sarif = true;
      continue;
    }
    if (arg === "--allow-majors") {
      allowMajors = true;
      continue;
    }
    if (arg === "--refresh" || arg === "--no-cache") {
      continue;
    }
    if (arg === "--report") {
      report = args[++i];
      continue;
    }
    if (arg.startsWith("--report=")) {
      report = arg.slice("--report=".length);
      continue;
    }
    if (!arg.startsWith("-")) {
      path = arg;
    }
  }

  return {
    path,
    preset,
    apply,
    applyAdvisories,
    interactive,
    concurrency,
    json,
    sarif,
    report,
    force,
    commit,
    allowMajors,
  };
}

function writeFile(path: string, body: string): void {
  writeFileSync(path, body);
}

function defaultGitStatus(root: string): "clean" | "dirty" | "not-git" {
  const proc = Bun.spawnSync(["git", "-C", root, "status", "--porcelain"], {
    stdout: "pipe",
    stderr: "pipe",
  });
  if (proc.exitCode !== 0) return "not-git";
  const stdout = new TextDecoder().decode(proc.stdout).trim();
  return stdout === "" ? "clean" : "dirty";
}

function defaultGitCommit(root: string, message: string, files: string[]): boolean {
  if (files.length === 0) return false;
  const add = Bun.spawnSync(["git", "-C", root, "add", "--", ...files], {
    stdout: "pipe",
    stderr: "pipe",
  });
  if (add.exitCode !== 0) return false;
  const commit = Bun.spawnSync(["git", "-C", root, "commit", "-m", message], {
    stdout: "pipe",
    stderr: "pipe",
  });
  return commit.exitCode === 0;
}

async function defaultRun(
  argv: string[],
  cwd: string,
): Promise<{ code: number; stdout: string; stderr: string }> {
  const proc = Bun.spawn(argv, { cwd, stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  return { code, stdout, stderr };
}

function userConfigPath(env: Record<string, string | undefined>): string {
  const xdg = env.XDG_CONFIG_HOME;
  if (xdg !== undefined && xdg !== "") return join(xdg, "pmsec", "config.toml");
  return join(env.HOME ?? "", ".config", "pmsec", "config.toml");
}

function userCachePath(env: Record<string, string | undefined>): string {
  const xdg = env.XDG_CACHE_HOME;
  if (xdg !== undefined && xdg !== "") return join(xdg, "pmsec");
  return join(env.HOME ?? "", ".cache", "pmsec");
}

function isPresetName(value: string | undefined): value is PresetName {
  return value === "relaxed" || value === "standard" || value === "strict";
}

function readFile(path: string): string | null {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

function readDir(dir: string): string[] {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}

function isDir(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

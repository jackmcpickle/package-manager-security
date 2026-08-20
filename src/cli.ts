import { readdirSync, readFileSync, statSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { auditPath } from "./audit";
import type { ExitCode, PresetName } from "./domain";
import { loadPolicy } from "./policy";
import { formatHuman } from "./report";

export async function run(
  argv: string[],
  deps?: {
    stdout: { write: (s: string) => unknown };
    stderr: { write: (s: string) => unknown };
    cwd: string;
    env: Record<string, string | undefined>;
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
  if (flags.apply) {
    stderr.write("apply is not implemented\n");
  }

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

  const result = auditPath(root, {
    policy,
    apply: flags.apply,
    applyAdvisories: flags.applyAdvisories,
    interactive: flags.interactive,
    concurrency: flags.concurrency,
    flags: flags.preset === undefined ? undefined : { preset: flags.preset },
    deps: {
      readFile,
      readDir,
      isDir,
      which: (binary) => Bun.which(binary) ?? null,
    },
  });

  stdout.write(formatHuman(result));
  return { exitCode: result.exitCode };
}

function parseAuditArgs(args: string[]): {
  path?: string;
  preset?: PresetName;
  apply: boolean;
  applyAdvisories: boolean;
  interactive: boolean;
  concurrency: number;
} {
  let path: string | undefined;
  let preset: PresetName | undefined;
  let apply = false;
  let applyAdvisories = false;
  let interactive = false;
  let concurrency = 4;

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
    if (
      arg === "--json" ||
      arg === "--sarif" ||
      arg === "--force" ||
      arg === "--commit" ||
      arg === "--refresh" ||
      arg === "--no-cache" ||
      arg === "--allow-majors"
    ) {
      continue;
    }
    if (arg === "--report") {
      i += 1;
      continue;
    }
    if (!arg.startsWith("-")) {
      path = arg;
    }
  }

  return { path, preset, apply, applyAdvisories, interactive, concurrency };
}

function userConfigPath(env: Record<string, string | undefined>): string {
  const xdg = env.XDG_CONFIG_HOME;
  if (xdg !== undefined && xdg !== "") return join(xdg, "pmsec", "config.toml");
  return join(env.HOME ?? "", ".config", "pmsec", "config.toml");
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

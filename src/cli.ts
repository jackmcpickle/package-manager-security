import path from "node:path";

import { APP_NAME, CONFIG_FILE_NAME } from "./app-name";
import type { ApplyPrompt } from "./apply-advisories";
import { auditPath } from "./audit";
import type { AuditMode, AuditResult, WriteDeps } from "./audit";
import type { ExitCode, PresetName } from "./domain";
import {
  commandByName,
  formatCommandHelp,
  formatRootHelp,
  formatUnknownCommand,
  isHelpFlag,
} from "./help";
import type { Host } from "./host";
import type { PolicyLayers } from "./policy";
import { formatHuman, formatJson, formatMarkdown, formatSarif } from "./report";

interface AuditFlags {
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
  refresh: boolean;
  noCache: boolean;
}

type BooleanFlagKey =
  | "allowMajors"
  | "apply"
  | "applyAdvisories"
  | "commit"
  | "force"
  | "interactive"
  | "json"
  | "noCache"
  | "refresh"
  | "sarif";

const BOOLEAN_FLAGS: Readonly<Record<string, BooleanFlagKey>> = {
  "--allow-majors": "allowMajors",
  "--apply": "apply",
  "--apply-advisories": "applyAdvisories",
  "--commit": "commit",
  "--fix": "apply",
  "--force": "force",
  "--interactive": "interactive",
  "--json": "json",
  "--no-cache": "noCache",
  "--refresh": "refresh",
  "--sarif": "sarif",
  "-i": "interactive",
};

const PRESET_NAMES: ReadonlySet<string> = new Set([
  "relaxed",
  "standard",
  "strict",
]);

const PROMPT_CHOICES: ReadonlySet<string> = new Set([
  "settings",
  "advisories",
  "both",
  "skip",
]);

type PromptChoice = "settings" | "advisories" | "both" | "skip";

const baseDir = (xdg: string | undefined, fallback: string): string =>
  xdg !== undefined && xdg !== "" ? xdg : fallback;

const userConfigPath = (env: Record<string, string | undefined>): string =>
  path.join(
    baseDir(env.XDG_CONFIG_HOME, path.join(env.HOME ?? "", ".config")),
    APP_NAME,
    "config.toml"
  );

const userCachePath = (env: Record<string, string | undefined>): string =>
  path.join(
    baseDir(env.XDG_CACHE_HOME, path.join(env.HOME ?? "", ".cache")),
    APP_NAME
  );

const isPresetName = (value: string | undefined): value is PresetName =>
  value !== undefined && PRESET_NAMES.has(value);

const presetFlags = (
  preset: PresetName | undefined
): { preset: PresetName } | undefined =>
  preset === undefined ? undefined : { preset };

const readUntilNewline = async (
  readChunk: () => Promise<string | null>,
  buffered: string
): Promise<string> => {
  if (buffered.includes("\n")) {
    return buffered;
  }
  const chunk = await readChunk();
  if (chunk === null) {
    return buffered;
  }
  return readUntilNewline(readChunk, buffered + chunk);
};

export const createLineReader = (
  readChunk: () => Promise<string | null>
): (() => Promise<string>) => {
  let leftover = "";
  return async () => {
    const buffered = await readUntilNewline(readChunk, leftover);
    const nl = buffered.indexOf("\n");
    if (nl === -1) {
      leftover = "";
      return buffered;
    }
    leftover = buffered.slice(nl + 1);
    return buffered.slice(0, nl).replace(/\r$/u, "");
  };
};

const isPromptChoice = (value: string): value is PromptChoice =>
  PROMPT_CHOICES.has(value);

const defaultPrompt =
  (
    write: (text: string) => void,
    readLine: () => Promise<string>
  ): ApplyPrompt =>
  async ({ project, settingsCount, advisoryCount }) => {
    write(
      `${project.root}: ${settingsCount} settings, ${advisoryCount} advisories [settings|advisories|both|skip] `
    );
    const raw = await readLine();
    const line = raw.trim().toLowerCase();
    return isPromptChoice(line) ? line : "skip";
  };

const resolvePrompt = (
  host: Host,
  flags: AuditFlags
): ApplyPrompt | undefined =>
  host.prompt ??
  (flags.interactive
    ? defaultPrompt(host.stdout, createLineReader(host.readStdinChunk))
    : undefined);

const setPreset = (flags: AuditFlags, value: string | undefined): void => {
  if (isPresetName(value)) {
    flags.preset = value;
  }
};

const setConcurrency = (flags: AuditFlags, raw: string | undefined): void => {
  const value = Number(raw);
  if (Number.isFinite(value) && value >= 1) {
    flags.concurrency = value;
  }
};

const consumePreset = (
  flags: AuditFlags,
  arg: string,
  next: string | undefined
): number | null => {
  if (arg === "--preset") {
    setPreset(flags, next);
    return 1;
  }
  if (arg.startsWith("--preset=")) {
    setPreset(flags, arg.slice("--preset=".length));
    return 0;
  }
  return null;
};

const consumeConcurrency = (
  flags: AuditFlags,
  arg: string,
  next: string | undefined
): number | null => {
  if (arg === "--concurrency") {
    setConcurrency(flags, next);
    return 1;
  }
  if (arg.startsWith("--concurrency=")) {
    setConcurrency(flags, arg.slice("--concurrency=".length));
    return 0;
  }
  return null;
};

const consumeReport = (
  flags: AuditFlags,
  arg: string,
  next: string | undefined
): number | null => {
  if (arg === "--report") {
    flags.report = next;
    return 1;
  }
  if (arg.startsWith("--report=")) {
    flags.report = arg.slice("--report=".length);
    return 0;
  }
  return null;
};

const consumeValueFlag = (
  flags: AuditFlags,
  arg: string,
  next: string | undefined
): number | null =>
  consumePreset(flags, arg, next) ??
  consumeConcurrency(flags, arg, next) ??
  consumeReport(flags, arg, next);

const consumeArg = (
  flags: AuditFlags,
  arg: string,
  next: string | undefined
): number => {
  const boolKey = BOOLEAN_FLAGS[arg];
  if (boolKey !== undefined) {
    flags[boolKey] = true;
    return 0;
  }
  const consumed = consumeValueFlag(flags, arg, next);
  if (consumed !== null) {
    return consumed;
  }
  if (!arg.startsWith("-")) {
    flags.path = arg;
  }
  return 0;
};

const parseAuditArgs = (args: string[]): AuditFlags => {
  const flags: AuditFlags = {
    allowMajors: false,
    apply: false,
    applyAdvisories: false,
    commit: false,
    concurrency: 4,
    force: false,
    interactive: false,
    json: false,
    noCache: false,
    refresh: false,
    sarif: false,
  };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === undefined) {
      continue;
    }
    index += consumeArg(flags, arg, args[index + 1]);
  }
  return flags;
};

const resolveRoot = (flagPath: string | undefined, cwd: string): string => {
  if (flagPath === undefined) {
    return cwd;
  }
  if (path.isAbsolute(flagPath)) {
    return flagPath;
  }
  return path.join(cwd, flagPath);
};

const buildWriteDeps = (flags: AuditFlags, host: Host): WriteDeps => ({
  commit: flags.commit,
  force: flags.force,
  gitCommit: host.gitCommit,
  gitStatus: host.gitStatus,
  writeFile: host.files.writeFile,
});

const modeFromFlags = (
  flags: AuditFlags,
  write: WriteDeps,
  prompt: ApplyPrompt | undefined
): AuditMode => {
  if (flags.interactive && prompt !== undefined) {
    return {
      kind: "interactive",
      prompt,
      write,
    };
  }
  if (flags.apply || flags.applyAdvisories) {
    return {
      advisories: flags.applyAdvisories,
      allowMajors: flags.allowMajors,
      kind: "apply",
      settings: flags.apply,
      write,
    };
  }
  return { kind: "audit" };
};

export const resolveColor = (host: Host): boolean =>
  host.env.NO_COLOR === undefined && host.isTTY;

const emitOutput = (
  flags: AuditFlags,
  result: AuditResult,
  host: Host,
  cwd: string,
  color: boolean
): void => {
  if (flags.report !== undefined) {
    const reportPath = path.isAbsolute(flags.report)
      ? flags.report
      : path.join(cwd, flags.report);
    host.files.writeFile(reportPath, formatMarkdown(result));
  }
  if (flags.json) {
    host.stdout(formatJson(result));
    return;
  }
  if (flags.sarif) {
    host.stdout(formatSarif(result));
    return;
  }
  host.stdout(formatHuman(result, { color }));
};

const topicFromHelpArgs = (rest: string[]): string | undefined =>
  rest.find((arg) => !isHelpFlag(arg));

const writeHelp = (
  text: string,
  write: (s: string) => void
): { exitCode: 0 } => {
  write(text);
  return { exitCode: 0 };
};

const writeUsageError = (
  text: string,
  write: (s: string) => void
): { exitCode: 2 } => {
  write(text);
  return { exitCode: 2 };
};

const helpForCommand = (
  name: string,
  color: boolean,
  stdout: (s: string) => void,
  stderr: (s: string) => void
): { exitCode: ExitCode } => {
  const command = commandByName(name);
  if (command === undefined) {
    return writeUsageError(formatUnknownCommand(name, color), stderr);
  }
  return writeHelp(formatCommandHelp(command, color), stdout);
};

const dispatchHelp = (
  head: string,
  rest: string[],
  color: boolean,
  stdout: (s: string) => void,
  stderr: (s: string) => void
): { exitCode: ExitCode } | null => {
  if (head === "help" || isHelpFlag(head)) {
    const topic = topicFromHelpArgs(rest);
    if (topic === undefined) {
      if (head === "help" && rest.some(isHelpFlag)) {
        return helpForCommand("help", color, stdout, stderr);
      }
      return writeHelp(formatRootHelp(color), stdout);
    }
    return helpForCommand(topic, color, stdout, stderr);
  }
  if (rest.some(isHelpFlag)) {
    const command = commandByName(head);
    if (command !== undefined) {
      return writeHelp(formatCommandHelp(command, color), stdout);
    }
  }
  return null;
};

export const run = async (
  argv: string[],
  host: Host
): Promise<{ exitCode: ExitCode }> => {
  const cwd = host.cwd();
  const { env } = host;
  const color = resolveColor(host);

  if (argv.length === 0) {
    return writeUsageError(formatRootHelp(color), host.stderr);
  }

  const [head, ...rest] = argv;
  if (head === undefined) {
    return writeUsageError(formatRootHelp(color), host.stderr);
  }

  const helpResult = dispatchHelp(head, rest, color, host.stdout, host.stderr);
  if (helpResult !== null) {
    return helpResult;
  }

  if (head !== "audit") {
    return writeUsageError(formatUnknownCommand(head, color), host.stderr);
  }

  const flags = parseAuditArgs(rest);
  const root = resolveRoot(flags.path, cwd);

  const layers: PolicyLayers = {
    flags: presetFlags(flags.preset),
    scanToml:
      host.files.readFile(path.join(root, CONFIG_FILE_NAME)) ?? undefined,
    userToml: host.files.readFile(userConfigPath(env)) ?? undefined,
  };

  const prompt = resolvePrompt(host, flags);
  const result = await auditPath(root, {
    concurrency: flags.concurrency,
    deps: {
      cache: host.createCache(userCachePath(env)),
      digest: host.digest,
      isDir: host.files.isDir,
      now: host.now,
      readDir: host.files.readDir,
      readFile: host.files.readFile,
      run: host.run,
      runOsv: host.runOsv,
      which: host.which,
    },
    layers,
    mode: modeFromFlags(flags, buildWriteDeps(flags, host), prompt),
    noCache: flags.noCache,
    refresh: flags.refresh,
  });

  emitOutput(flags, result, host, cwd, color);
  return { exitCode: result.exitCode };
};

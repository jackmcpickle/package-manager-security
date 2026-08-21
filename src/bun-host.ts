import { createHash } from "node:crypto";
import {
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

import { CACHE_TTL_MS, createFsCache } from "./cache";
import type { Finding } from "./domain";
import type { Host, HostFiles } from "./host";

const readFile = (filePath: string): string | null => {
  try {
    return readFileSync(filePath, "utf-8");
  } catch {
    return null;
  }
};

const readDir = (dir: string): string[] => {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
};

const isDir = (filePath: string): boolean => {
  try {
    return statSync(filePath).isDirectory();
  } catch {
    return false;
  }
};

const writeFile = (filePath: string, body: string): void => {
  mkdirSync(path.dirname(filePath), { recursive: true });
  writeFileSync(filePath, body);
};

export const bunFiles: HostFiles = { isDir, readDir, readFile, writeFile };

const runGit = (root: string, args: string[]): boolean => {
  const proc = Bun.spawnSync(["git", "-C", root, ...args], {
    stderr: "pipe",
    stdout: "pipe",
  });
  return proc.exitCode === 0;
};

const gitAddAndCommit = (
  root: string,
  message: string,
  files: string[]
): boolean =>
  runGit(root, ["add", "--", ...files]) &&
  runGit(root, ["commit", "-m", message]);

const defaultGitCommit = (
  root: string,
  message: string,
  files: string[]
): boolean => files.length > 0 && gitAddAndCommit(root, message, files);

const gitStatusFromOutput = (stdout: Uint8Array): "clean" | "dirty" => {
  const text = new TextDecoder().decode(stdout).trim();
  return text === "" ? "clean" : "dirty";
};

const defaultGitStatus = (root: string): "clean" | "dirty" | "not-git" => {
  const proc = Bun.spawnSync(["git", "-C", root, "status", "--porcelain"], {
    stderr: "pipe",
    stdout: "pipe",
  });
  if (proc.exitCode !== 0) {
    return "not-git";
  }
  return gitStatusFromOutput(proc.stdout);
};

const defaultRun = async (
  argv: string[],
  cwd: string
): Promise<{ code: number; stdout: string; stderr: string }> => {
  const proc = Bun.spawn(argv, { cwd, stderr: "pipe", stdout: "pipe" });
  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  return { code, stderr, stdout };
};

const defaultWhich = (binary: string): string | null =>
  Bun.which(binary) ?? null;

const defaultRunOsv = (): Promise<Finding[]> => Promise.resolve([]);

const createBunStdinChunkReader = (): (() => Promise<string | null>) => {
  const reader = Bun.stdin.stream().getReader();
  const decoder = new TextDecoder();
  return async () => {
    const { done, value } = await reader.read();
    if (done) {
      return null;
    }
    return decoder.decode(value, { stream: true });
  };
};

export const defaultDigest = (lockfileBytes: string): string =>
  createHash("sha256").update(lockfileBytes).digest("hex");

export const createBunHost = (): Host => {
  const host: Host = {
    createCache: (dir) => createFsCache(dir, () => host.now(), CACHE_TTL_MS),
    cwd: () => process.cwd(),
    digest: defaultDigest,
    env: process.env,
    files: bunFiles,
    gitCommit: defaultGitCommit,
    gitStatus: defaultGitStatus,
    isTTY: Boolean(process.stdout.isTTY),
    now: () => Date.now(),
    readStdinChunk: createBunStdinChunkReader(),
    run: defaultRun,
    runOsv: defaultRunOsv,
    stderr: (text) => {
      process.stderr.write(text);
    },
    stdout: (text) => {
      process.stdout.write(text);
    },
    which: defaultWhich,
  };
  return host;
};

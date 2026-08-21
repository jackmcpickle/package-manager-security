import type { ApplyPrompt } from "./apply-advisories";
import type { AuditRun } from "./audit";
import type { Cache } from "./cache";
import type { Finding } from "./domain";

export interface HostFiles {
  readFile: (path: string) => string | null;
  writeFile: (path: string, content: string) => void;
  readDir: (path: string) => string[];
  isDir: (path: string) => boolean;
}

export interface Host {
  files: HostFiles;
  run: AuditRun;
  runOsv: (lockOrRequirements: string) => Promise<Finding[]>;
  which: (binary: string) => string | null;
  gitStatus: (root: string) => "clean" | "dirty" | "not-git";
  gitCommit: (root: string, message: string, files: string[]) => boolean;
  readStdinChunk: () => Promise<string | null>;
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  isTTY: boolean;
  env: Record<string, string | undefined>;
  cwd: () => string;
  now: () => number;
  digest: (bytes: string) => string;
  createCache: (dir: string) => Cache;
  prompt?: ApplyPrompt;
}

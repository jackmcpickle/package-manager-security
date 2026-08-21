import path from "node:path";

import { bunFiles } from "../../src/bun-host";
import type { DiscoverFs } from "../../src/discover";
import type { Host, HostFiles } from "../../src/host";
import { createMemoryCache } from "../../src/memory-cache";

const addAncestors = (dirs: Set<string>, dir: string): void => {
  let current = dir;
  while (current && current !== "/") {
    dirs.add(current);
    current = path.dirname(current);
  }
};

const collectDirs = (
  files: Record<string, string>,
  extraDirs: string[]
): Set<string> => {
  const dirs = new Set<string>(["/"]);
  for (const file of Object.keys(files)) {
    addAncestors(dirs, path.dirname(file));
  }
  for (const dir of extraDirs) {
    addAncestors(dirs, dir);
  }
  return dirs;
};

const childNames = (entries: string[], dir: string): string[] => {
  const prefix = dir.endsWith("/") ? dir : `${dir}/`;
  const names = new Set<string>();
  for (const entry of entries) {
    if (entry.startsWith(prefix)) {
      const [name] = entry.slice(prefix.length).split("/");
      if (name) {
        names.add(name);
      }
    }
  }
  return [...names];
};

/**
 * An in-memory `DiscoverFs` built from a flat map of absolute path -> contents.
 * Directories are derived from the file keys; `extraDirs` adds empty ones.
 */
export const memoryFs = (
  files: Record<string, string>,
  extraDirs: string[] = []
): DiscoverFs => {
  const dirs = collectDirs(files, extraDirs);
  const entries = [...dirs, ...Object.keys(files)];
  return {
    isDir: (filePath: string): boolean => dirs.has(filePath),
    readDir: (dir: string): string[] => childNames(entries, dir),
    readFile: (filePath: string): string | null => files[filePath] ?? null,
  };
};

const memoryHostFiles = (
  files: Record<string, string>,
  extraDirs: string[] = []
): HostFiles => {
  const fs = memoryFs(files, extraDirs);
  return {
    ...fs,
    exists: (filePath: string): boolean =>
      Object.hasOwn(files, filePath) || dirs.has(filePath),
    writeFile: (filePath: string, content: string): void => {
      files[filePath] = content;
    },
  };
};

const notStubbed =
  (name: string): (() => never) =>
  () => {
    throw new Error(`${name} not stubbed`);
  };

const discardHostOutput = (_text: string): void => {
  void _text;
};

export type FakeHostOverrides = Partial<Omit<Host, "files">> & {
  extraDirs?: string[];
  files?: Partial<HostFiles>;
  fsMap?: Record<string, string>;
};

export const fakeHost = (overrides: FakeHostOverrides = {}): Host => {
  const {
    extraDirs,
    fsMap,
    files: filesOverride,
    ...hostOverrides
  } = overrides;
  const baseFiles =
    fsMap === undefined ? bunFiles : memoryHostFiles(fsMap, extraDirs ?? []);
  return {
    createCache: () => createMemoryCache(),
    cwd: () => "/",
    digest: (bytes) => bytes,
    env: {},
    files: { ...baseFiles, ...filesOverride },
    gitCommit: () => true,
    gitStatus: () => "clean",
    isTTY: false,
    now: () => 0,
    readStdinChunk: () => Promise.resolve(null),
    run: notStubbed("run"),
    runOsv: () => Promise.resolve([]),
    stderr: discardHostOutput,
    stdout: discardHostOutput,
    which: notStubbed("which"),
    ...hostOverrides,
  };
};

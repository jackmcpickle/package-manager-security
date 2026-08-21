import path from "node:path";

import type { DiscoverFs } from "../../src/discover";

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
): Required<DiscoverFs> => {
  const dirs = collectDirs(files, extraDirs);
  const entries = [...dirs, ...Object.keys(files)];
  return {
    isDir: (filePath: string): boolean => dirs.has(filePath),
    readDir: (dir: string): string[] => childNames(entries, dir),
    readFile: (filePath: string): string | null => files[filePath] ?? null,
  };
};

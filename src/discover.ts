import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { parse as parseToml } from "smol-toml";
import type { DetectedManager, ManagerRole, PackageManager, Project } from "./domain";

export type DiscoverFs = {
  readDir?: (dir: string) => string[];
  readFile?: (path: string) => string | null;
  isDir?: (path: string) => boolean;
};

const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  ".venv",
  "vendor",
  "__pycache__",
  ".pnpm-store",
]);

const NESTED_CONFIGS = [
  ".npmrc",
  "pnpm-workspace.yaml",
  ".yarnrc.yml",
  "bunfig.toml",
  "uv.toml",
  "uv.lock",
];

type Fs = {
  readDir: (dir: string) => string[];
  readFile: (path: string) => string | null;
  isDir: (path: string) => boolean;
};

export function discoverProjects(root: string, opts?: DiscoverFs): Project[] {
  const fs = resolveFs(opts);
  const repos = findRepoTrees(root, fs);
  const projects: Project[] = [];

  for (const repo of repos) {
    const gitRoot = hasGit(repo, fs) ? repo : null;
    for (const pmRoot of findPmRoots(repo, fs)) {
      const managers = detectManagers(pmRoot, fs);
      if (managers.length === 0) continue;
      projects.push({ root: pmRoot, gitRoot, managers });
    }
  }

  return projects;
}

function resolveFs(opts?: DiscoverFs): Fs {
  return {
    readDir: opts?.readDir ?? defaultReadDir,
    readFile: opts?.readFile ?? defaultReadFile,
    isDir: opts?.isDir ?? defaultIsDir,
  };
}

function defaultReadDir(dir: string): string[] {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}

function defaultReadFile(path: string): string | null {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

function defaultIsDir(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

function findRepoTrees(root: string, fs: Fs): string[] {
  if (hasGit(root, fs)) return [root];

  const nested = findNestedGitRepos(root, fs);
  if (nested.length === 0) return [root];

  const trees = [...nested];
  if (hasRootPmMarkers(root, fs)) trees.unshift(root);
  return trees;
}

function findNestedGitRepos(dir: string, fs: Fs): string[] {
  const found: string[] = [];
  for (const name of fs.readDir(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const child = join(dir, name);
    if (!fs.isDir(child)) continue;
    if (hasGit(child, fs)) found.push(child);
    found.push(...findNestedGitRepos(child, fs));
  }
  return found;
}

function findPmRoots(repo: string, fs: Fs): string[] {
  const roots: string[] = [];
  const walk = (dir: string, isRepoRoot: boolean) => {
    if (isRepoRoot && hasRootPmMarkers(dir, fs)) roots.push(dir);
    if (!isRepoRoot && hasNestedConfig(dir, fs)) roots.push(dir);

    for (const name of fs.readDir(dir)) {
      if (SKIP_DIRS.has(name)) continue;
      const child = join(dir, name);
      if (!fs.isDir(child)) continue;
      if (hasGit(child, fs) && child !== repo) continue;
      walk(child, false);
    }
  };
  walk(repo, true);
  return roots;
}

function hasRootPmMarkers(dir: string, fs: Fs): boolean {
  const names = new Set(fs.readDir(dir));
  if (
    names.has("package.json") ||
    names.has("package-lock.json") ||
    names.has("pnpm-lock.yaml") ||
    names.has("pnpm-workspace.yaml") ||
    names.has("yarn.lock") ||
    names.has(".yarnrc.yml") ||
    names.has("bun.lock") ||
    names.has("bun.lockb") ||
    names.has("bunfig.toml") ||
    names.has("uv.lock") ||
    names.has("uv.toml") ||
    names.has("poetry.lock") ||
    names.has("Pipfile") ||
    names.has("Pipfile.lock") ||
    hasRequirementsTxt(names)
  ) {
    return true;
  }
  return hasToolUv(dir, fs) || hasToolPoetry(dir, fs) || hasProjectTable(dir, fs);
}

function hasNestedConfig(dir: string, fs: Fs): boolean {
  const names = new Set(fs.readDir(dir));
  if (NESTED_CONFIGS.some((name) => names.has(name))) return true;
  if (
    names.has("poetry.lock") ||
    names.has("Pipfile") ||
    names.has("Pipfile.lock") ||
    hasRequirementsTxt(names)
  ) {
    return true;
  }
  return hasToolPoetry(dir, fs) || hasProjectTable(dir, fs);
}

function readPyproject(dir: string, fs: Fs): Record<string, unknown> | null {
  const raw = fs.readFile(join(dir, "pyproject.toml"));
  if (raw === null) return null;
  try {
    const parsed: unknown = parseToml(raw);
    return isPlainObject(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function hasToolTable(dir: string, fs: Fs, name: string): boolean {
  const pyproject = readPyproject(dir, fs);
  if (pyproject === null) return false;
  const tool = pyproject["tool"];
  return isPlainObject(tool) && isPlainObject(tool[name]);
}

function hasToolUv(dir: string, fs: Fs): boolean {
  return hasToolTable(dir, fs, "uv");
}

function hasToolPoetry(dir: string, fs: Fs): boolean {
  return hasToolTable(dir, fs, "poetry");
}

function hasProjectTable(dir: string, fs: Fs): boolean {
  const pyproject = readPyproject(dir, fs);
  return pyproject !== null && isPlainObject(pyproject["project"]);
}

function hasRequirementsTxt(names: Set<string>): boolean {
  if (names.has("requirements.txt")) return true;
  for (const name of names) {
    if (/^requirements-.+\.txt$/.test(name)) return true;
  }
  return false;
}

function detectManagers(dir: string, fs: Fs): DetectedManager[] {
  const names = new Set(fs.readDir(dir));
  const pkg = readPackageJson(dir, fs);
  const packageManager =
    typeof pkg?.packageManager === "string" ? pkg.packageManager : undefined;
  const jsPrimary = pickJsPrimary(names, packageManager);
  const managers: DetectedManager[] = [];

  const pnpm = detectPnpm(dir, names, jsPrimary);
  if (pnpm) managers.push(pnpm);
  const yarn = detectYarn(dir, names, packageManager, jsPrimary);
  if (yarn) managers.push(yarn);
  const bun = detectBun(dir, names, jsPrimary);
  if (bun) managers.push(bun);
  const npm = detectNpm(dir, names, packageManager, jsPrimary);
  if (npm) managers.push(npm);
  const uv = detectUv(dir, names, fs);
  if (uv) managers.push(uv);
  const poetry = detectPoetry(dir, names, fs, uv !== null);
  if (poetry) managers.push(poetry);
  const pipenv = detectPipenv(dir, names);
  if (pipenv) managers.push(pipenv);
  const pip = detectPip(dir, names, fs, uv !== null, poetry !== null, pipenv !== null);
  if (pip) managers.push(pip);

  return managers;
}

function pickJsPrimary(
  names: Set<string>,
  packageManager: string | undefined,
): PackageManager | null {
  const pin = parsePackageManager(packageManager);
  const candidates: PackageManager[] = [];
  if (names.has("pnpm-lock.yaml") || names.has("pnpm-workspace.yaml")) {
    candidates.push("pnpm");
  }
  if (names.has("yarn.lock")) candidates.push("yarn");
  if (names.has("bun.lock") || names.has("bun.lockb") || names.has("bunfig.toml")) {
    candidates.push("bun");
  }
  if (names.has("package-lock.json") || names.has("package.json")) {
    const otherJsLock =
      names.has("pnpm-lock.yaml") ||
      names.has("yarn.lock") ||
      names.has("bun.lock") ||
      names.has("bun.lockb");
    const pinnedOther = pin !== null && pin.name !== "npm" && isJsManager(pin.name);
    if (names.has("package-lock.json") || (!otherJsLock && !pinnedOther && names.has("package.json"))) {
      candidates.push("npm");
    }
  }

  if (candidates.length === 0) return null;
  if (pin && candidates.includes(pin.name as PackageManager) && isJsManager(pin.name)) {
    return pin.name as PackageManager;
  }
  const order: PackageManager[] = ["pnpm", "yarn", "bun", "npm"];
  return order.find((name) => candidates.includes(name)) ?? candidates[0] ?? null;
}

function detectPnpm(
  dir: string,
  names: Set<string>,
  jsPrimary: PackageManager | null,
): DetectedManager | null {
  if (!names.has("pnpm-lock.yaml") && !names.has("pnpm-workspace.yaml")) return null;
  return manager(
    "pnpm",
    jsPrimary === "pnpm" ? "primary" : "leftover",
    join(dir, "package.json"),
    names.has("pnpm-lock.yaml") ? join(dir, "pnpm-lock.yaml") : null,
    names.has("pnpm-workspace.yaml") ? join(dir, "pnpm-workspace.yaml") : null,
  );
}

function detectYarn(
  dir: string,
  names: Set<string>,
  packageManager: string | undefined,
  jsPrimary: PackageManager | null,
): DetectedManager | null {
  if (!names.has("yarn.lock")) return null;
  const berry = names.has(".yarnrc.yml") || yarnMajor(packageManager) >= 2;
  const role: ManagerRole =
    jsPrimary !== null && jsPrimary !== "yarn"
      ? "leftover"
      : berry
        ? "primary"
        : "unsupported";
  return manager(
    "yarn",
    role,
    join(dir, "package.json"),
    names.has("yarn.lock") ? join(dir, "yarn.lock") : null,
    names.has(".yarnrc.yml") ? join(dir, ".yarnrc.yml") : null,
  );
}

function detectBun(
  dir: string,
  names: Set<string>,
  jsPrimary: PackageManager | null,
): DetectedManager | null {
  if (!names.has("bun.lock") && !names.has("bun.lockb") && !names.has("bunfig.toml")) {
    return null;
  }
  const lockfilePath = names.has("bun.lock")
    ? join(dir, "bun.lock")
    : names.has("bun.lockb")
      ? join(dir, "bun.lockb")
      : null;
  return manager(
    "bun",
    jsPrimary === "bun" ? "primary" : "leftover",
    join(dir, "package.json"),
    lockfilePath,
    names.has("bunfig.toml") ? join(dir, "bunfig.toml") : null,
  );
}

function detectNpm(
  dir: string,
  names: Set<string>,
  packageManager: string | undefined,
  jsPrimary: PackageManager | null,
): DetectedManager | null {
  const pin = parsePackageManager(packageManager);
  const otherJsLock =
    names.has("pnpm-lock.yaml") ||
    names.has("yarn.lock") ||
    names.has("bun.lock") ||
    names.has("bun.lockb");
  const pinnedOther = pin !== null && pin.name !== "npm" && isJsManager(pin.name);

  if (names.has("package-lock.json")) {
    return manager(
      "npm",
      jsPrimary === "npm" ? "primary" : "leftover",
      join(dir, "package.json"),
      join(dir, "package-lock.json"),
      names.has(".npmrc") ? join(dir, ".npmrc") : null,
    );
  }

  if (!names.has("package.json") || otherJsLock || pinnedOther) return null;
  if (jsPrimary !== null && jsPrimary !== "npm") return null;

  return manager(
    "npm",
    "primary",
    join(dir, "package.json"),
    null,
    names.has(".npmrc") ? join(dir, ".npmrc") : null,
  );
}

function detectPoetry(
  dir: string,
  names: Set<string>,
  fs: Fs,
  uvPresent: boolean,
): DetectedManager | null {
  if (!names.has("poetry.lock") && !hasToolPoetry(dir, fs)) return null;
  return manager(
    "poetry",
    uvPresent ? "leftover" : "primary",
    join(dir, "pyproject.toml"),
    names.has("poetry.lock") ? join(dir, "poetry.lock") : null,
    join(dir, "pyproject.toml"),
  );
}

function detectPipenv(dir: string, names: Set<string>): DetectedManager | null {
  if (!names.has("Pipfile") && !names.has("Pipfile.lock")) return null;
  return manager(
    "pipenv",
    "primary",
    names.has("Pipfile") ? join(dir, "Pipfile") : join(dir, "Pipfile.lock"),
    names.has("Pipfile.lock") ? join(dir, "Pipfile.lock") : null,
    names.has("Pipfile") ? join(dir, "Pipfile") : null,
  );
}

function detectPip(
  dir: string,
  names: Set<string>,
  fs: Fs,
  uvPresent: boolean,
  poetryPresent: boolean,
  pipenvPresent: boolean,
): DetectedManager | null {
  if (uvPresent) return null;
  const reqs = [...names].filter(
    (name) => name === "requirements.txt" || /^requirements-.+\.txt$/.test(name),
  );
  const fromProject =
    !poetryPresent && !pipenvPresent && !hasToolUv(dir, fs) && hasProjectTable(dir, fs);
  if (reqs.length === 0 && !fromProject) return null;
  const manifest = fromProject
    ? join(dir, "pyproject.toml")
    : join(dir, reqs.includes("requirements.txt") ? "requirements.txt" : reqs[0]!);
  return manager("pip", "primary", manifest, null, null);
}

function detectUv(dir: string, names: Set<string>, fs: Fs): DetectedManager | null {
  const toolUv = hasToolUv(dir, fs);
  if (!names.has("uv.lock") && !toolUv) return null;
  const configPath = names.has("uv.toml")
    ? join(dir, "uv.toml")
    : toolUv
      ? join(dir, "pyproject.toml")
      : null;
  return manager(
    "uv",
    "primary",
    join(dir, "pyproject.toml"),
    names.has("uv.lock") ? join(dir, "uv.lock") : null,
    configPath,
  );
}

function manager(
  name: PackageManager,
  role: ManagerRole,
  manifestPath: string,
  lockfilePath: string | null,
  configPath: string | null,
): DetectedManager {
  return { name, role, manifestPath, lockfilePath, configPath };
}

function readPackageJson(dir: string, fs: Fs): Record<string, unknown> | null {
  const raw = fs.readFile(join(dir, "package.json"));
  if (raw === null) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    return isPlainObject(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function parsePackageManager(
  field: string | undefined,
): { name: string; major: number } | null {
  if (!field) return null;
  const at = field.indexOf("@");
  if (at <= 0) return null;
  const name = field.slice(0, at);
  const major = Number.parseInt(field.slice(at + 1), 10);
  if (!name || Number.isNaN(major)) return null;
  return { name, major };
}

function yarnMajor(packageManager: string | undefined): number {
  const pin = parsePackageManager(packageManager);
  return pin?.name === "yarn" ? pin.major : -1;
}

function isJsManager(name: string): name is PackageManager {
  return name === "npm" || name === "pnpm" || name === "yarn" || name === "bun";
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    !(value instanceof Date)
  );
}

function hasGit(dir: string, fs: Fs): boolean {
  return fs.isDir(join(dir, ".git")) || fs.readDir(dir).includes(".git");
}

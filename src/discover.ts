import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

import { parse as parseToml } from "smol-toml";

import type {
  DetectedManager,
  ManagerRole,
  PackageManager,
  Project,
} from "./domain";
import { profileFor } from "./managers/profile";

export interface DiscoverFs {
  readDir?: (dir: string) => string[];
  readFile?: (path: string) => string | null;
  isDir?: (path: string) => boolean;
}

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
  "Cargo.toml",
  "composer.json",
];

interface Fs {
  readDir: (dir: string) => string[];
  readFile: (path: string) => string | null;
  isDir: (path: string) => boolean;
}

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" &&
  value !== null &&
  !Array.isArray(value) &&
  !(value instanceof Date);

const isJsManager = (name: string): name is PackageManager =>
  name === "npm" || name === "pnpm" || name === "yarn" || name === "bun";

const hasGit = (dir: string, fs: Fs): boolean =>
  fs.isDir(path.join(dir, ".git")) || fs.readDir(dir).includes(".git");

const hasRequirementsTxt = (names: Set<string>): boolean => {
  if (names.has("requirements.txt")) {
    return true;
  }
  for (const name of names) {
    if (/^requirements-.+\.txt$/u.test(name)) {
      return true;
    }
  }
  return false;
};

const defaultReadDir = (dir: string): string[] => {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
};

const defaultReadFile = (filePath: string): string | null => {
  try {
    return readFileSync(filePath, "utf-8");
  } catch {
    return null;
  }
};

const defaultIsDir = (dir: string): boolean => {
  try {
    return statSync(dir).isDirectory();
  } catch {
    return false;
  }
};

const resolveFs = (opts?: DiscoverFs): Fs => ({
  isDir: opts?.isDir ?? defaultIsDir,
  readDir: opts?.readDir ?? defaultReadDir,
  readFile: opts?.readFile ?? defaultReadFile,
});

const readPyproject = (dir: string, fs: Fs): Record<string, unknown> | null => {
  const raw = fs.readFile(path.join(dir, "pyproject.toml"));
  if (raw === null) {
    return null;
  }
  try {
    const parsed: unknown = parseToml(raw);
    return isPlainObject(parsed) ? parsed : null;
  } catch {
    return null;
  }
};

const hasToolTable = (dir: string, fs: Fs, name: string): boolean => {
  const pyproject = readPyproject(dir, fs);
  if (pyproject === null) {
    return false;
  }
  const { tool } = pyproject;
  return isPlainObject(tool) && isPlainObject(tool[name]);
};

const hasToolUv = (dir: string, fs: Fs): boolean => hasToolTable(dir, fs, "uv");

const hasToolPoetry = (dir: string, fs: Fs): boolean =>
  hasToolTable(dir, fs, "poetry");

const hasProjectTable = (dir: string, fs: Fs): boolean => {
  const pyproject = readPyproject(dir, fs);
  return pyproject !== null && isPlainObject(pyproject["project"]);
};

const ROOT_PM_FILES = [
  "package.json",
  "package-lock.json",
  "pnpm-lock.yaml",
  "pnpm-workspace.yaml",
  "yarn.lock",
  ".yarnrc.yml",
  "bun.lock",
  "bun.lockb",
  "bunfig.toml",
  "uv.lock",
  "uv.toml",
  "Cargo.toml",
  "Cargo.lock",
  "poetry.lock",
  "Pipfile",
  "Pipfile.lock",
  "Gemfile",
  "Gemfile.lock",
  "composer.json",
  "composer.lock",
] as const;

const hasNamedFile = (names: Set<string>, files: readonly string[]): boolean =>
  files.some((name) => names.has(name));

const hasRootPmMarkers = (dir: string, fs: Fs): boolean => {
  const names = new Set(fs.readDir(dir));
  if (hasNamedFile(names, ROOT_PM_FILES) || hasRequirementsTxt(names)) {
    return true;
  }
  return (
    hasToolUv(dir, fs) || hasToolPoetry(dir, fs) || hasProjectTable(dir, fs)
  );
};

const NESTED_PM_MARKER_FILES = [
  "Cargo.lock",
  "Cargo.toml",
  "Gemfile",
  "Gemfile.lock",
  "Pipfile",
  "Pipfile.lock",
  "composer.json",
  "composer.lock",
  "poetry.lock",
] as const;

const hasNestedPmFiles = (names: Set<string>): boolean =>
  NESTED_PM_MARKER_FILES.some((file) => names.has(file)) ||
  hasRequirementsTxt(names);

const hasNestedConfig = (dir: string, fs: Fs): boolean => {
  const names = new Set(fs.readDir(dir));
  if (NESTED_CONFIGS.some((name) => names.has(name))) {
    return true;
  }
  if (hasNestedPmFiles(names)) {
    return true;
  }
  return hasToolPoetry(dir, fs) || hasProjectTable(dir, fs);
};

const findNestedGitRepos = (dir: string, fs: Fs): string[] => {
  const found: string[] = [];
  for (const name of fs.readDir(dir)) {
    if (SKIP_DIRS.has(name)) {
      continue;
    }
    const child = path.join(dir, name);
    if (!fs.isDir(child)) {
      continue;
    }
    if (hasGit(child, fs)) {
      found.push(child);
    }
    found.push(...findNestedGitRepos(child, fs));
  }
  return found;
};

const findRepoTrees = (root: string, fs: Fs): string[] => {
  if (hasGit(root, fs)) {
    return [root];
  }

  const nested = findNestedGitRepos(root, fs);
  if (nested.length === 0) {
    return [root];
  }

  const trees = [...nested];
  if (hasRootPmMarkers(root, fs)) {
    trees.unshift(root);
  }
  return trees;
};

const shouldSkipPmChild = (
  name: string,
  child: string,
  repo: string,
  fs: Fs
): boolean =>
  SKIP_DIRS.has(name) ||
  !fs.isDir(child) ||
  (hasGit(child, fs) && child !== repo);

const collectPmRoot = (
  dir: string,
  isRepoRoot: boolean,
  fs: Fs,
  roots: string[]
): void => {
  if (isRepoRoot && hasRootPmMarkers(dir, fs)) {
    roots.push(dir);
  } else if (!isRepoRoot && hasNestedConfig(dir, fs)) {
    roots.push(dir);
  }
};

const walkPmRoots = (
  dir: string,
  isRepoRoot: boolean,
  repo: string,
  fs: Fs,
  roots: string[]
): void => {
  collectPmRoot(dir, isRepoRoot, fs, roots);
  for (const name of fs.readDir(dir)) {
    const child = path.join(dir, name);
    if (shouldSkipPmChild(name, child, repo, fs)) {
      continue;
    }
    walkPmRoots(child, false, repo, fs, roots);
  }
};

const findPmRoots = (repo: string, fs: Fs): string[] => {
  const roots: string[] = [];
  walkPmRoots(repo, true, repo, fs, roots);
  return roots;
};

const readPackageJson = (
  dir: string,
  fs: Fs
): Record<string, unknown> | null => {
  const raw = fs.readFile(path.join(dir, "package.json"));
  if (raw === null) {
    return null;
  }
  try {
    const parsed: unknown = JSON.parse(raw);
    return isPlainObject(parsed) ? parsed : null;
  } catch {
    return null;
  }
};

const parsePackageManager = (
  field: string | undefined
): { name: string; major: number } | null => {
  if (!field) {
    return null;
  }
  const at = field.indexOf("@");
  if (at <= 0) {
    return null;
  }
  const name = field.slice(0, at);
  const [majorRaw] = field.slice(at + 1).split(".");
  const major = Math.trunc(Number(majorRaw));
  if (!name || Number.isNaN(major)) {
    return null;
  }
  return { major, name };
};

const yarnMajor = (packageManager: string | undefined): number => {
  const pin = parsePackageManager(packageManager);
  return pin?.name === "yarn" ? pin.major : -1;
};

const manager = (
  name: PackageManager,
  role: ManagerRole,
  manifestPath: string,
  lockfilePath: string | null,
  configPath: string | null
): DetectedManager => ({ configPath, lockfilePath, manifestPath, name, role });

const JS_PRIMARY_ORDER: PackageManager[] = ["pnpm", "yarn", "bun", "npm"];

const hasBunLock = (names: Set<string>): boolean =>
  names.has("bun.lock") || names.has("bun.lockb");

const hasOtherJsLock = (names: Set<string>): boolean =>
  names.has("pnpm-lock.yaml") || names.has("yarn.lock") || hasBunLock(names);

const isPinnedOtherJs = (
  pin: { name: string; major: number } | null
): boolean => pin !== null && pin.name !== "npm" && isJsManager(pin.name);

const shouldIncludeNpm = (
  names: Set<string>,
  pin: { name: string; major: number } | null
): boolean => {
  if (names.has("package-lock.json")) {
    return true;
  }
  if (!names.has("package.json")) {
    return false;
  }
  return !hasOtherJsLock(names) && !isPinnedOtherJs(pin);
};

const collectJsCandidates = (
  names: Set<string>,
  pin: { name: string; major: number } | null
): PackageManager[] => {
  const candidates: PackageManager[] = [];
  if (names.has("pnpm-lock.yaml") || names.has("pnpm-workspace.yaml")) {
    candidates.push("pnpm");
  }
  if (names.has("yarn.lock")) {
    candidates.push("yarn");
  }
  if (hasBunLock(names) || names.has("bunfig.toml")) {
    candidates.push("bun");
  }
  if (shouldIncludeNpm(names, pin)) {
    candidates.push("npm");
  }
  return candidates;
};

const pinnedJsPrimary = (
  pin: { name: string; major: number } | null,
  candidates: PackageManager[]
): PackageManager | null => {
  if (
    pin &&
    candidates.includes(pin.name as PackageManager) &&
    isJsManager(pin.name)
  ) {
    return pin.name;
  }
  return null;
};

const pickJsPrimary = (
  names: Set<string>,
  packageManager: string | undefined
): PackageManager | null => {
  const pin = parsePackageManager(packageManager);
  const candidates = collectJsCandidates(names, pin);
  if (candidates.length === 0) {
    return null;
  }
  return (
    pinnedJsPrimary(pin, candidates) ??
    JS_PRIMARY_ORDER.find((name) => candidates.includes(name)) ??
    candidates[0] ??
    null
  );
};

const detectPnpm = (
  dir: string,
  names: Set<string>,
  jsPrimary: PackageManager | null
): DetectedManager | null => {
  if (!names.has("pnpm-lock.yaml") && !names.has("pnpm-workspace.yaml")) {
    return null;
  }
  return manager(
    "pnpm",
    jsPrimary === "pnpm" ? "primary" : "leftover",
    path.join(dir, "package.json"),
    names.has("pnpm-lock.yaml") ? path.join(dir, "pnpm-lock.yaml") : null,
    names.has("pnpm-workspace.yaml")
      ? path.join(dir, "pnpm-workspace.yaml")
      : null
  );
};

const yarnRole = (
  jsPrimary: PackageManager | null,
  berry: boolean
): ManagerRole => {
  if (jsPrimary !== null && jsPrimary !== "yarn") {
    return "leftover";
  }
  if (berry) {
    return "primary";
  }
  return "unsupported";
};

const detectYarn = (
  dir: string,
  names: Set<string>,
  packageManager: string | undefined,
  jsPrimary: PackageManager | null
): DetectedManager | null => {
  if (!names.has("yarn.lock")) {
    return null;
  }
  const berry = names.has(".yarnrc.yml") || yarnMajor(packageManager) >= 2;
  return manager(
    "yarn",
    yarnRole(jsPrimary, berry),
    path.join(dir, "package.json"),
    path.join(dir, "yarn.lock"),
    names.has(".yarnrc.yml") ? path.join(dir, ".yarnrc.yml") : null
  );
};

const hasBunMarker = (names: Set<string>): boolean =>
  hasBunLock(names) || names.has("bunfig.toml");

const bunLockfilePath = (dir: string, names: Set<string>): string | null => {
  for (const name of profileFor("bun").lockfileNames) {
    if (names.has(name)) {
      return path.join(dir, name);
    }
  }
  return null;
};

const detectBun = (
  dir: string,
  names: Set<string>,
  jsPrimary: PackageManager | null
): DetectedManager | null => {
  if (!hasBunMarker(names)) {
    return null;
  }
  return manager(
    "bun",
    jsPrimary === "bun" ? "primary" : "leftover",
    path.join(dir, "package.json"),
    bunLockfilePath(dir, names),
    names.has("bunfig.toml") ? path.join(dir, "bunfig.toml") : null
  );
};

const npmConfigPath = (dir: string, names: Set<string>): string | null =>
  names.has(".npmrc") ? path.join(dir, ".npmrc") : null;

const canDetectBareNpm = (
  names: Set<string>,
  pin: { name: string; major: number } | null,
  jsPrimary: PackageManager | null
): boolean => {
  if (
    !names.has("package.json") ||
    hasOtherJsLock(names) ||
    isPinnedOtherJs(pin)
  ) {
    return false;
  }
  return jsPrimary === null || jsPrimary === "npm";
};

const detectNpm = (
  dir: string,
  names: Set<string>,
  packageManager: string | undefined,
  jsPrimary: PackageManager | null
): DetectedManager | null => {
  if (names.has("package-lock.json")) {
    return manager(
      "npm",
      jsPrimary === "npm" ? "primary" : "leftover",
      path.join(dir, "package.json"),
      path.join(dir, "package-lock.json"),
      npmConfigPath(dir, names)
    );
  }
  if (
    !canDetectBareNpm(names, parsePackageManager(packageManager), jsPrimary)
  ) {
    return null;
  }
  return manager(
    "npm",
    "primary",
    path.join(dir, "package.json"),
    null,
    npmConfigPath(dir, names)
  );
};

const detectPoetry = (
  dir: string,
  names: Set<string>,
  fs: Fs,
  uvPresent: boolean
): DetectedManager | null => {
  if (!names.has("poetry.lock") && !hasToolPoetry(dir, fs)) {
    return null;
  }
  return manager(
    "poetry",
    uvPresent ? "leftover" : "primary",
    path.join(dir, "pyproject.toml"),
    names.has("poetry.lock") ? path.join(dir, "poetry.lock") : null,
    path.join(dir, "pyproject.toml")
  );
};

const detectPipenv = (
  dir: string,
  names: Set<string>
): DetectedManager | null => {
  if (!names.has("Pipfile") && !names.has("Pipfile.lock")) {
    return null;
  }
  return manager(
    "pipenv",
    "primary",
    names.has("Pipfile")
      ? path.join(dir, "Pipfile")
      : path.join(dir, "Pipfile.lock"),
    names.has("Pipfile.lock") ? path.join(dir, "Pipfile.lock") : null,
    names.has("Pipfile") ? path.join(dir, "Pipfile") : null
  );
};

const requirementFiles = (names: Set<string>): string[] =>
  [...names].filter(
    (name) =>
      name === "requirements.txt" || /^requirements-.+\.txt$/u.test(name)
  );

const pipFromProject = (
  dir: string,
  fs: Fs,
  poetryPresent: boolean,
  pipenvPresent: boolean
): boolean =>
  !poetryPresent &&
  !pipenvPresent &&
  !hasToolUv(dir, fs) &&
  hasProjectTable(dir, fs);

const detectPip = (
  dir: string,
  names: Set<string>,
  fs: Fs,
  uvPresent: boolean,
  poetryPresent: boolean,
  pipenvPresent: boolean
): DetectedManager | null => {
  if (uvPresent) {
    return null;
  }
  const reqs = requirementFiles(names);
  const fromProject = pipFromProject(dir, fs, poetryPresent, pipenvPresent);
  if (reqs.length === 0 && !fromProject) {
    return null;
  }
  const reqName = reqs.includes("requirements.txt")
    ? "requirements.txt"
    : reqs[0];
  const manifest = fromProject
    ? path.join(dir, "pyproject.toml")
    : path.join(dir, reqName ?? "requirements.txt");
  return manager("pip", "primary", manifest, null, null);
};

const detectBundler = (
  dir: string,
  names: Set<string>,
  fs: Fs
): DetectedManager | null => {
  if (!names.has("Gemfile")) {
    return null;
  }
  const configPath = path.join(dir, ".bundle/config");
  const hasConfig = fs.readFile(configPath) !== null;
  return manager(
    "bundler",
    "primary",
    path.join(dir, "Gemfile"),
    names.has("Gemfile.lock") ? path.join(dir, "Gemfile.lock") : null,
    hasConfig ? configPath : null
  );
};

const uvRole = (
  jsPrimary: PackageManager | null,
  pythonProject: boolean
): ManagerRole =>
  jsPrimary !== null && !pythonProject ? "leftover" : "primary";

const uvDetectedConfigPath = (
  dir: string,
  names: Set<string>,
  toolUv: boolean
): string | null => {
  const [uvTomlName, pyprojectName] = profileFor("uv").configNames;
  if (uvTomlName !== undefined && names.has(uvTomlName)) {
    return path.join(dir, uvTomlName);
  }
  if (toolUv && pyprojectName !== undefined) {
    return path.join(dir, pyprojectName);
  }
  return null;
};

const detectUv = (
  dir: string,
  names: Set<string>,
  fs: Fs,
  jsPrimary: PackageManager | null
): DetectedManager | null => {
  const toolUv = hasToolUv(dir, fs);
  if (!names.has("uv.lock") && !toolUv) {
    return null;
  }
  const pythonProject = toolUv || hasProjectTable(dir, fs);
  return manager(
    "uv",
    uvRole(jsPrimary, pythonProject),
    path.join(dir, "pyproject.toml"),
    names.has("uv.lock") ? path.join(dir, "uv.lock") : null,
    uvDetectedConfigPath(dir, names, toolUv)
  );
};

const cargoConfigPath = (dir: string, fs: Fs): string => {
  const [configToml, config] = profileFor("cargo").configNames.map((name) =>
    path.join(dir, name)
  );
  if (configToml !== undefined && fs.readFile(configToml) !== null) {
    return configToml;
  }
  if (config !== undefined && fs.readFile(config) !== null) {
    return config;
  }
  return configToml ?? path.join(dir, ".cargo/config.toml");
};

const detectComposer = (
  dir: string,
  names: Set<string>,
  jsPrimary: PackageManager | null
): DetectedManager | null => {
  const hasComposerJson = names.has("composer.json");
  if (!hasComposerJson && !names.has("composer.lock")) {
    return null;
  }
  const role: ManagerRole =
    hasComposerJson || jsPrimary === null ? "primary" : "leftover";
  return manager(
    "composer",
    role,
    path.join(dir, "composer.json"),
    names.has("composer.lock") ? path.join(dir, "composer.lock") : null,
    hasComposerJson ? path.join(dir, "composer.json") : null
  );
};

const detectCargo = (
  dir: string,
  names: Set<string>,
  fs: Fs,
  jsPrimary: PackageManager | null
): DetectedManager | null => {
  const hasCargoToml = names.has("Cargo.toml");
  if (!hasCargoToml && !names.has("Cargo.lock")) {
    return null;
  }
  const role: ManagerRole =
    hasCargoToml || jsPrimary === null ? "primary" : "leftover";
  return manager(
    "cargo",
    role,
    path.join(dir, "Cargo.toml"),
    names.has("Cargo.lock") ? path.join(dir, "Cargo.lock") : null,
    cargoConfigPath(dir, fs)
  );
};

const appendManager = (
  managers: DetectedManager[],
  detected: DetectedManager | null
): void => {
  if (detected !== null) {
    managers.push(detected);
  }
};

const detectManagers = (dir: string, fs: Fs): DetectedManager[] => {
  const names = new Set(fs.readDir(dir));
  const pkg = readPackageJson(dir, fs);
  const packageManager =
    typeof pkg?.packageManager === "string" ? pkg.packageManager : undefined;
  const jsPrimary = pickJsPrimary(names, packageManager);
  const managers: DetectedManager[] = [];

  appendManager(managers, detectPnpm(dir, names, jsPrimary));
  appendManager(managers, detectYarn(dir, names, packageManager, jsPrimary));
  appendManager(managers, detectBun(dir, names, jsPrimary));
  appendManager(managers, detectNpm(dir, names, packageManager, jsPrimary));
  const uv = detectUv(dir, names, fs, jsPrimary);
  appendManager(managers, uv);
  const poetry = detectPoetry(dir, names, fs, uv !== null);
  appendManager(managers, poetry);
  const pipenv = detectPipenv(dir, names);
  appendManager(managers, pipenv);
  appendManager(
    managers,
    detectPip(dir, names, fs, uv !== null, poetry !== null, pipenv !== null)
  );
  appendManager(managers, detectBundler(dir, names, fs));
  appendManager(managers, detectComposer(dir, names, jsPrimary));
  appendManager(managers, detectCargo(dir, names, fs, jsPrimary));

  return managers;
};

export const discoverProjects = (
  root: string,
  opts?: DiscoverFs
): Project[] => {
  const fs = resolveFs(opts);
  const repos = findRepoTrees(root, fs);
  const projects: Project[] = [];

  for (const repo of repos) {
    const gitRoot = hasGit(repo, fs) ? repo : null;
    for (const pmRoot of findPmRoots(repo, fs)) {
      const managers = detectManagers(pmRoot, fs);
      if (managers.length === 0) {
        continue;
      }
      projects.push({ gitRoot, managers, root: pmRoot });
    }
  }

  return projects;
};

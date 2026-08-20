import { parse as parseToml, stringify as stringifyToml } from "smol-toml";
import type { DetectedManager, Finding, PackageManager, Policy, Project } from "./domain";
import { PRESET_DEFAULTS } from "./policy";

export interface ApplyResult {
  written: string[];
  skipped: "dirty" | "nothing" | null;
  committed: boolean;
}

export type ApplySettingsDeps = {
  readFile: (path: string) => string | null;
  writeFile: (path: string, body: string) => void;
  gitStatus: (root: string) => "clean" | "dirty" | "not-git";
  gitCommit?: (root: string, message: string, files: string[]) => boolean;
  force: boolean;
  commit: boolean;
};

export type ApplySettingsItem = {
  project: Project;
  findings: Finding[];
  policy: Policy;
};

const COMMIT_MESSAGE = "chore: apply pmsec security settings";

type ResolvedSettings = {
  minReleaseAgeDays: number;
  auditLevel: string;
};

const DEFAULT_REGISTRY = "https://registry.npmjs.org/";

export function applySettings(
  project: Project,
  findings: Finding[],
  policy: Policy,
  deps: ApplySettingsDeps,
): ApplyResult {
  return applySettingsGroup([{ project, findings, policy }], deps);
}

export function applySettingsGroup(items: ApplySettingsItem[], deps: ApplySettingsDeps): ApplyResult {
  if (items.length === 0) return { written: [], skipped: "nothing", committed: false };

  const gitRoot = items[0]!.project.gitRoot ?? items[0]!.project.root;
  if (!deps.force && deps.gitStatus(gitRoot) !== "clean") {
    return { written: [], skipped: "dirty", committed: false };
  }

  const written: string[] = [];
  for (const item of items) {
    written.push(...writeSettings(item.project, item.findings, item.policy, deps));
  }

  if (written.length === 0) {
    return { written: [], skipped: "nothing", committed: false };
  }

  let committed = false;
  if (deps.commit && deps.gitCommit) {
    committed = deps.gitCommit(gitRoot, COMMIT_MESSAGE, written) === true;
  }

  return { written, skipped: null, committed };
}

function writeSettings(
  project: Project,
  findings: Finding[],
  policy: Policy,
  deps: ApplySettingsDeps,
): string[] {
  const written: string[] = [];
  for (const [path, target] of collectTargets(project, findings, deps.readFile)) {
    const next = renderConfig(
      target.manager,
      deps.readFile(path) ?? "",
      target.codes,
      resolveSettings(policy, target.manager),
    );
    if (next === null) continue;
    deps.writeFile(path, next);
    written.push(path);
  }
  return written;
}

function collectTargets(
  project: Project,
  findings: Finding[],
  readFile: (path: string) => string | null,
): Map<string, { manager: PackageManager; codes: Set<string> }> {
  const targets = new Map<string, { manager: PackageManager; codes: Set<string> }>();

  for (const finding of findings) {
    if (!finding.fixable || finding.kind !== "settings") continue;
    if (finding.code === "lockfile.missing" || finding.code === "pm.unpinned") continue;
    const name = finding.manager;
    if (name === undefined) continue;
    const manager = project.managers.find((row) => row.name === name && row.role === "primary");
    if (manager === undefined) continue;

    const path = configPathFor(project, manager, readFile);
    if (path === null || isForbiddenWrite(path, project.root)) continue;

    const entry = targets.get(path) ?? { manager: name, codes: new Set<string>() };
    entry.codes.add(finding.code);
    targets.set(path, entry);
  }

  return targets;
}

function configPathFor(
  project: Project,
  manager: DetectedManager,
  readFile: (path: string) => string | null,
): string | null {
  switch (manager.name) {
    case "npm":
      return localPath(project.root, ".npmrc");
    case "pnpm":
      return localPath(project.root, "pnpm-workspace.yaml");
    case "yarn":
      return localPath(project.root, ".yarnrc.yml");
    case "bun":
      return localPath(project.root, "bunfig.toml");
    case "uv":
      return uvConfigPath(project, manager, readFile);
    default:
      return null;
  }
}

function uvConfigPath(
  project: Project,
  manager: DetectedManager,
  readFile: (path: string) => string | null,
): string {
  const uvToml = localPath(project.root, "uv.toml");
  if (readFile(uvToml) !== null) return uvToml;
  const pyproject = localPath(project.root, "pyproject.toml");
  if (
    manager.configPath !== null &&
    isInside(manager.configPath, project.root) &&
    manager.configPath.endsWith("pyproject.toml")
  ) {
    return manager.configPath;
  }
  const raw = readFile(pyproject);
  if (raw !== null && hasToolUv(raw)) return pyproject;
  return uvToml;
}

function renderConfig(
  manager: PackageManager,
  raw: string,
  codes: Set<string>,
  settings: ResolvedSettings,
): string | null {
  if (manager === "npm") return mergeNpmrc(raw, codes, settings);
  if (manager === "pnpm") return mergePnpmYaml(raw, codes, settings);
  if (manager === "yarn") return mergeYarnYaml(raw, codes, settings);
  if (manager === "bun") return mergeBunfig(raw, codes, settings);
  return mergeUv(raw, codes, settings);
}

function mergeNpmrc(raw: string, codes: Set<string>, settings: ResolvedSettings): string {
  const updates: Record<string, string> = {};
  if (codes.has("scripts.unrestricted")) updates["ignore-scripts"] = "true";
  if (codes.has("audit.disabled")) {
    updates.audit = "true";
    updates["audit-level"] = settings.auditLevel;
  }
  if (codes.has("min-age.disabled")) updates["min-release-age"] = String(settings.minReleaseAgeDays);
  if (codes.has("source.non-registry")) {
    updates["allow-git"] = "none";
    updates["allow-remote"] = "none";
  }
  if (codes.has("registry.unpinned")) updates.registry = DEFAULT_REGISTRY;

  const seen = new Set<string>();
  const lines = raw.split(/\r?\n/).map((line) => {
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#") || trimmed.startsWith(";")) return line;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) return line;
    const key = trimmed.slice(0, eq).trim();
    if (key in updates) {
      seen.add(key);
      return `${key}=${updates[key]}`;
    }
    return line;
  });
  const out = [...lines];
  while (out.length > 0 && out[out.length - 1] === "") out.pop();
  for (const [key, value] of Object.entries(updates)) {
    if (!seen.has(key)) out.push(`${key}=${value}`);
  }
  return `${out.join("\n")}\n`;
}

function mergePnpmYaml(raw: string, codes: Set<string>, settings: ResolvedSettings): string | null {
  const parsed = parseYaml(raw);
  if (!parsed.ok) return null;
  const yaml = parsed.value;
  if (codes.has("scripts.unrestricted") || codes.has("scripts.legacy-config")) {
    yaml.dangerouslyAllowAllBuilds = false;
    yaml.allowBuilds = migrateAllowBuilds(yaml);
  }
  if (codes.has("scripts.non-strict")) yaml.strictDepBuilds = true;
  if (codes.has("source.non-registry")) yaml.blockExoticSubdeps = true;
  if (codes.has("audit.disabled")) {
    yaml.audit = true;
    yaml.auditLevel = settings.auditLevel;
  }
  // pnpm reads bare minimumReleaseAge numbers as minutes.
  if (codes.has("min-age.disabled")) yaml.minimumReleaseAge = settings.minReleaseAgeDays * 24 * 60;
  if (codes.has("min-age.non-strict")) yaml.minimumReleaseAgeStrict = true;
  if (codes.has("min-age.missing-time")) yaml.minimumReleaseAgeIgnoreMissingTime = false;
  if (codes.has("min-age.exclude-all")) {
    yaml.minimumReleaseAgeExclude = dropBlanketEntries(yaml.minimumReleaseAgeExclude);
  }
  if (codes.has("registry.unpinned") && !hasText(yaml.registry) && !hasDefaultRegistry(yaml)) {
    yaml.registry = DEFAULT_REGISTRY;
  }
  return stringifyYaml(yaml);
}

function mergeYarnYaml(raw: string, codes: Set<string>, settings: ResolvedSettings): string | null {
  const parsed = parseYaml(raw);
  if (!parsed.ok) return null;
  const yaml = parsed.value;
  if (codes.has("scripts.unrestricted")) yaml.enableScripts = false;
  if (codes.has("audit.disabled")) {
    delete yaml.audit;
    delete yaml.npmAudit;
    yaml.enableNpmAudit = true;
  }
  // yarn reads bare npmMinimalAgeGate numbers as minutes.
  if (codes.has("min-age.disabled")) {
    yaml.npmMinimalAgeGate = settings.minReleaseAgeDays * 24 * 60;
  }
  if (codes.has("min-age.exclude-all")) {
    yaml.npmPreapprovedPackages = dropBlanketEntries(yaml.npmPreapprovedPackages);
  }
  if (codes.has("integrity.checksum-relaxed")) yaml.checksumBehavior = "throw";
  if (codes.has("integrity.strict-ssl")) yaml.enableStrictSsl = true;
  if (codes.has("integrity.hardened-mode")) yaml.enableHardenedMode = true;
  if (codes.has("registry.unpinned") && !hasText(yaml.npmRegistryServer)) {
    yaml.npmRegistryServer = DEFAULT_REGISTRY;
  }
  return stringifyYaml(yaml);
}

function mergeBunfig(raw: string, codes: Set<string>, settings: ResolvedSettings): string | null {
  const parsed = parseTomlObject(raw);
  if (!parsed.ok) return null;
  const table = parsed.value;
  const install = isPlainObject(table.install) ? table.install : {};
  if (codes.has("scripts.unrestricted")) install.ignoreScripts = true;
  // bun reads minimumReleaseAge as seconds.
  if (codes.has("min-age.disabled")) {
    install.minimumReleaseAge = settings.minReleaseAgeDays * 86_400;
  }
  if (codes.has("min-age.exclude-all")) {
    install.minimumReleaseAgeExcludes = dropBlanketEntries(install.minimumReleaseAgeExcludes);
  }
  if (codes.has("registry.unpinned") && !bunRegistryPinned(install)) {
    install.registry = DEFAULT_REGISTRY;
  }
  table.install = install;
  return `${stringifyToml(table).trimEnd()}\n`;
}

function mergeUv(raw: string, codes: Set<string>, settings: ResolvedSettings): string | null {
  const parsed = parseTomlObject(raw);
  if (!parsed.ok) return null;
  const table = parsed.value;
  const target = uvWriteTable(table);
  if (codes.has("min-age.disabled")) {
    target["exclude-newer"] = new Date(
      Date.now() - settings.minReleaseAgeDays * 86_400_000,
    ).toISOString();
  }
  if (codes.has("min-age.exclude-all") && isPlainObject(target["exclude-newer-package"])) {
    const kept = Object.entries(target["exclude-newer-package"]).filter(
      ([key]) => !isBlanket(key),
    );
    target["exclude-newer-package"] = Object.fromEntries(kept);
  }
  if (codes.has("registry.unpinned")) target["index-strategy"] = "first-index";
  return `${stringifyToml(table).trimEnd()}\n`;
}

function isBlanket(entry: unknown): boolean {
  return typeof entry === "string" && /^\*+$/.test(entry.trim());
}

/** Strips bare wildcards, which would otherwise void the release-age gate. */
function dropBlanketEntries(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is string => typeof entry === "string" && !isBlanket(entry));
}

/**
 * Folds pnpm's removed onlyBuiltDependencies family into the allowBuilds map
 * that replaced it in pnpm 11, deleting the legacy keys as it goes.
 */
function migrateAllowBuilds(yaml: Record<string, unknown>): Record<string, unknown> {
  const allowBuilds = isPlainObject(yaml.allowBuilds) ? yaml.allowBuilds : {};
  const merge = (key: string, allowed: boolean) => {
    const list = yaml[key];
    if (Array.isArray(list)) {
      for (const name of list) {
        if (typeof name === "string" && allowBuilds[name] === undefined) {
          allowBuilds[name] = allowed;
        }
      }
    }
    delete yaml[key];
  };
  merge("onlyBuiltDependencies", true);
  merge("neverBuiltDependencies", false);
  merge("ignoredBuiltDependencies", false);
  delete yaml.onlyBuiltDependenciesFile;
  delete yaml.ignoreDepScripts;
  return allowBuilds;
}

function uvWriteTable(table: Record<string, unknown>): Record<string, unknown> {
  if (table["exclude-newer"] !== undefined || table["index-strategy"] !== undefined) return table;
  if (isPlainObject(table.tool) || table.project !== undefined) {
    const tool = isPlainObject(table.tool) ? table.tool : {};
    table.tool = tool;
    const uv = isPlainObject(tool.uv) ? tool.uv : {};
    tool.uv = uv;
    return uv;
  }
  return table;
}

function resolveSettings(policy: Policy, name: PackageManager): ResolvedSettings {
  const base = PRESET_DEFAULTS[policy.preset];
  const extra = { ...policy.overrides, ...policy.perManager[name] };
  return {
    minReleaseAgeDays:
      typeof extra.minReleaseAgeDays === "number" ? extra.minReleaseAgeDays : base.minReleaseAgeDays,
    auditLevel: typeof extra.auditLevel === "string" ? extra.auditLevel : base.auditLevel,
  };
}

type ParsedTable = { ok: true; value: Record<string, unknown> } | { ok: false };

function parseYaml(raw: string): ParsedTable {
  if (raw.trim() === "") return { ok: true, value: {} };
  try {
    const parsed: unknown = Bun.YAML.parse(raw);
    return isPlainObject(parsed) ? { ok: true, value: parsed } : { ok: false };
  } catch {
    return { ok: false };
  }
}

function stringifyYaml(obj: Record<string, unknown>): string {
  const lines: string[] = [];
  for (const [key, value] of Object.entries(obj)) {
    if (isPlainObject(value) && Object.keys(value).length === 0) {
      lines.push(`${key}: {}`);
    } else if (Array.isArray(value)) {
      if (value.length === 0) {
        lines.push(`${key}: []`);
      } else {
        lines.push(`${key}:`);
        for (const item of value) lines.push(`  - ${yamlScalar(item)}`);
      }
    } else if (isPlainObject(value)) {
      lines.push(`${key}:`);
      for (const [childKey, child] of Object.entries(value)) {
        lines.push(`  ${childKey}: ${yamlScalar(child)}`);
      }
    } else {
      lines.push(`${key}: ${yamlScalar(value)}`);
    }
  }
  return `${lines.join("\n")}\n`;
}

function yamlScalar(value: unknown): string {
  if (typeof value === "string") {
    if (value === "" || /[:#{}[\],&*?|<>=!%@`]/.test(value)) return JSON.stringify(value);
    return value;
  }
  if (typeof value === "boolean" || typeof value === "number") return String(value);
  if (value === null) return "null";
  return JSON.stringify(value);
}

function parseTomlObject(raw: string): ParsedTable {
  if (raw.trim() === "") return { ok: true, value: {} };
  try {
    const parsed: unknown = parseToml(raw);
    return isPlainObject(parsed) ? { ok: true, value: parsed } : { ok: false };
  } catch {
    return { ok: false };
  }
}

function hasToolUv(raw: string): boolean {
  const parsed = parseTomlObject(raw);
  if (!parsed.ok) return false;
  const tool = isPlainObject(parsed.value.tool) ? parsed.value.tool : {};
  return isPlainObject(tool.uv);
}

function hasDefaultRegistry(yaml: Record<string, unknown>): boolean {
  const registries = yaml.registries;
  return isPlainObject(registries) && hasText(registries.default);
}

function bunRegistryPinned(install: Record<string, unknown>): boolean {
  const registry = install.registry;
  if (hasText(registry)) return true;
  return isPlainObject(registry) && hasText(registry.url);
}

function localPath(root: string, name: string): string {
  return root.endsWith("/") ? `${root}${name}` : `${root}/${name}`;
}

function isForbiddenWrite(path: string, root: string): boolean {
  if (path === "~/.npmrc") return true;
  return !isInside(path, root);
}

function isInside(path: string, root: string): boolean {
  const prefix = root.endsWith("/") ? root : `${root}/`;
  return path === root || path.startsWith(prefix);
}

function hasText(value: unknown): boolean {
  return typeof value === "string" && value.trim() !== "";
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

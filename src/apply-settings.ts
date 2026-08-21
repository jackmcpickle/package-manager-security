import { parse as parseToml, stringify as stringifyToml } from "smol-toml";

import { APP_NAME } from "./app-name";
import { parseBundleConfig, stringifyBundleConfig } from "./bundle-config";
import {
  mergeComposerManifest,
  parseComposerManifest,
  stringifyComposerManifest,
} from "./composer-config";
import type {
  DetectedManager,
  Finding,
  PackageManager,
  Policy,
  Project,
} from "./domain";
import { PRESET_DEFAULTS } from "./policy";

export interface ApplyResult {
  written: string[];
  skipped: "dirty" | "nothing" | null;
  committed: boolean;
}

export interface ApplySettingsDeps {
  readFile: (path: string) => string | null;
  writeFile: (path: string, body: string) => void;
  gitStatus: (root: string) => "clean" | "dirty" | "not-git";
  gitCommit?: (root: string, message: string, files: string[]) => boolean;
  force: boolean;
  commit: boolean;
}

export interface ApplySettingsItem {
  project: Project;
  findings: Finding[];
  policy: Policy;
}

const COMMIT_MESSAGE = `chore: apply ${APP_NAME} security settings`;

interface ResolvedSettings {
  minReleaseAgeDays: number;
  auditLevel: string;
}

const DEFAULT_REGISTRY = "https://registry.npmjs.org/";

type ParsedTable = { ok: true; value: Record<string, unknown> } | { ok: false };

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const hasText = (value: unknown): boolean =>
  typeof value === "string" && value.trim() !== "";

const isInside = (filePath: string, root: string): boolean => {
  const prefix = root.endsWith("/") ? root : `${root}/`;
  return filePath === root || filePath.startsWith(prefix);
};

const isForbiddenWrite = (filePath: string, root: string): boolean => {
  if (filePath === "~/.npmrc") {
    return true;
  }
  return !isInside(filePath, root);
};

const localPath = (root: string, name: string): string =>
  root.endsWith("/") ? `${root}${name}` : `${root}/${name}`;

const isBlanket = (entry: unknown): boolean =>
  typeof entry === "string" && /^\*+$/u.test(entry.trim());

/** Strips bare wildcards, which would otherwise void the release-age gate. */
const dropBlanketEntries = (value: unknown): string[] => {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter(
    (entry): entry is string => typeof entry === "string" && !isBlanket(entry)
  );
};

const quoteYamlString = (value: string): string => {
  if (value === "" || /[:#{}[\],&*?|<>=!%@`]/u.test(value)) {
    return JSON.stringify(value);
  }
  return value;
};

const yamlScalar = (value: unknown): string => {
  if (typeof value === "string") {
    return quoteYamlString(value);
  }
  if (typeof value === "boolean" || typeof value === "number") {
    return String(value);
  }
  if (value === null) {
    return "null";
  }
  return JSON.stringify(value);
};

const yamlArrayLines = (key: string, value: unknown[]): string[] => {
  if (value.length === 0) {
    return [`${key}: []`];
  }
  return [`${key}:`, ...value.map((item) => `  - ${yamlScalar(item)}`)];
};

const yamlObjectLines = (
  key: string,
  value: Record<string, unknown>
): string[] => {
  if (Object.keys(value).length === 0) {
    return [`${key}: {}`];
  }
  return [
    `${key}:`,
    ...Object.entries(value).map(
      ([childKey, child]) => `  ${childKey}: ${yamlScalar(child)}`
    ),
  ];
};

const stringifyYaml = (obj: Record<string, unknown>): string => {
  const lines: string[] = [];
  for (const [key, value] of Object.entries(obj)) {
    if (Array.isArray(value)) {
      lines.push(...yamlArrayLines(key, value));
    } else if (isPlainObject(value)) {
      lines.push(...yamlObjectLines(key, value));
    } else {
      lines.push(`${key}: ${yamlScalar(value)}`);
    }
  }
  return `${lines.join("\n")}\n`;
};

const parseYaml = (raw: string): ParsedTable => {
  if (raw.trim() === "") {
    return { ok: true, value: {} };
  }
  try {
    const parsed: unknown = Bun.YAML.parse(raw);
    return isPlainObject(parsed) ? { ok: true, value: parsed } : { ok: false };
  } catch {
    return { ok: false };
  }
};

const parseTomlObject = (raw: string): ParsedTable => {
  if (raw.trim() === "") {
    return { ok: true, value: {} };
  }
  try {
    const parsed: unknown = parseToml(raw);
    return isPlainObject(parsed) ? { ok: true, value: parsed } : { ok: false };
  } catch {
    return { ok: false };
  }
};

const hasToolUv = (raw: string): boolean => {
  const parsed = parseTomlObject(raw);
  if (!parsed.ok) {
    return false;
  }
  const tool = isPlainObject(parsed.value.tool) ? parsed.value.tool : {};
  return isPlainObject(tool.uv);
};

const hasDefaultRegistry = (yaml: Record<string, unknown>): boolean => {
  const { registries } = yaml;
  return isPlainObject(registries) && hasText(registries.default);
};

const bunRegistryPinned = (install: Record<string, unknown>): boolean => {
  const { registry } = install;
  if (hasText(registry)) {
    return true;
  }
  return isPlainObject(registry) && hasText(registry.url);
};

const uvWriteTable = (
  table: Record<string, unknown>
): Record<string, unknown> => {
  if (
    table["exclude-newer"] !== undefined ||
    table["index-strategy"] !== undefined
  ) {
    return table;
  }
  if (isPlainObject(table.tool) || table.project !== undefined) {
    const tool = isPlainObject(table.tool) ? table.tool : {};
    table.tool = tool;
    const uv = isPlainObject(tool.uv) ? tool.uv : {};
    tool.uv = uv;
    return uv;
  }
  return table;
};

/**
 * Folds pnpm's removed onlyBuiltDependencies family into the allowBuilds map
 * that replaced it in pnpm 11, deleting the legacy keys as it goes.
 */
const migrateAllowBuilds = (
  yaml: Record<string, unknown>
): Record<string, unknown> => {
  const allowBuilds = isPlainObject(yaml.allowBuilds) ? yaml.allowBuilds : {};
  const merge = (list: unknown, allowed: boolean) => {
    if (Array.isArray(list)) {
      for (const name of list) {
        if (typeof name === "string" && allowBuilds[name] === undefined) {
          allowBuilds[name] = allowed;
        }
      }
    }
  };
  merge(yaml.onlyBuiltDependencies, true);
  merge(yaml.neverBuiltDependencies, false);
  merge(yaml.ignoredBuiltDependencies, false);
  delete yaml.onlyBuiltDependencies;
  delete yaml.neverBuiltDependencies;
  delete yaml.ignoredBuiltDependencies;
  delete yaml.onlyBuiltDependenciesFile;
  delete yaml.ignoreDepScripts;
  return allowBuilds;
};

const resolveSettings = (
  policy: Policy,
  name: PackageManager
): ResolvedSettings => {
  const base = PRESET_DEFAULTS[policy.preset];
  const extra = { ...policy.overrides, ...policy.perManager[name] };
  return {
    auditLevel:
      typeof extra.auditLevel === "string" ? extra.auditLevel : base.auditLevel,
    minReleaseAgeDays:
      typeof extra.minReleaseAgeDays === "number"
        ? extra.minReleaseAgeDays
        : base.minReleaseAgeDays,
  };
};

const npmrcUpdates = (
  codes: Set<string>,
  settings: ResolvedSettings
): Record<string, string> => {
  const fixes: [
    string,
    Record<string, string> | (() => Record<string, string>),
  ][] = [
    ["scripts.unrestricted", { "ignore-scripts": "true" }],
    [
      "audit.disabled",
      () => ({ audit: "true", "audit-level": settings.auditLevel }),
    ],
    [
      "min-age.disabled",
      () => ({ "min-release-age": String(settings.minReleaseAgeDays) }),
    ],
    [
      "source.non-registry",
      {
        "allow-directory": "none",
        "allow-file": "none",
        "allow-git": "none",
        "allow-remote": "none",
      },
    ],
    ["scripts.pin-missing", { "allow-scripts-pin": "true" }],
    ["scripts.bypass-enabled", { "dangerously-allow-all-scripts": "false" }],
    ["registry.unpinned", { registry: DEFAULT_REGISTRY }],
  ];
  const updates: Record<string, string> = {};
  for (const [code, fix] of fixes) {
    if (!codes.has(code)) {
      continue;
    }
    Object.assign(updates, typeof fix === "function" ? fix() : fix);
  }
  return updates;
};

const rewriteNpmrcLine = (
  line: string,
  updates: Record<string, string>,
  seen: Set<string>
): string => {
  const trimmed = line.trim();
  if (trimmed === "" || trimmed.startsWith("#") || trimmed.startsWith(";")) {
    return line;
  }
  const eq = trimmed.indexOf("=");
  if (eq <= 0) {
    return line;
  }
  const key = trimmed.slice(0, eq).trim();
  if (key in updates) {
    seen.add(key);
    return `${key}=${updates[key]}`;
  }
  return line;
};

const mergeNpmrc = (
  raw: string,
  codes: Set<string>,
  settings: ResolvedSettings
): string => {
  const updates = npmrcUpdates(codes, settings);
  const seen = new Set<string>();
  const lines = raw
    .split(/\r?\n/u)
    .map((line) => rewriteNpmrcLine(line, updates, seen));
  const out = [...lines];
  while (out.length > 0 && out.at(-1) === "") {
    out.pop();
  }
  for (const [key, value] of Object.entries(updates)) {
    if (!seen.has(key)) {
      out.push(`${key}=${value}`);
    }
  }
  return `${out.join("\n")}\n`;
};

const applyPnpmScripts = (
  yaml: Record<string, unknown>,
  codes: Set<string>
): void => {
  if (codes.has("scripts.unrestricted") || codes.has("scripts.legacy-config")) {
    yaml.dangerouslyAllowAllBuilds = false;
    yaml.allowBuilds = migrateAllowBuilds(yaml);
  }
  if (codes.has("scripts.non-strict")) {
    yaml.strictDepBuilds = true;
  }
  if (codes.has("source.non-registry")) {
    yaml.blockExoticSubdeps = true;
  }
};

const applyPnpmAuditAndAge = (
  yaml: Record<string, unknown>,
  codes: Set<string>,
  settings: ResolvedSettings
): void => {
  if (codes.has("audit.disabled")) {
    yaml.audit = true;
    yaml.auditLevel = settings.auditLevel;
  }
  // pnpm reads bare minimumReleaseAge numbers as minutes.
  if (codes.has("min-age.disabled")) {
    yaml.minimumReleaseAge = settings.minReleaseAgeDays * 24 * 60;
  }
  if (codes.has("min-age.non-strict")) {
    yaml.minimumReleaseAgeStrict = true;
  }
  if (codes.has("min-age.missing-time")) {
    yaml.minimumReleaseAgeIgnoreMissingTime = false;
  }
  if (codes.has("min-age.exclude-all")) {
    yaml.minimumReleaseAgeExclude = dropBlanketEntries(
      yaml.minimumReleaseAgeExclude
    );
  }
};

const applyPnpmSecurity = (
  yaml: Record<string, unknown>,
  codes: Set<string>
): void => {
  if (codes.has("provenance.no-downgrade")) {
    yaml.trustPolicy = "no-downgrade";
  }
  if (codes.has("lockfile.trust-bypass")) {
    yaml.trustLockfile = false;
  }
  if (codes.has("lockfile.run-verify")) {
    yaml.verifyDepsBeforeRun = "error";
  }
};

const applyPnpmRegistry = (
  yaml: Record<string, unknown>,
  codes: Set<string>
): void => {
  if (
    codes.has("registry.unpinned") &&
    !hasText(yaml.registry) &&
    !hasDefaultRegistry(yaml)
  ) {
    yaml.registry = DEFAULT_REGISTRY;
  }
};

const mergePnpmYaml = (
  raw: string,
  codes: Set<string>,
  settings: ResolvedSettings
): string | null => {
  const parsed = parseYaml(raw);
  if (!parsed.ok) {
    return null;
  }
  const { value: yaml } = parsed;
  applyPnpmScripts(yaml, codes);
  applyPnpmAuditAndAge(yaml, codes, settings);
  applyPnpmSecurity(yaml, codes);
  applyPnpmRegistry(yaml, codes);
  return stringifyYaml(yaml);
};

const applyYarnScriptsAndAudit = (
  yaml: Record<string, unknown>,
  codes: Set<string>
): void => {
  if (codes.has("scripts.unrestricted")) {
    yaml.enableScripts = false;
  }
  if (codes.has("audit.disabled")) {
    delete yaml.audit;
    delete yaml.npmAudit;
    yaml.enableNpmAudit = true;
  }
  if (codes.has("source.git-unrestricted")) {
    yaml.approvedGitRepositories = [];
  }
};

const applyYarnAgeAndIntegrity = (
  yaml: Record<string, unknown>,
  codes: Set<string>,
  settings: ResolvedSettings
): void => {
  // yarn reads bare npmMinimalAgeGate numbers as minutes.
  if (codes.has("min-age.disabled")) {
    yaml.npmMinimalAgeGate = settings.minReleaseAgeDays * 24 * 60;
  }
  if (codes.has("min-age.exclude-all")) {
    yaml.npmPreapprovedPackages = dropBlanketEntries(
      yaml.npmPreapprovedPackages
    );
  }
  if (codes.has("integrity.checksum-relaxed")) {
    yaml.checksumBehavior = "throw";
  }
  if (codes.has("integrity.strict-ssl")) {
    yaml.enableStrictSsl = true;
  }
  if (codes.has("integrity.hardened-mode")) {
    yaml.enableHardenedMode = true;
  }
};

const applyYarnRegistry = (
  yaml: Record<string, unknown>,
  codes: Set<string>
): void => {
  if (codes.has("registry.unpinned") && !hasText(yaml.npmRegistryServer)) {
    yaml.npmRegistryServer = DEFAULT_REGISTRY;
  }
};

const mergeYarnYaml = (
  raw: string,
  codes: Set<string>,
  settings: ResolvedSettings
): string | null => {
  const parsed = parseYaml(raw);
  if (!parsed.ok) {
    return null;
  }
  const { value: yaml } = parsed;
  applyYarnScriptsAndAudit(yaml, codes);
  applyYarnAgeAndIntegrity(yaml, codes, settings);
  applyYarnRegistry(yaml, codes);
  return stringifyYaml(yaml);
};

const applyBunfigInstall = (
  install: Record<string, unknown>,
  codes: Set<string>,
  settings: ResolvedSettings
): void => {
  if (codes.has("scripts.unrestricted")) {
    install.ignoreScripts = true;
  }
  // bun reads minimumReleaseAge as seconds.
  if (codes.has("min-age.disabled")) {
    install.minimumReleaseAge = settings.minReleaseAgeDays * 86_400;
  }
  if (codes.has("min-age.exclude-all")) {
    install.minimumReleaseAgeExcludes = dropBlanketEntries(
      install.minimumReleaseAgeExcludes
    );
  }
  if (codes.has("registry.unpinned") && !bunRegistryPinned(install)) {
    install.registry = DEFAULT_REGISTRY;
  }
};

const mergeBunfig = (
  raw: string,
  codes: Set<string>,
  settings: ResolvedSettings
): string | null => {
  const parsed = parseTomlObject(raw);
  if (!parsed.ok) {
    return null;
  }
  const table = parsed.value;
  const install = isPlainObject(table.install) ? table.install : {};
  applyBunfigInstall(install, codes, settings);
  table.install = install;
  return `${stringifyToml(table).trimEnd()}\n`;
};

const applyUvFixes = (
  target: Record<string, unknown>,
  codes: Set<string>,
  settings: ResolvedSettings
): void => {
  if (codes.has("min-age.disabled")) {
    target["exclude-newer"] = new Date(
      Date.now() - settings.minReleaseAgeDays * 86_400_000
    ).toISOString();
  }
  if (
    codes.has("min-age.exclude-all") &&
    isPlainObject(target["exclude-newer-package"])
  ) {
    const kept = Object.entries(target["exclude-newer-package"]).filter(
      ([key]) => !isBlanket(key)
    );
    target["exclude-newer-package"] = Object.fromEntries(kept);
  }
  if (codes.has("registry.unpinned")) {
    target["index-strategy"] = "first-index";
  }
  if (codes.has("audit.malware-disabled")) {
    const audit = isPlainObject(target.audit) ? target.audit : {};
    audit["malware-check"] = true;
    target.audit = audit;
  }
};

const mergeUv = (
  raw: string,
  codes: Set<string>,
  settings: ResolvedSettings
): string | null => {
  const parsed = parseTomlObject(raw);
  if (!parsed.ok) {
    return null;
  }
  const table = parsed.value;
  const target = uvWriteTable(table);
  applyUvFixes(target, codes, settings);
  return `${stringifyToml(table).trimEnd()}\n`;
};

/** Only called for a positive `days`; the min-age fix is skipped at or below 0. */
const cargoDuration = (days: number): string => {
  if (days % 7 === 0) {
    return `${days / 7}w`;
  }
  return `${days}d`;
};

const mergeCargo = (
  raw: string,
  codes: Set<string>,
  settings: ResolvedSettings
): string | null => {
  const parsed = parseTomlObject(raw);
  if (!parsed.ok) {
    return null;
  }
  const table = parsed.value;
  const install = isPlainObject(table.install) ? table.install : {};
  if (codes.has("min-age.disabled")) {
    install["minimum-release-age"] = cargoDuration(settings.minReleaseAgeDays);
  }
  table.install = install;
  return `${stringifyToml(table).trimEnd()}\n`;
};

const mergeComposer = (raw: string, codes: Set<string>): string | null => {
  const parsed = parseComposerManifest(raw);
  if (parsed === null) {
    return null;
  }
  return stringifyComposerManifest(mergeComposerManifest(parsed, codes));
};

const mergeBundleConfig = (
  raw: string,
  codes: Set<string>,
  settings: ResolvedSettings
): string => {
  const config = parseBundleConfig(raw);
  if (codes.has("min-age.disabled")) {
    config["BUNDLE_COOLDOWN"] = String(settings.minReleaseAgeDays);
  }
  return stringifyBundleConfig(config);
};

const renderConfig = (
  manager: PackageManager,
  raw: string,
  codes: Set<string>,
  settings: ResolvedSettings
): string | null => {
  if (manager === "npm") {
    return mergeNpmrc(raw, codes, settings);
  }
  if (manager === "pnpm") {
    return mergePnpmYaml(raw, codes, settings);
  }
  if (manager === "yarn") {
    return mergeYarnYaml(raw, codes, settings);
  }
  if (manager === "bun") {
    return mergeBunfig(raw, codes, settings);
  }
  if (manager === "cargo") {
    return mergeCargo(raw, codes, settings);
  }
  if (manager === "bundler") {
    return mergeBundleConfig(raw, codes, settings);
  }
  if (manager === "composer") {
    return mergeComposer(raw, codes);
  }
  return mergeUv(raw, codes, settings);
};

const uvConfigPath = (
  project: Project,
  manager: DetectedManager,
  readFile: (path: string) => string | null
): string => {
  const uvToml = localPath(project.root, "uv.toml");
  if (readFile(uvToml) !== null) {
    return uvToml;
  }
  const pyproject = localPath(project.root, "pyproject.toml");
  if (
    manager.configPath !== null &&
    isInside(manager.configPath, project.root) &&
    manager.configPath.endsWith("pyproject.toml")
  ) {
    return manager.configPath;
  }
  const raw = readFile(pyproject);
  if (raw !== null && hasToolUv(raw)) {
    return pyproject;
  }
  return uvToml;
};

const LOCAL_CONFIG_FILE: Partial<Record<PackageManager, string>> = {
  bun: "bunfig.toml",
  bundler: ".bundle/config",
  composer: "composer.json",
  npm: ".npmrc",
  pnpm: "pnpm-workspace.yaml",
  yarn: ".yarnrc.yml",
};

const configPathFor = (
  project: Project,
  manager: DetectedManager,
  readFile: (path: string) => string | null
): string | null => {
  if (manager.name === "uv") {
    return uvConfigPath(project, manager, readFile);
  }
  if (manager.name === "cargo") {
    return manager.configPath ?? localPath(project.root, ".cargo/config.toml");
  }
  const file = LOCAL_CONFIG_FILE[manager.name];
  return file ? localPath(project.root, file) : null;
};

const isSettingsFix = (finding: Finding): boolean =>
  finding.fixable &&
  finding.kind === "settings" &&
  finding.code !== "lockfile.missing" &&
  finding.code !== "pm.unpinned";

const primaryManager = (
  project: Project,
  name: PackageManager
): DetectedManager | undefined =>
  project.managers.find((row) => row.name === name && row.role === "primary");

const collectTargets = (
  project: Project,
  findings: Finding[],
  readFile: (path: string) => string | null
): Map<string, { manager: PackageManager; codes: Set<string> }> => {
  const targets = new Map<
    string,
    { manager: PackageManager; codes: Set<string> }
  >();

  for (const finding of findings) {
    if (!isSettingsFix(finding)) {
      continue;
    }
    const name = finding.manager;
    if (name === undefined) {
      continue;
    }
    const manager = primaryManager(project, name);
    if (manager === undefined) {
      continue;
    }

    const filePath = configPathFor(project, manager, readFile);
    if (filePath === null || isForbiddenWrite(filePath, project.root)) {
      continue;
    }

    const entry = targets.get(filePath) ?? {
      codes: new Set<string>(),
      manager: name,
    };
    entry.codes.add(finding.code);
    targets.set(filePath, entry);
  }

  return targets;
};

const writeSettings = (
  project: Project,
  findings: Finding[],
  policy: Policy,
  deps: ApplySettingsDeps
): string[] => {
  const written: string[] = [];
  for (const [filePath, target] of collectTargets(
    project,
    findings,
    deps.readFile
  )) {
    const next = renderConfig(
      target.manager,
      deps.readFile(filePath) ?? "",
      target.codes,
      resolveSettings(policy, target.manager)
    );
    if (next === null) {
      continue;
    }
    deps.writeFile(filePath, next);
    written.push(filePath);
  }
  return written;
};

const emptyApply = (skipped: "nothing" | "dirty"): ApplyResult => ({
  committed: false,
  skipped,
  written: [],
});

const isDirtyRoot = (deps: ApplySettingsDeps, gitRoot: string): boolean =>
  !deps.force && deps.gitStatus(gitRoot) !== "clean";

const maybeCommit = (
  deps: ApplySettingsDeps,
  gitRoot: string,
  written: string[]
): boolean =>
  Boolean(
    deps.commit &&
    deps.gitCommit &&
    deps.gitCommit(gitRoot, COMMIT_MESSAGE, written)
  );

export const applySettingsGroup = (
  items: ApplySettingsItem[],
  deps: ApplySettingsDeps
): ApplyResult => {
  const [first] = items;
  if (first === undefined) {
    return emptyApply("nothing");
  }

  const gitRoot = first.project.gitRoot ?? first.project.root;
  if (isDirtyRoot(deps, gitRoot)) {
    return emptyApply("dirty");
  }

  const written: string[] = [];
  for (const item of items) {
    written.push(
      ...writeSettings(item.project, item.findings, item.policy, deps)
    );
  }

  if (written.length === 0) {
    return emptyApply("nothing");
  }

  return {
    committed: maybeCommit(deps, gitRoot, written),
    skipped: null,
    written,
  };
};

export const applySettings = (
  project: Project,
  findings: Finding[],
  policy: Policy,
  deps: ApplySettingsDeps
): ApplyResult => applySettingsGroup([{ findings, policy, project }], deps);

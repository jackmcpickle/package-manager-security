import { parse as parseTomlRaw } from "smol-toml";

import { parseBundleConfig } from "./bundle-config";
import { parseComposerManifest, readComposerSecurity } from "./composer-config";
import type {
  ConfigEdit,
  ConfigEditValue,
  ConfigFormat,
  DetectedManager,
  Finding,
  PackageManager,
  Policy,
  PresetName,
  Project,
  SettingsFix,
  Severity,
} from "./domain";
import { profileFor } from "./managers/profile";
import { resolveSettings } from "./policy";
import type { ResolvedSettings } from "./policy";

export interface SettingsFs {
  readFile: (path: string) => string | null;
}

type ReadFile = (path: string) => string | null;

interface ManagerVersion {
  major: number;
  minor: number;
  patch: number;
}

type ManagerAuditor = (
  project: Project,
  manager: DetectedManager,
  policy: Policy,
  readFile: ReadFile
) => Finding[];

const AUDIT_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  info: 0,
  low: 1,
  moderate: 2,
};

const PNPM_LEGACY_BUILD_KEYS = [
  "onlyBuiltDependencies",
  "onlyBuiltDependenciesFile",
  "neverBuiltDependencies",
  "ignoredBuiltDependencies",
  "ignoreDepScripts",
] as const;

const BUN_AUTO_SCRIPT_VALUES: ReadonlySet<string> = new Set([
  "auto",
  "force",
  "fallback",
  "true",
  "all",
]);

const MANAGER_VERSION_PATTERN =
  /^(?<name>[a-z]+)@(?<major>\d+)\.(?<minor>\d+)(?:\.(?<patch>\d+))?/u;

const YARN_BERRY_PATTERN =
  /^yarn@(?<major>0|[1-9]\d*)\.(?<minor>0|[1-9]\d*)\.(?<patch>0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u;

const AGE_UNIT_PATTERN =
  /^(?<amount>\d+(?:\.\d+)?)\s*(?<unit>m|min|mins|minutes|h|hr|hrs|hours|d|day|days|w|week|weeks)?$/u;

const STAR_PATTERN = /^\*+$/u;

const NPMRC_LINE_BREAK = /\r?\n/u;

const DEFAULT_REGISTRY = "https://registry.npmjs.org/";

const MINUTES_PER_DAY = 24 * 60;

const SECONDS_PER_DAY = 86_400;

const MS_PER_DAY = 86_400_000;

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const hasText = (value: unknown): boolean =>
  typeof value === "string" && value.trim() !== "";

const parseNumber = (value: unknown): number | null => {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value !== "string") {
    return null;
  }
  const n = Number(value.trim());
  return Number.isFinite(n) ? n : null;
};

const isTruthy = (value: unknown): boolean =>
  value === true || value === "true";

const isStar = (entry: unknown): boolean =>
  typeof entry === "string" && STAR_PATTERN.test(entry.trim());

/** True when an exclude list uses a bare wildcard, which voids the gate. */
const isBlanketExclude = (value: unknown): boolean => {
  if (isStar(value)) {
    return true;
  }
  if (Array.isArray(value)) {
    return value.some(isStar);
  }
  if (isPlainObject(value)) {
    return Object.keys(value).some(isStar);
  }
  return false;
};

const parseNpmrc = (raw: string): Record<string, string> => {
  const out: Record<string, string> = {};
  for (const line of raw.split(NPMRC_LINE_BREAK)) {
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#") || trimmed.startsWith(";")) {
      continue;
    }
    const eq = trimmed.indexOf("=");
    if (eq <= 0) {
      continue;
    }
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim();
    out[key] = value;
  }
  return out;
};

const parseYaml = (raw: string): Record<string, unknown> => {
  if (raw.trim() === "") {
    return {};
  }
  try {
    const parsed: unknown = Bun.YAML.parse(raw);
    return isPlainObject(parsed) ? parsed : {};
  } catch {
    return {};
  }
};

const parseToml = (raw: string): Record<string, unknown> => {
  if (raw.trim() === "") {
    return {};
  }
  try {
    const parsed: unknown = parseTomlRaw(raw);
    return isPlainObject(parsed) ? parsed : {};
  } catch {
    return {};
  }
};

const manifestField = (raw: string | null, key: string): unknown => {
  if (raw === null) {
    return undefined;
  }
  try {
    const parsed: unknown = JSON.parse(raw);
    return isPlainObject(parsed) ? parsed[key] : undefined;
  } catch {
    return undefined;
  }
};

const setOp = (key: string, value: ConfigEditValue): ConfigEdit => ({
  key,
  op: "set",
  value,
});

const unsetOp = (key: string): ConfigEdit => ({ key, op: "unset" });

const configFix = (
  file: string,
  format: ConfigFormat,
  edits: readonly ConfigEdit[]
): SettingsFix => ({ edits, file, format });

const setting = (
  code: string,
  message: string,
  severity: Severity,
  path: string,
  manager: PackageManager,
  fix?: SettingsFix
): Finding => ({
  code,
  fixable: true,
  kind: "settings",
  manager,
  message,
  path,
  severity,
  ...(fix === undefined ? {} : { fix }),
});

/**
 * A finding that flags a weaker-than-ideal but not broken configuration —
 * typically relying on a safe default instead of pinning it explicitly.
 * Those are safe to write automatically; notes needing human judgement are not.
 */
const advice = (
  code: string,
  message: string,
  path: string,
  manager: PackageManager,
  severity: Severity = "info",
  fixable = false,
  fix?: SettingsFix
): Finding => ({
  code,
  fixable,
  kind: "settings",
  manager,
  message,
  path,
  severity,
  ...(fix === undefined ? {} : { fix }),
});

const leftoverFinding = (manager: DetectedManager): Finding => ({
  code: "lockfile.leftover",
  fixable: false,
  kind: "leftover-lockfile",
  manager: manager.name,
  message: `Leftover ${manager.name} lockfile is not an apply target`,
  path: manager.lockfilePath ?? manager.manifestPath,
  severity: "high",
});

const unsupportedFinding = (manager: DetectedManager): Finding => ({
  code: "pm.unsupported",
  fixable: false,
  kind: "unsupported-pm",
  manager: manager.name,
  message: `${manager.name} is unsupported`,
  path: manager.lockfilePath ?? manager.manifestPath,
  severity: "high",
});

const notUsingUvFinding = (manager: DetectedManager): Finding => ({
  code: "python.not-uv",
  fixable: false,
  kind: "not-using-uv",
  manager: manager.name,
  message: `${manager.name} project is not using uv`,
  path: manager.lockfilePath ?? manager.manifestPath,
  severity: "high",
});

const joinRoot = (root: string, name: string): string =>
  root.endsWith("/") ? `${root}${name}` : `${root}/${name}`;

const isInside = (filePath: string, root: string): boolean => {
  const prefix = root.endsWith("/") ? root : `${root}/`;
  return filePath === root || filePath.startsWith(prefix);
};

const profileWritePath = (
  project: Project,
  manager: PackageManager
): string | null => {
  const name = profileFor(manager).writeConfigName;
  return name === null ? null : joinRoot(project.root, name);
};

const cargoDuration = (days: number): string => {
  if (days % 7 === 0) {
    return `${days / 7}w`;
  }
  return `${days}d`;
};

const uvExcludeNewerValue = (days: number): string =>
  new Date(Date.now() - days * MS_PER_DAY).toISOString();

const presentLegacyBuildKeys = (
  yaml: Record<string, unknown>
): (typeof PNPM_LEGACY_BUILD_KEYS)[number][] =>
  PNPM_LEGACY_BUILD_KEYS.filter((key) => yaml[key] !== undefined);

const migratedAllowBuilds = (
  yaml: Record<string, unknown>
): Record<string, unknown> => {
  const allowBuilds: Record<string, unknown> = isPlainObject(yaml.allowBuilds)
    ? { ...yaml.allowBuilds }
    : {};
  const merge = (list: unknown, allowed: boolean): void => {
    if (!Array.isArray(list)) {
      return;
    }
    for (const name of list) {
      if (typeof name === "string" && allowBuilds[name] === undefined) {
        allowBuilds[name] = allowed;
      }
    }
  };
  merge(yaml.onlyBuiltDependencies, true);
  merge(yaml.neverBuiltDependencies, false);
  merge(yaml.ignoredBuiltDependencies, false);
  return allowBuilds;
};

const pnpmBuildEdits = (yaml: Record<string, unknown>): ConfigEdit[] => [
  setOp("dangerouslyAllowAllBuilds", false),
  ...presentLegacyBuildKeys(yaml).map((key) => unsetOp(key)),
  setOp("allowBuilds", migratedAllowBuilds(yaml)),
];

const dropBlanketEntries = (value: unknown): string[] => {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter(
    (entry): entry is string => typeof entry === "string" && !isStar(entry)
  );
};

const dropBlanketObject = (
  value: Record<string, unknown>
): Record<string, string | number | boolean> => {
  const kept: Record<string, string | number | boolean> = {};
  for (const [key, child] of Object.entries(value)) {
    if (isStar(key)) {
      continue;
    }
    if (
      typeof child === "string" ||
      typeof child === "number" ||
      typeof child === "boolean"
    ) {
      kept[key] = child;
    }
  }
  return kept;
};

const pinSeverity = (preset: PresetName): Severity =>
  preset === "strict" ? "high" : "info";

const defaultRelianceSeverity = (preset: PresetName): Severity =>
  preset === "strict" ? "moderate" : "info";

/** Reads the pinned version out of package.json `packageManager`. */
const managerVersion = (
  raw: string | null,
  name: string
): ManagerVersion | null => {
  const field = manifestField(raw, "packageManager");
  if (typeof field !== "string") {
    return null;
  }
  const match = MANAGER_VERSION_PATTERN.exec(field);
  if (match?.groups === undefined || match.groups["name"] !== name) {
    return null;
  }
  return {
    major: Number(match.groups["major"]),
    minor: Number(match.groups["minor"]),
    patch: Number(match.groups["patch"] ?? "0"),
  };
};

/**
 * True when the pinned version is at least `major.minor`, or when no version is
 * pinned at all — an unpinned repo is assumed to be on a current release, and
 * `pm.unpinned` already nags about the missing pin.
 */
const atLeastOrUnknown = (
  version: ManagerVersion | null,
  major: number,
  minor = 0
): boolean => {
  if (version === null) {
    return true;
  }
  if (version.major !== major) {
    return version.major > major;
  }
  return version.minor >= minor;
};

/** Like atLeastOrUnknown, but also compares patch when major.minor matches. */
const atLeastPatchOrUnknown = (
  version: ManagerVersion | null,
  major: number,
  minor: number,
  patch: number
): boolean => {
  if (version === null) {
    return true;
  }
  if (version.major !== major) {
    return version.major > major;
  }
  if (version.minor !== minor) {
    return version.minor > minor;
  }
  return version.patch >= patch;
};

const lockfilePresent = (
  manager: DetectedManager,
  readFile: ReadFile,
  fallback: string
): boolean => {
  const path = manager.lockfilePath ?? fallback;
  return readFile(path) !== null;
};

const auditMeetsGate = (
  auditEnabled: boolean,
  auditLevel: unknown,
  gate: string
): boolean => {
  if (auditEnabled) {
    return true;
  }
  const level = typeof auditLevel === "string" ? auditLevel.toLowerCase() : "";
  const have = AUDIT_RANK[level];
  const need = AUDIT_RANK[gate] ?? AUDIT_RANK.high;
  return have !== undefined && need !== undefined && have <= need;
};

const packageManagerStartsWith = (
  raw: string | null,
  prefix: string
): boolean => {
  if (raw === null) {
    return false;
  }
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!isPlainObject(parsed)) {
      return false;
    }
    return (
      typeof parsed.packageManager === "string" &&
      parsed.packageManager.startsWith(prefix)
    );
  } catch {
    return false;
  }
};

const packageManagerYarnBerry = (raw: string | null): boolean => {
  if (raw === null) {
    return false;
  }
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!isPlainObject(parsed)) {
      return false;
    }
    const field = parsed.packageManager;
    if (typeof field !== "string") {
      return false;
    }
    const match = YARN_BERRY_PATTERN.exec(field);
    if (match?.groups === undefined) {
      return false;
    }
    return Number(match.groups["major"]) >= 2;
  } catch {
    return false;
  }
};

/** npm 12 defaults allow-git and allow-remote to "none"; allow-file/directory default to "all". */
const npmrcAllowsNonRegistry = (npmrc: Record<string, string>): boolean =>
  npmrc["allow-git"] === "all" ||
  npmrc["allow-remote"] === "all" ||
  npmrc["allow-file"] === "all" ||
  npmrc["allow-directory"] === "all";

const pnpmRegistryPinned = (yaml: Record<string, unknown>): boolean => {
  if (hasText(yaml["registry"])) {
    return true;
  }
  const { registries } = yaml;
  if (!isPlainObject(registries)) {
    return false;
  }
  return hasText(registries["default"]);
};

const bareMinutesToHours = (trimmed: string): number | null => {
  const bare = parseNumber(trimmed);
  return bare === null ? null : bare / 60;
};

const unitToHours = (amount: number, unit: string): number => {
  if (unit.startsWith("w")) {
    return amount * 24 * 7;
  }
  if (unit.startsWith("d")) {
    return amount * 24;
  }
  if (unit.startsWith("m")) {
    return amount / 60;
  }
  return amount;
};

const parsePnpmAgeHours = (value: unknown): number | null => {
  // pnpm treats bare minimumReleaseAge numbers as MINUTES.
  if (typeof value === "number" && Number.isFinite(value)) {
    return value / 60;
  }
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim().toLowerCase();
  const match = AGE_UNIT_PATTERN.exec(trimmed);
  if (match?.groups === undefined) {
    return bareMinutesToHours(trimmed);
  }
  const amount = Number(match.groups["amount"]);
  if (!Number.isFinite(amount)) {
    return null;
  }
  return unitToHours(amount, match.groups["unit"] ?? "m");
};

const yarnAuditDisabled = (yarnrc: Record<string, unknown>): boolean =>
  [yarnrc["audit"], yarnrc["npmAudit"], yarnrc["enableNpmAudit"]].includes(
    false
  );

/** True when git deps are fully blocked via an empty approvedGitRepositories. */
const yarnGitReposBlocked = (yarnrc: Record<string, unknown>): boolean => {
  const raw = yarnrc["approvedGitRepositories"];
  if (!Array.isArray(raw)) {
    return false;
  }
  if (raw.length === 0) {
    return true;
  }
  return !raw.some(isStar);
};

const readUvAudit = (cfg: Record<string, unknown>): Record<string, unknown> => {
  const { audit } = cfg;
  return isPlainObject(audit) ? audit : {};
};

const bunAutoAllowsScripts = (auto: unknown): boolean => {
  if (auto === true) {
    return true;
  }
  if (typeof auto !== "string") {
    return false;
  }
  return BUN_AUTO_SCRIPT_VALUES.has(auto.trim().toLowerCase());
};

const bunDenyScripts = (
  bunfig: Record<string, unknown>,
  install: Record<string, unknown>
): boolean =>
  [
    bunfig["ignoreScripts"],
    install["ignoreScripts"],
    bunfig["ignore-scripts"],
    install["ignore-scripts"],
  ].includes(true);

const bunHasTrusted = (
  bunfig: Record<string, unknown>,
  install: Record<string, unknown>
): boolean =>
  bunfig["trustedDependencies"] !== undefined ||
  install["trustedDependencies"] !== undefined;

const bunScriptsUnrestricted = (
  bunfig: Record<string, unknown>,
  install: Record<string, unknown>
): boolean => {
  if (bunAutoAllowsScripts(install["auto"])) {
    return true;
  }
  const hasSecurity = isPlainObject(install["security"]);
  return (
    !bunHasTrusted(bunfig, install) &&
    !hasSecurity &&
    !bunDenyScripts(bunfig, install)
  );
};

const bunRegistryPinned = (install: Record<string, unknown>): boolean => {
  const { registry } = install;
  if (hasText(registry)) {
    return true;
  }
  return isPlainObject(registry) && hasText(registry["url"]);
};

const bunLockfilePresent = (
  project: Project,
  manager: DetectedManager,
  readFile: ReadFile
): boolean => {
  if (
    manager.lockfilePath !== null &&
    readFile(manager.lockfilePath) !== null
  ) {
    return true;
  }
  return profileFor("bun").lockfileNames.some(
    (name) => readFile(`${project.root}/${name}`) !== null
  );
};

const readUvConfig = (
  project: Project,
  readFile: ReadFile
): Record<string, unknown> => {
  const [uvTomlName, pyprojectName] = profileFor("uv").configNames;
  const pyproject = parseToml(
    readFile(`${project.root}/${pyprojectName ?? "pyproject.toml"}`) ?? ""
  );
  const tool = isPlainObject(pyproject["tool"]) ? pyproject["tool"] : {};
  const toolUv = isPlainObject(tool["uv"]) ? tool["uv"] : {};
  const uvToml = parseToml(
    readFile(`${project.root}/${uvTomlName ?? "uv.toml"}`) ?? ""
  );
  return { ...toolUv, ...uvToml };
};

const hasToolUv = (raw: string): boolean => {
  const parsed = parseToml(raw);
  const tool = isPlainObject(parsed.tool) ? parsed.tool : {};
  return isPlainObject(tool.uv);
};

const uvConfigPath = (
  project: Project,
  manager: DetectedManager,
  readFile: ReadFile
): string => {
  const [uvTomlName, pyprojectName] = profileFor("uv").configNames;
  const uvToml = joinRoot(project.root, uvTomlName ?? "uv.toml");
  if (readFile(uvToml) !== null) {
    return uvToml;
  }
  const pyproject = joinRoot(project.root, pyprojectName ?? "pyproject.toml");
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

const uvKeyPrefix = (raw: string): string => {
  const table = parseToml(raw);
  if (
    table["exclude-newer"] !== undefined ||
    table["index-strategy"] !== undefined
  ) {
    return "";
  }
  if (isPlainObject(table.tool) || table.project !== undefined) {
    return "tool.uv.";
  }
  return "";
};

/** Returns null when the value is not a timestamp and other parses apply. */
const uvDateMeets = (trimmed: string, minDays: number): boolean | null => {
  if (!/[tT-]/u.test(trimmed)) {
    return null;
  }
  const ts = Date.parse(trimmed);
  if (Number.isNaN(ts)) {
    return null;
  }
  return Date.now() - ts >= minDays * 86_400_000;
};

const uvExcludeNewerStringMeets = (
  trimmed: string,
  minDays: number
): boolean => {
  if (trimmed === "") {
    return false;
  }
  const asNumber = Number(trimmed);
  if (Number.isFinite(asNumber) && trimmed === String(asNumber)) {
    return asNumber >= minDays;
  }
  const dateMeets = uvDateMeets(trimmed, minDays);
  if (dateMeets !== null) {
    return dateMeets;
  }
  const hours = parsePnpmAgeHours(trimmed);
  return hours !== null && hours / 24 >= minDays;
};

const uvExcludeNewerMeets = (value: unknown, minDays: number): boolean => {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value >= minDays;
  }
  if (typeof value !== "string") {
    return false;
  }
  return uvExcludeNewerStringMeets(value.trim(), minDays);
};

const hasExtraIndexUrl = (extra: unknown): boolean => {
  if (typeof extra === "string") {
    return extra.trim() !== "";
  }
  return Array.isArray(extra) && extra.length > 0;
};

const uvIndexIsExtra = (entry: unknown): boolean =>
  isPlainObject(entry) && entry["default"] !== true;

const uvIndexListExtra = (index: unknown): boolean => {
  if (!Array.isArray(index)) {
    return false;
  }
  return index.length > 1 || index.some(uvIndexIsExtra);
};

const uvHasExtraIndexes = (cfg: Record<string, unknown>): boolean =>
  hasExtraIndexUrl(cfg["extra-index-url"]) || uvIndexListExtra(cfg["index"]);

const lockfileMissingFinding = (
  required: boolean,
  present: boolean,
  path: string,
  message: string,
  manager: PackageManager
): Finding[] =>
  required && !present
    ? [setting("lockfile.missing", message, "high", path, manager)]
    : [];

const pmPinFinding = (
  required: boolean,
  pinned: boolean,
  message: string,
  preset: PresetName,
  path: string,
  manager: PackageManager
): Finding[] =>
  required && !pinned
    ? [setting("pm.unpinned", message, pinSeverity(preset), path, manager)]
    : [];

const registryUnpinnedFinding = (
  pinned: boolean,
  message: string,
  preset: PresetName,
  path: string,
  manager: PackageManager,
  fix?: SettingsFix
): Finding[] =>
  pinned
    ? []
    : [
        setting(
          "registry.unpinned",
          message,
          pinSeverity(preset),
          path,
          manager,
          fix
        ),
      ];

const blanketExcludeFinding = (
  value: unknown,
  message: string,
  path: string,
  manager: PackageManager,
  fix?: SettingsFix
): Finding[] =>
  isBlanketExclude(value)
    ? [setting("min-age.exclude-all", message, "high", path, manager, fix)]
    : [];

// An enforced package.json allowScripts policy is a valid, more precise
// alternative to blanket ignore-scripts. It is only enforced once
// strict-allow-scripts is on; until then npm 11 merely warns.
const npmScriptEnforcementFinding = (
  settings: ResolvedSettings,
  scriptsIgnored: boolean,
  allowScripts: boolean,
  strictAllowScripts: boolean,
  npmrcPath: string,
  file: string
): Finding[] => {
  if (
    settings.ignoreScripts &&
    !scriptsIgnored &&
    !(allowScripts && strictAllowScripts)
  ) {
    return [
      setting(
        "scripts.unrestricted",
        "npm ignore-scripts must be true, or allowScripts with strict-allow-scripts",
        "high",
        npmrcPath,
        "npm",
        configFix(file, "npmrc", [setOp("ignore-scripts", true)])
      ),
    ];
  }
  return [];
};

const npmScriptAdviceFindings = (
  settings: ResolvedSettings,
  scriptsIgnored: boolean,
  allowScripts: boolean,
  strictAllowScripts: boolean,
  npmrcPath: string
): Finding[] => {
  const findings: Finding[] = [];
  if (settings.ignoreScripts && allowScripts && !strictAllowScripts) {
    findings.push(
      advice(
        "scripts.allowlist-advisory",
        "allowScripts is advisory until strict-allow-scripts=true (npm 12 default)",
        npmrcPath,
        "npm"
      )
    );
  }
  // npm/cli#9450: ignore-scripts hides the allowScripts tooling entirely.
  if (scriptsIgnored && allowScripts) {
    findings.push(
      advice(
        "scripts.allowlist-masked",
        "ignore-scripts=true masks the package.json allowScripts policy",
        npmrcPath,
        "npm"
      )
    );
  }
  return findings;
};

const npmScriptPinFinding = (
  settings: ResolvedSettings,
  npmrc: Record<string, string>,
  npmrcPath: string,
  preset: PresetName,
  file: string
): Finding[] => {
  if (!settings.ignoreScripts || npmrc["allow-scripts-pin"] === "true") {
    return [];
  }
  const pinFix = configFix(file, "npmrc", [setOp("allow-scripts-pin", true)]);
  if (npmrc["allow-scripts-pin"] === "false") {
    return [
      setting(
        "scripts.pin-missing",
        "allow-scripts-pin must be true",
        "high",
        npmrcPath,
        "npm",
        pinFix
      ),
    ];
  }
  return [
    advice(
      "scripts.pin-missing",
      "npm defaults allow-scripts-pin to true; set it explicitly",
      npmrcPath,
      "npm",
      defaultRelianceSeverity(preset),
      true,
      pinFix
    ),
  ];
};

const npmScriptBypassFinding = (
  settings: ResolvedSettings,
  npmrc: Record<string, string>,
  npmrcPath: string,
  file: string
): Finding[] => {
  if (
    !settings.ignoreScripts ||
    npmrc["dangerously-allow-all-scripts"] !== "true"
  ) {
    return [];
  }
  return [
    setting(
      "scripts.bypass-enabled",
      "dangerously-allow-all-scripts must not be true",
      "high",
      npmrcPath,
      "npm",
      configFix(file, "npmrc", [setOp("dangerously-allow-all-scripts", false)])
    ),
  ];
};

const npmScriptsFindings = (
  settings: ResolvedSettings,
  npmrc: Record<string, string>,
  manifestRaw: string | null,
  npmrcPath: string,
  preset: PresetName,
  file: string
): Finding[] => {
  const scriptsIgnored = npmrc["ignore-scripts"] === "true";
  const allowScripts = isPlainObject(
    manifestField(manifestRaw, "allowScripts")
  );
  const strictAllowScripts = npmrc["strict-allow-scripts"] === "true";
  return [
    ...npmScriptEnforcementFinding(
      settings,
      scriptsIgnored,
      allowScripts,
      strictAllowScripts,
      npmrcPath,
      file
    ),
    ...npmScriptAdviceFindings(
      settings,
      scriptsIgnored,
      allowScripts,
      strictAllowScripts,
      npmrcPath
    ),
    ...npmScriptPinFinding(settings, npmrc, npmrcPath, preset, file),
    ...npmScriptBypassFinding(settings, npmrc, npmrcPath, file),
  ];
};

const npmSourceFinding = (
  settings: ResolvedSettings,
  npmrc: Record<string, string>,
  npmrcPath: string,
  file: string
): Finding[] => {
  if (settings.ignoreScripts && npmrcAllowsNonRegistry(npmrc)) {
    return [
      setting(
        "source.non-registry",
        "allow-git, allow-remote, allow-file, and allow-directory must not be set to all",
        "high",
        npmrcPath,
        "npm",
        configFix(file, "npmrc", [
          setOp("allow-directory", "none"),
          setOp("allow-file", "none"),
          setOp("allow-git", "none"),
          setOp("allow-remote", "none"),
        ])
      ),
    ];
  }
  return [];
};

const npmAuditFinding = (
  npmrc: Record<string, string>,
  settings: ResolvedSettings,
  npmrcPath: string,
  file: string
): Finding[] => {
  if (
    auditMeetsGate(
      npmrc["audit"] === "true",
      npmrc["audit-level"],
      settings.auditLevel
    )
  ) {
    return [];
  }
  return [
    setting(
      "audit.disabled",
      "npm audit must be enabled at the preset gate",
      "high",
      npmrcPath,
      "npm",
      configFix(file, "npmrc", [
        setOp("audit", true),
        setOp("audit-level", settings.auditLevel),
      ])
    ),
  ];
};

const npmMinAgeFinding = (
  settings: ResolvedSettings,
  npmrc: Record<string, string>,
  npmrcPath: string,
  file: string
): Finding[] => {
  if (settings.minReleaseAgeDays <= 0) {
    return [];
  }
  const days = parseNumber(npmrc["min-release-age"]);
  if (days !== null && days >= settings.minReleaseAgeDays) {
    return [];
  }
  return [
    setting(
      "min-age.disabled",
      `min-release-age must be at least ${settings.minReleaseAgeDays} days`,
      "high",
      npmrcPath,
      "npm",
      configFix(file, "npmrc", [
        setOp("min-release-age", String(settings.minReleaseAgeDays)),
      ])
    ),
  ];
};

const auditNpm: ManagerAuditor = (project, manager, policy, readFile) => {
  const settings = resolveSettings(policy, "npm");
  const npmrcPath =
    manager.configPath ??
    `${project.root}/${profileFor("npm").configNames[0] ?? ".npmrc"}`;
  const file = profileWritePath(project, "npm") ?? npmrcPath;
  const npmrc = parseNpmrc(readFile(npmrcPath) ?? "");
  const manifestRaw = readFile(manager.manifestPath);
  return [
    ...npmScriptsFindings(
      settings,
      npmrc,
      manifestRaw,
      npmrcPath,
      policy.preset,
      file
    ),
    ...npmSourceFinding(settings, npmrc, npmrcPath, file),
    ...lockfileMissingFinding(
      settings.requireLockfile,
      lockfilePresent(manager, readFile, `${project.root}/package-lock.json`),
      manager.lockfilePath ?? `${project.root}/package-lock.json`,
      "package-lock.json is required",
      "npm"
    ),
    ...npmAuditFinding(npmrc, settings, npmrcPath, file),
    ...npmMinAgeFinding(settings, npmrc, npmrcPath, file),
    ...registryUnpinnedFinding(
      hasText(npmrc["registry"]),
      "registry must be set in .npmrc",
      policy.preset,
      npmrcPath,
      "npm",
      configFix(file, "npmrc", [setOp("registry", DEFAULT_REGISTRY)])
    ),
    ...pmPinFinding(
      settings.requirePmPin,
      packageManagerStartsWith(manifestRaw, "npm@"),
      "package.json packageManager must start with npm@",
      policy.preset,
      manager.manifestPath,
      "npm"
    ),
  ];
};

const pnpmDefaultBuildsFinding = (
  preset: PresetName,
  yamlPath: string,
  buildsBlockedByDefault: boolean,
  file: string,
  yaml: Record<string, unknown>
): Finding => {
  const fix = configFix(file, "yaml", pnpmBuildEdits(yaml));
  return buildsBlockedByDefault
    ? advice(
        "scripts.unrestricted",
        "pnpm blocks dependency builds by default; declare allowBuilds to review them explicitly",
        yamlPath,
        "pnpm",
        defaultRelianceSeverity(preset),
        true,
        fix
      )
    : setting(
        "scripts.unrestricted",
        "pnpm builds must be restricted",
        "high",
        yamlPath,
        "pnpm",
        fix
      );
};

const pnpmBuildsFindings = (
  yaml: Record<string, unknown>,
  yamlPath: string,
  policy: Policy,
  usesAllowBuilds: boolean,
  buildsBlockedByDefault: boolean,
  file: string
): Finding[] => {
  const hasAllowBuilds = isPlainObject(yaml["allowBuilds"]);
  const legacy = PNPM_LEGACY_BUILD_KEYS.filter(
    (key) => yaml[key] !== undefined
  );
  const buildFix = configFix(file, "yaml", pnpmBuildEdits(yaml));
  if (yaml["dangerouslyAllowAllBuilds"] === true) {
    return [
      setting(
        "scripts.unrestricted",
        "pnpm dangerouslyAllowAllBuilds must not be true",
        "high",
        yamlPath,
        "pnpm",
        buildFix
      ),
    ];
  }
  if (usesAllowBuilds && legacy.length > 0 && !hasAllowBuilds) {
    return [
      setting(
        "scripts.legacy-config",
        `pnpm 11 removed ${legacy.join(", ")}; use allowBuilds instead`,
        "high",
        yamlPath,
        "pnpm",
        buildFix
      ),
    ];
  }
  if (!hasAllowBuilds && legacy.length === 0) {
    return [
      pnpmDefaultBuildsFinding(
        policy.preset,
        yamlPath,
        buildsBlockedByDefault,
        file,
        yaml
      ),
    ];
  }
  return [];
};

const pnpmScriptsFindings = (
  settings: ResolvedSettings,
  yaml: Record<string, unknown>,
  yamlPath: string,
  policy: Policy,
  usesAllowBuilds: boolean,
  buildsBlockedByDefault: boolean,
  file: string
): Finding[] => {
  if (!settings.ignoreScripts) {
    return [];
  }
  const findings = pnpmBuildsFindings(
    yaml,
    yamlPath,
    policy,
    usesAllowBuilds,
    buildsBlockedByDefault,
    file
  );
  if (yaml["strictDepBuilds"] === false) {
    findings.push(
      setting(
        "scripts.non-strict",
        "pnpm strictDepBuilds must not be false",
        "high",
        yamlPath,
        "pnpm",
        configFix(file, "yaml", [setOp("strictDepBuilds", true)])
      )
    );
  }
  return findings;
};

const pnpmExoticFinding = (
  yaml: Record<string, unknown>,
  yamlPath: string,
  file: string
): Finding[] => {
  if (yaml["blockExoticSubdeps"] === false) {
    return [
      setting(
        "source.non-registry",
        "pnpm blockExoticSubdeps must not be false",
        "high",
        yamlPath,
        "pnpm",
        configFix(file, "yaml", [setOp("blockExoticSubdeps", true)])
      ),
    ];
  }
  return [];
};

const pnpmAuditFinding = (
  yaml: Record<string, unknown>,
  settings: ResolvedSettings,
  yamlPath: string,
  file: string
): Finding[] => {
  if (
    auditMeetsGate(
      isTruthy(yaml["audit"]),
      yaml["auditLevel"] ?? yaml["audit-level"],
      settings.auditLevel
    )
  ) {
    return [];
  }
  return [
    setting(
      "audit.disabled",
      "pnpm audit must be enabled at the preset gate",
      "high",
      yamlPath,
      "pnpm",
      configFix(file, "yaml", [
        setOp("audit", true),
        setOp("auditLevel", settings.auditLevel),
      ])
    ),
  ];
};

const pnpmMinAgeGateFinding = (
  settings: ResolvedSettings,
  yaml: Record<string, unknown>,
  yamlPath: string,
  usesAllowBuilds: boolean,
  file: string
): Finding[] => {
  const raw = yaml["minimumReleaseAge"];
  // pnpm 11 ships minimumReleaseAge=1440 (24h) on by default.
  const defaultHours = usesAllowBuilds ? 24 : 0;
  const hours = raw === undefined ? defaultHours : parsePnpmAgeHours(raw);
  const requiredHours = settings.minReleaseAgeDays * 24;
  if (hours !== null && hours >= requiredHours) {
    return [];
  }
  return [
    setting(
      "min-age.disabled",
      `minimumReleaseAge must be at least ${requiredHours * 60} minutes`,
      "high",
      yamlPath,
      "pnpm",
      configFix(file, "yaml", [
        setOp(
          "minimumReleaseAge",
          settings.minReleaseAgeDays * MINUTES_PER_DAY
        ),
      ])
    ),
  ];
};

// minimumReleaseAgeStrict defaults to true only when the gate is set
// explicitly; false lets pnpm fall back to a version that fails the gate.
const pnpmMinAgeStrictFinding = (
  yaml: Record<string, unknown>,
  yamlPath: string,
  file: string
): Finding[] => {
  if (yaml["minimumReleaseAgeStrict"] === false) {
    return [
      setting(
        "min-age.non-strict",
        "pnpm minimumReleaseAgeStrict must not be false",
        "high",
        yamlPath,
        "pnpm",
        configFix(file, "yaml", [setOp("minimumReleaseAgeStrict", true)])
      ),
    ];
  }
  return [];
};

const pnpmMissingTimeFinding = (
  policy: Policy,
  yaml: Record<string, unknown>,
  yamlPath: string,
  file: string
): Finding[] => {
  if (
    policy.preset === "strict" &&
    yaml["minimumReleaseAgeIgnoreMissingTime"] !== false
  ) {
    return [
      setting(
        "min-age.missing-time",
        "minimumReleaseAgeIgnoreMissingTime must be false to fail closed",
        "moderate",
        yamlPath,
        "pnpm",
        configFix(file, "yaml", [
          setOp("minimumReleaseAgeIgnoreMissingTime", false),
        ])
      ),
    ];
  }
  return [];
};

const pnpmTrustPolicyFinding = (
  yaml: Record<string, unknown>,
  yamlPath: string,
  version: ManagerVersion | null,
  file: string
): Finding[] => {
  if (!atLeastOrUnknown(version, 10, 21)) {
    return [];
  }
  const policy = yaml["trustPolicy"] ?? yaml["trust-policy"];
  if (policy === "no-downgrade") {
    return [];
  }
  return [
    setting(
      "provenance.no-downgrade",
      "pnpm trustPolicy must be no-downgrade",
      "high",
      yamlPath,
      "pnpm",
      configFix(file, "yaml", [setOp("trustPolicy", "no-downgrade")])
    ),
  ];
};

const pnpmTrustLockfileFinding = (
  yaml: Record<string, unknown>,
  yamlPath: string,
  file: string
): Finding[] => {
  const trustLockfile = yaml["trustLockfile"] ?? yaml["trust-lockfile"];
  if (isTruthy(trustLockfile)) {
    return [
      setting(
        "lockfile.trust-bypass",
        "pnpm trustLockfile must not be true",
        "high",
        yamlPath,
        "pnpm",
        configFix(file, "yaml", [setOp("trustLockfile", false)])
      ),
    ];
  }
  return [];
};

const pnpmVerifyDepsFinding = (
  yaml: Record<string, unknown>,
  yamlPath: string,
  version: ManagerVersion | null,
  file: string
): Finding[] => {
  if (!atLeastOrUnknown(version, 10, 12)) {
    return [];
  }
  const verify = yaml["verifyDepsBeforeRun"] ?? yaml["verify-deps-before-run"];
  if (typeof verify === "string" && verify.toLowerCase() === "error") {
    return [];
  }
  return [
    setting(
      "lockfile.run-verify",
      "pnpm verifyDepsBeforeRun must be error",
      "high",
      yamlPath,
      "pnpm",
      configFix(file, "yaml", [setOp("verifyDepsBeforeRun", "error")])
    ),
  ];
};

const pnpmMinAgeFindings = (
  settings: ResolvedSettings,
  yaml: Record<string, unknown>,
  yamlPath: string,
  policy: Policy,
  usesAllowBuilds: boolean,
  file: string
): Finding[] => {
  if (settings.minReleaseAgeDays <= 0) {
    return [];
  }
  return [
    ...pnpmMinAgeGateFinding(settings, yaml, yamlPath, usesAllowBuilds, file),
    ...pnpmMinAgeStrictFinding(yaml, yamlPath, file),
    ...blanketExcludeFinding(
      yaml["minimumReleaseAgeExclude"],
      "minimumReleaseAgeExclude must not exempt every package",
      yamlPath,
      "pnpm",
      configFix(file, "yaml", [
        setOp(
          "minimumReleaseAgeExclude",
          dropBlanketEntries(yaml["minimumReleaseAgeExclude"])
        ),
      ])
    ),
    ...pnpmMissingTimeFinding(policy, yaml, yamlPath, file),
  ];
};

const auditPnpm: ManagerAuditor = (project, manager, policy, readFile) => {
  const settings = resolveSettings(policy, "pnpm");
  const yamlPath = manager.configPath ?? `${project.root}/pnpm-workspace.yaml`;
  const file = profileWritePath(project, "pnpm") ?? yamlPath;
  const yaml = parseYaml(readFile(yamlPath) ?? "");
  const version = managerVersion(readFile(manager.manifestPath), "pnpm");
  // pnpm >= 10 blocks dependency builds by default; pnpm >= 11 replaced the
  // onlyBuiltDependencies family with a single allowBuilds map.
  const buildsBlockedByDefault = atLeastOrUnknown(version, 10);
  const usesAllowBuilds = atLeastOrUnknown(version, 11);
  const lockfileOff = yaml["lockfile"] === false;
  return [
    ...pnpmScriptsFindings(
      settings,
      yaml,
      yamlPath,
      policy,
      usesAllowBuilds,
      buildsBlockedByDefault,
      file
    ),
    ...pnpmExoticFinding(yaml, yamlPath, file),
    ...lockfileMissingFinding(
      settings.requireLockfile,
      !lockfileOff &&
        lockfilePresent(
          manager,
          readFile,
          `${project.root}/${profileFor("pnpm").lockfileNames[0] ?? "pnpm-lock.yaml"}`
        ),
      manager.lockfilePath ??
        `${project.root}/${profileFor("pnpm").lockfileNames[0] ?? "pnpm-lock.yaml"}`,
      "pnpm-lock.yaml is required",
      "pnpm"
    ),
    ...pnpmAuditFinding(yaml, settings, yamlPath, file),
    ...pnpmMinAgeFindings(
      settings,
      yaml,
      yamlPath,
      policy,
      usesAllowBuilds,
      file
    ),
    ...pnpmTrustPolicyFinding(yaml, yamlPath, version, file),
    ...pnpmTrustLockfileFinding(yaml, yamlPath, file),
    ...pnpmVerifyDepsFinding(yaml, yamlPath, version, file),
    ...registryUnpinnedFinding(
      pnpmRegistryPinned(yaml),
      "registry or registries.default must be set",
      policy.preset,
      yamlPath,
      "pnpm",
      configFix(file, "yaml", [setOp("registry", DEFAULT_REGISTRY)])
    ),
    ...pmPinFinding(
      settings.requirePmPin,
      packageManagerStartsWith(readFile(manager.manifestPath), "pnpm@"),
      "package.json packageManager must start with pnpm@",
      policy.preset,
      manager.manifestPath,
      "pnpm"
    ),
  ];
};

const yarnScriptsFinding = (
  settings: ResolvedSettings,
  yarnrc: Record<string, unknown>,
  yarnrcPath: string,
  policy: Policy,
  scriptsOffByDefault: boolean,
  file: string
): Finding[] => {
  if (!settings.ignoreScripts || yarnrc["enableScripts"] === false) {
    return [];
  }
  const fix = configFix(file, "yaml", [setOp("enableScripts", false)]);
  if (yarnrc["enableScripts"] === true || !scriptsOffByDefault) {
    return [
      setting(
        "scripts.unrestricted",
        "yarn enableScripts must be false",
        "high",
        yarnrcPath,
        "yarn",
        fix
      ),
    ];
  }
  return [
    advice(
      "scripts.unrestricted",
      "yarn defaults enableScripts to false; set it explicitly to keep that guarantee",
      yarnrcPath,
      "yarn",
      defaultRelianceSeverity(policy.preset),
      true,
      fix
    ),
  ];
};

const yarnMinAgeGateFinding = (
  settings: ResolvedSettings,
  yarnrc: Record<string, unknown>,
  yarnrcPath: string,
  ageGateByDefault: boolean,
  file: string
): Finding[] => {
  const raw = yarnrc["npmMinimalAgeGate"];
  const defaultHours = ageGateByDefault ? 24 * 7 : 0;
  const hours = raw === undefined ? defaultHours : parsePnpmAgeHours(raw);
  const requiredHours = settings.minReleaseAgeDays * 24;
  if (hours !== null && hours >= requiredHours) {
    return [];
  }
  return [
    setting(
      "min-age.disabled",
      `npmMinimalAgeGate must be at least ${requiredHours * 60} minutes`,
      "high",
      yarnrcPath,
      "yarn",
      configFix(file, "yaml", [
        setOp(
          "npmMinimalAgeGate",
          settings.minReleaseAgeDays * MINUTES_PER_DAY
        ),
      ])
    ),
  ];
};

const yarnMinAgeFindings = (
  settings: ResolvedSettings,
  yarnrc: Record<string, unknown>,
  yarnrcPath: string,
  ageGateByDefault: boolean,
  file: string
): Finding[] => {
  if (settings.minReleaseAgeDays <= 0) {
    return [];
  }
  return [
    ...yarnMinAgeGateFinding(
      settings,
      yarnrc,
      yarnrcPath,
      ageGateByDefault,
      file
    ),
    ...blanketExcludeFinding(
      yarnrc["npmPreapprovedPackages"],
      "npmPreapprovedPackages must not exempt every package",
      yarnrcPath,
      "yarn",
      configFix(file, "yaml", [
        setOp(
          "npmPreapprovedPackages",
          dropBlanketEntries(yarnrc["npmPreapprovedPackages"])
        ),
      ])
    ),
  ];
};

const yarnIntegrityFindings = (
  yarnrc: Record<string, unknown>,
  yarnrcPath: string,
  file: string
): Finding[] => {
  const findings: Finding[] = [];
  if (
    yarnrc["checksumBehavior"] !== undefined &&
    yarnrc["checksumBehavior"] !== "throw"
  ) {
    findings.push(
      setting(
        "integrity.checksum-relaxed",
        'yarn checksumBehavior must be "throw"',
        "high",
        yarnrcPath,
        "yarn",
        configFix(file, "yaml", [setOp("checksumBehavior", "throw")])
      )
    );
  }
  if (yarnrc["enableStrictSsl"] === false) {
    findings.push(
      setting(
        "integrity.strict-ssl",
        "yarn enableStrictSsl must not be false",
        "high",
        yarnrcPath,
        "yarn",
        configFix(file, "yaml", [setOp("enableStrictSsl", true)])
      )
    );
  }
  if (yarnrc["enableHardenedMode"] === false) {
    findings.push(
      setting(
        "integrity.hardened-mode",
        "yarn enableHardenedMode must not be false",
        "moderate",
        yarnrcPath,
        "yarn",
        configFix(file, "yaml", [setOp("enableHardenedMode", true)])
      )
    );
  }
  return findings;
};

const yarnAuditEdits = (yarnrc: Record<string, unknown>): ConfigEdit[] => {
  const edits: ConfigEdit[] = [];
  if (yarnrc.audit !== undefined) {
    edits.push(unsetOp("audit"));
  }
  if (yarnrc.npmAudit !== undefined) {
    edits.push(unsetOp("npmAudit"));
  }
  edits.push(setOp("enableNpmAudit", true));
  return edits;
};

const yarnAuditFinding = (
  yarnrc: Record<string, unknown>,
  yarnrcPath: string,
  file: string
): Finding[] => {
  if (yarnAuditDisabled(yarnrc)) {
    return [
      setting(
        "audit.disabled",
        "yarn audit must not be disabled",
        "high",
        yarnrcPath,
        "yarn",
        configFix(file, "yaml", yarnAuditEdits(yarnrc))
      ),
    ];
  }
  return [];
};

const yarnGitSourceFinding = (
  settings: ResolvedSettings,
  yarnrc: Record<string, unknown>,
  yarnrcPath: string,
  gitBlockingSupported: boolean,
  file: string
): Finding[] => {
  if (!settings.ignoreScripts) {
    return [];
  }
  if (gitBlockingSupported && yarnGitReposBlocked(yarnrc)) {
    return [];
  }
  const message =
    yarnrc["approvedGitRepositories"] === undefined
      ? "yarn approvedGitRepositories must block git-sourced dependencies"
      : "yarn approvedGitRepositories must not allow every git repository";
  return [
    setting(
      "source.git-unrestricted",
      message,
      "high",
      yarnrcPath,
      "yarn",
      configFix(file, "yaml", [setOp("approvedGitRepositories", [])])
    ),
  ];
};

const auditYarn: ManagerAuditor = (project, manager, policy, readFile) => {
  const settings = resolveSettings(policy, "yarn");
  const yarnrcPath = manager.configPath ?? `${project.root}/.yarnrc.yml`;
  const file = profileWritePath(project, "yarn") ?? yarnrcPath;
  const yarnrc = parseYaml(readFile(yarnrcPath) ?? "");
  const version = managerVersion(readFile(manager.manifestPath), "yarn");
  // Yarn stopped running dependency postinstalls by default in 4.14, and
  // added npmMinimalAgeGate (default 1w) in 4.12. approvedGitRepositories
  // arrived in 4.14 to block git deps that bypass enableScripts.
  const scriptsOffByDefault = atLeastOrUnknown(version, 4, 14);
  const ageGateByDefault = atLeastOrUnknown(version, 4, 12);
  const gitBlockingSupported = atLeastOrUnknown(version, 4, 14);
  return [
    ...yarnScriptsFinding(
      settings,
      yarnrc,
      yarnrcPath,
      policy,
      scriptsOffByDefault,
      file
    ),
    ...yarnMinAgeFindings(settings, yarnrc, yarnrcPath, ageGateByDefault, file),
    ...yarnIntegrityFindings(yarnrc, yarnrcPath, file),
    ...yarnGitSourceFinding(
      settings,
      yarnrc,
      yarnrcPath,
      gitBlockingSupported,
      file
    ),
    ...lockfileMissingFinding(
      settings.requireLockfile,
      lockfilePresent(manager, readFile, `${project.root}/yarn.lock`),
      manager.lockfilePath ?? `${project.root}/yarn.lock`,
      "yarn.lock is required",
      "yarn"
    ),
    ...yarnAuditFinding(yarnrc, yarnrcPath, file),
    ...registryUnpinnedFinding(
      hasText(yarnrc["npmRegistryServer"]),
      "npmRegistryServer must be set",
      policy.preset,
      yarnrcPath,
      "yarn",
      configFix(file, "yaml", [setOp("npmRegistryServer", DEFAULT_REGISTRY)])
    ),
    ...pmPinFinding(
      settings.requirePmPin,
      packageManagerYarnBerry(readFile(manager.manifestPath)),
      "package.json packageManager must be yarn@ major >= 2",
      policy.preset,
      manager.manifestPath,
      "yarn"
    ),
  ];
};

const bunScriptsFinding = (
  settings: ResolvedSettings,
  bunfig: Record<string, unknown>,
  install: Record<string, unknown>,
  bunfigPath: string,
  file: string
): Finding[] => {
  if (settings.ignoreScripts && bunScriptsUnrestricted(bunfig, install)) {
    return [
      setting(
        "scripts.unrestricted",
        "bun scripts must be restricted",
        "high",
        bunfigPath,
        "bun",
        configFix(file, "toml", [setOp("install.ignoreScripts", true)])
      ),
    ];
  }
  return [];
};

const bunMinAgeGateFinding = (
  settings: ResolvedSettings,
  install: Record<string, unknown>,
  bunfigPath: string,
  file: string
): Finding[] => {
  // bun expresses minimumReleaseAge in SECONDS and ships it off by default.
  const seconds = parseNumber(install["minimumReleaseAge"]);
  const requiredSeconds = settings.minReleaseAgeDays * SECONDS_PER_DAY;
  if (seconds !== null && seconds >= requiredSeconds) {
    return [];
  }
  return [
    setting(
      "min-age.disabled",
      `install.minimumReleaseAge must be at least ${requiredSeconds} seconds`,
      "high",
      bunfigPath,
      "bun",
      configFix(file, "toml", [
        setOp("install.minimumReleaseAge", requiredSeconds),
      ])
    ),
  ];
};

const bunMinAgeFindings = (
  settings: ResolvedSettings,
  install: Record<string, unknown>,
  bunfigPath: string,
  file: string
): Finding[] => {
  if (settings.minReleaseAgeDays <= 0) {
    return [];
  }
  return [
    ...bunMinAgeGateFinding(settings, install, bunfigPath, file),
    ...blanketExcludeFinding(
      install["minimumReleaseAgeExcludes"],
      "minimumReleaseAgeExcludes must not exempt every package",
      bunfigPath,
      "bun",
      configFix(file, "toml", [
        setOp(
          "install.minimumReleaseAgeExcludes",
          dropBlanketEntries(install["minimumReleaseAgeExcludes"])
        ),
      ])
    ),
  ];
};

const auditBun: ManagerAuditor = (project, manager, policy, readFile) => {
  const settings = resolveSettings(policy, "bun");
  const bunfigPath = manager.configPath ?? `${project.root}/bunfig.toml`;
  const file = profileWritePath(project, "bun") ?? bunfigPath;
  const bunfig = parseToml(readFile(bunfigPath) ?? "");
  const install = isPlainObject(bunfig["install"]) ? bunfig["install"] : {};
  return [
    ...bunScriptsFinding(settings, bunfig, install, bunfigPath, file),
    ...lockfileMissingFinding(
      settings.requireLockfile,
      bunLockfilePresent(project, manager, readFile),
      manager.lockfilePath ?? `${project.root}/bun.lock`,
      "bun.lock or bun.lockb is required",
      "bun"
    ),
    ...bunMinAgeFindings(settings, install, bunfigPath, file),
    ...registryUnpinnedFinding(
      bunRegistryPinned(install),
      "install.registry must be set",
      policy.preset,
      bunfigPath,
      "bun",
      configFix(file, "toml", [setOp("install.registry", DEFAULT_REGISTRY)])
    ),
  ];
};

const uvExcludeNewerFinding = (
  settings: ResolvedSettings,
  cfg: Record<string, unknown>,
  configPath: string,
  file: string,
  prefix: string
): Finding[] => {
  if (uvExcludeNewerMeets(cfg["exclude-newer"], settings.minReleaseAgeDays)) {
    return [];
  }
  return [
    setting(
      "min-age.disabled",
      `exclude-newer must meet ${settings.minReleaseAgeDays} days`,
      "high",
      configPath,
      "uv",
      configFix(file, "toml", [
        setOp(
          `${prefix}exclude-newer`,
          uvExcludeNewerValue(settings.minReleaseAgeDays)
        ),
      ])
    ),
  ];
};

const uvMinAgeFindings = (
  settings: ResolvedSettings,
  cfg: Record<string, unknown>,
  configPath: string,
  file: string,
  prefix: string
): Finding[] => {
  if (settings.minReleaseAgeDays <= 0) {
    return [];
  }
  const excludePkg = isPlainObject(cfg["exclude-newer-package"])
    ? dropBlanketObject(cfg["exclude-newer-package"])
    : {};
  return [
    ...uvExcludeNewerFinding(settings, cfg, configPath, file, prefix),
    ...blanketExcludeFinding(
      cfg["exclude-newer-package"],
      "exclude-newer-package must not exempt every package",
      configPath,
      "uv",
      configFix(file, "toml", [
        setOp(`${prefix}exclude-newer-package`, excludePkg),
      ])
    ),
  ];
};

const uvIndexStrategyFinding = (
  policy: Policy,
  cfg: Record<string, unknown>,
  configPath: string,
  file: string,
  prefix: string
): Finding[] => {
  if (
    policy.preset === "strict" &&
    uvHasExtraIndexes(cfg) &&
    cfg["index-strategy"] !== "first-index"
  ) {
    return [
      setting(
        "registry.unpinned",
        'extra indexes require index-strategy = "first-index"',
        pinSeverity(policy.preset),
        configPath,
        "uv",
        configFix(file, "toml", [
          setOp(`${prefix}index-strategy`, "first-index"),
        ])
      ),
    ];
  }
  return [];
};

const uvMalwareFinding = (
  cfg: Record<string, unknown>,
  configPath: string,
  manifestRaw: string | null,
  file: string,
  prefix: string
): Finding[] => {
  const version = managerVersion(manifestRaw, "uv");
  if (!atLeastPatchOrUnknown(version, 0, 11, 31)) {
    return [];
  }
  if (readUvAudit(cfg)["malware-check"] === true) {
    return [];
  }
  return [
    setting(
      "audit.malware-disabled",
      "uv audit malware-check must be true",
      "high",
      configPath,
      "uv",
      configFix(file, "toml", [setOp(`${prefix}audit.malware-check`, true)])
    ),
  ];
};

const auditUv: ManagerAuditor = (project, manager, policy, readFile) => {
  const settings = resolveSettings(policy, "uv");
  const cfg = readUvConfig(project, readFile);
  const configPath = manager.configPath ?? `${project.root}/pyproject.toml`;
  const file = uvConfigPath(project, manager, readFile);
  const prefix = uvKeyPrefix(readFile(file) ?? "");
  const manifestRaw = readFile(manager.manifestPath);
  return [
    ...lockfileMissingFinding(
      settings.requireLockfile,
      lockfilePresent(manager, readFile, `${project.root}/uv.lock`),
      manager.lockfilePath ?? `${project.root}/uv.lock`,
      "uv.lock is required",
      "uv"
    ),
    ...uvMinAgeFindings(settings, cfg, configPath, file, prefix),
    ...uvIndexStrategyFinding(policy, cfg, configPath, file, prefix),
    ...uvMalwareFinding(cfg, configPath, manifestRaw, file, prefix),
  ];
};

const readCargoConfig = (
  project: Project,
  readFile: ReadFile
): Record<string, unknown> => {
  const raw =
    profileFor("cargo")
      .configNames.map((name) => readFile(`${project.root}/${name}`))
      .find((contents) => contents !== null) ?? "";
  return parseToml(raw);
};

const cargoMinAgeMeets = (value: unknown, minDays: number): boolean => {
  if (value === undefined) {
    return false;
  }
  const hours = parsePnpmAgeHours(value);
  if (hours === null) {
    return false;
  }
  return hours / 24 >= minDays;
};

const cargoMinAgeFinding = (
  settings: ResolvedSettings,
  install: Record<string, unknown>,
  configPath: string,
  file: string
): Finding[] => {
  if (
    cargoMinAgeMeets(install["minimum-release-age"], settings.minReleaseAgeDays)
  ) {
    return [];
  }
  return [
    setting(
      "min-age.disabled",
      `install.minimum-release-age must meet ${settings.minReleaseAgeDays} days`,
      "high",
      configPath,
      "cargo",
      configFix(file, "toml", [
        setOp(
          "install.minimum-release-age",
          cargoDuration(settings.minReleaseAgeDays)
        ),
      ])
    ),
  ];
};

const cargoMinAgeFindings = (
  settings: ResolvedSettings,
  install: Record<string, unknown>,
  configPath: string,
  file: string
): Finding[] => {
  if (settings.minReleaseAgeDays <= 0) {
    return [];
  }
  return cargoMinAgeFinding(settings, install, configPath, file);
};

const auditCargo: ManagerAuditor = (project, manager, policy, readFile) => {
  const settings = resolveSettings(policy, "cargo");
  const cfg = readCargoConfig(project, readFile);
  const install = isPlainObject(cfg["install"]) ? cfg["install"] : {};
  const configPath = manager.configPath ?? `${project.root}/.cargo/config.toml`;
  const file =
    manager.configPath ?? profileWritePath(project, "cargo") ?? configPath;
  return [
    ...lockfileMissingFinding(
      settings.requireLockfile,
      lockfilePresent(manager, readFile, `${project.root}/Cargo.lock`),
      manager.lockfilePath ?? `${project.root}/Cargo.lock`,
      "Cargo.lock is required",
      "cargo"
    ),
    ...cargoMinAgeFindings(settings, install, configPath, file),
  ];
};

const bundlerMinAgeFinding = (
  settings: ResolvedSettings,
  config: Record<string, string>,
  configPath: string,
  file: string
): Finding[] => {
  if (settings.minReleaseAgeDays <= 0) {
    return [];
  }
  const days = parseNumber(config["BUNDLE_COOLDOWN"]);
  if (days !== null && days >= settings.minReleaseAgeDays) {
    return [];
  }
  return [
    setting(
      "min-age.disabled",
      `BUNDLE_COOLDOWN must be at least ${settings.minReleaseAgeDays} days`,
      "high",
      configPath,
      "bundler",
      configFix(file, "bundle-config", [
        setOp("BUNDLE_COOLDOWN", String(settings.minReleaseAgeDays)),
      ])
    ),
  ];
};

const composerScriptsFinding = (
  settings: ResolvedSettings,
  allowPlugins: unknown,
  configPath: string,
  file: string
): Finding[] => {
  if (!settings.ignoreScripts || allowPlugins !== true) {
    return [];
  }
  return [
    setting(
      "scripts.unrestricted",
      "composer allow-plugins must not be true",
      "high",
      configPath,
      "composer",
      configFix(file, "json", [setOp("config.allow-plugins", false)])
    ),
  ];
};

const composerTlsFinding = (
  disableTls: boolean,
  secureHttp: boolean,
  configPath: string,
  file: string
): Finding[] => {
  if (!disableTls && secureHttp) {
    return [];
  }
  const edits: ConfigEdit[] = [];
  if (disableTls) {
    edits.push(unsetOp("config.disable-tls"));
  }
  edits.push(setOp("config.secure-http", true));
  return [
    setting(
      "registry.unpinned",
      "composer must keep secure-http enabled and disable-tls off",
      "high",
      configPath,
      "composer",
      configFix(file, "json", edits)
    ),
  ];
};

const composerHttpRepoFinding = (
  urls: string[],
  preset: PresetName,
  configPath: string
): Finding[] => {
  if (urls.length === 0) {
    return [];
  }
  return [
    advice(
      "registry.unpinned",
      `composer repositories must use https (${urls[0]})`,
      configPath,
      "composer",
      pinSeverity(preset)
    ),
  ];
};

const composerPolicyFindings = (
  security: ReturnType<typeof readComposerSecurity>,
  configPath: string,
  file: string
): Finding[] => {
  const findings: Finding[] = [];
  if (security.policyDisabled || security.advisoriesAudit === "ignore") {
    findings.push(
      setting(
        "audit.disabled",
        "composer policy.advisories.audit must not be ignore",
        "high",
        configPath,
        "composer",
        configFix(file, "json", [
          setOp("config.policy.advisories.audit", "fail"),
          setOp("config.policy.advisories.block", true),
          setOp("config.policy.malware.block", true),
        ])
      )
    );
  }
  if (!security.advisoriesBlock) {
    findings.push(
      setting(
        "audit.blocking-disabled",
        "composer policy.advisories.block must be true",
        "high",
        configPath,
        "composer",
        configFix(file, "json", [setOp("config.policy.advisories.block", true)])
      )
    );
  }
  if (!security.malwareBlock) {
    findings.push(
      setting(
        "audit.malware-disabled",
        "composer policy.malware.block must be true",
        "high",
        configPath,
        "composer",
        configFix(file, "json", [setOp("config.policy.malware.block", true)])
      )
    );
  }
  return findings;
};

const composerSourceFallbackFinding = (
  sourceFallback: boolean,
  preset: PresetName,
  configPath: string,
  file: string
): Finding[] => {
  if (!sourceFallback) {
    return [];
  }
  return [
    setting(
      "source-fallback.enabled",
      "composer source-fallback must not be true",
      pinSeverity(preset),
      configPath,
      "composer",
      configFix(file, "json", [setOp("config.source-fallback", false)])
    ),
  ];
};

const auditComposer: ManagerAuditor = (project, manager, policy, readFile) => {
  const settings = resolveSettings(policy, "composer");
  const configPath = manager.configPath ?? `${project.root}/composer.json`;
  const file = profileWritePath(project, "composer") ?? configPath;
  const manifest = parseComposerManifest(readFile(configPath) ?? "") ?? {};
  const security = readComposerSecurity(manifest);
  return [
    ...lockfileMissingFinding(
      settings.requireLockfile,
      lockfilePresent(manager, readFile, `${project.root}/composer.lock`),
      manager.lockfilePath ?? `${project.root}/composer.lock`,
      "composer.lock is required",
      "composer"
    ),
    ...composerScriptsFinding(
      settings,
      security.allowPlugins,
      configPath,
      file
    ),
    ...composerTlsFinding(
      security.disableTls,
      security.secureHttp,
      configPath,
      file
    ),
    ...composerHttpRepoFinding(
      security.httpRepoUrls,
      policy.preset,
      configPath
    ),
    ...composerPolicyFindings(security, configPath, file),
    ...composerSourceFallbackFinding(
      security.sourceFallback,
      policy.preset,
      configPath,
      file
    ),
  ];
};

const auditBundler: ManagerAuditor = (project, manager, policy, readFile) => {
  const settings = resolveSettings(policy, "bundler");
  const configPath = manager.configPath ?? `${project.root}/.bundle/config`;
  const file = profileWritePath(project, "bundler") ?? configPath;
  const config = parseBundleConfig(readFile(configPath) ?? "");
  return [
    ...lockfileMissingFinding(
      settings.requireLockfile,
      lockfilePresent(manager, readFile, `${project.root}/Gemfile.lock`),
      manager.lockfilePath ?? `${project.root}/Gemfile.lock`,
      "Gemfile.lock is required",
      "bundler"
    ),
    ...bundlerMinAgeFinding(settings, config, configPath, file),
  ];
};

const AUDITORS: Partial<Record<PackageManager, ManagerAuditor>> = {
  bun: auditBun,
  bundler: auditBundler,
  cargo: auditCargo,
  composer: auditComposer,
  npm: auditNpm,
  pnpm: auditPnpm,
  uv: auditUv,
  yarn: auditYarn,
};

const roleFinding = (manager: DetectedManager): Finding | null => {
  if (manager.role === "leftover") {
    return leftoverFinding(manager);
  }
  if (manager.role === "unsupported") {
    return unsupportedFinding(manager);
  }
  return null;
};

const primaryFindings = (
  project: Project,
  manager: DetectedManager,
  policy: Policy,
  readFile: ReadFile
): Finding[] => {
  if (profileFor(manager.name).kind === "python-legacy") {
    return [notUsingUvFinding(manager)];
  }
  if (!policy.enabledManagers.includes(manager.name)) {
    return [];
  }
  const auditor = AUDITORS[manager.name];
  return auditor === undefined
    ? []
    : auditor(project, manager, policy, readFile);
};

const managerFindings = (
  project: Project,
  manager: DetectedManager,
  policy: Policy,
  readFile: ReadFile
): Finding[] => {
  const role = roleFinding(manager);
  if (role !== null) {
    return [role];
  }
  if (manager.role !== "primary") {
    return [];
  }
  return primaryFindings(project, manager, policy, readFile);
};

export const auditSettings = (
  project: Project,
  policy: Policy,
  opts: SettingsFs
): Finding[] => {
  const { readFile } = opts;
  return project.managers.flatMap((manager) =>
    managerFindings(project, manager, policy, readFile)
  );
};

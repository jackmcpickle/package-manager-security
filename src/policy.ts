import { parse } from "smol-toml";
import type { PackageManager, Policy, PresetName } from "./domain";

export const PRESET_DEFAULTS = {
  standard: {
    ignoreScripts: true,
    minReleaseAgeDays: 7,
    auditLevel: "high",
    requireLockfile: true,
    requirePmPin: true,
  },
  strict: {
    ignoreScripts: true,
    minReleaseAgeDays: 14,
    auditLevel: "moderate",
    requireLockfile: true,
    requirePmPin: true,
  },
  relaxed: {
    ignoreScripts: false,
    minReleaseAgeDays: 0,
    auditLevel: "critical",
    requireLockfile: true,
    requirePmPin: false,
  },
} as const;

const DEFAULT_ENABLED_MANAGERS: PackageManager[] = [
  "npm",
  "pnpm",
  "yarn",
  "bun",
  "uv",
];

const CONFIG_MANAGERS = new Set<string>([
  "npm",
  "pnpm",
  "yarn",
  "bun",
  "uv",
]);

const PACKAGE_MANAGERS = new Set<string>([
  ...CONFIG_MANAGERS,
  "poetry",
  "pip",
  "pipenv",
]);

const RESERVED_KEYS = new Set(["preset", "enabledManagers"]);

export function loadPolicy(input: {
  userToml?: string;
  scanToml?: string;
  repoToml?: string;
  flags?: { preset?: PresetName; overrides?: Record<string, unknown> };
}): Policy {
  let preset: PresetName = "standard";
  let enabledManagers = [...DEFAULT_ENABLED_MANAGERS];
  let overrides: Record<string, unknown> = {};
  const tables: Partial<Record<PackageManager, Record<string, unknown>>> = {};

  for (const toml of [input.userToml, input.scanToml, input.repoToml]) {
    if (toml === undefined) continue;
    const layer = parseLayer(toml);
    if (layer.preset !== undefined) preset = layer.preset;
    if (layer.enabledManagers !== undefined) {
      enabledManagers = layer.enabledManagers;
    }
    overrides = { ...overrides, ...layer.overrides };
    for (const [name, table] of Object.entries(layer.perManager) as [
      PackageManager,
      Record<string, unknown>,
    ][]) {
      tables[name] = { ...tables[name], ...table };
    }
  }

  const flagOverrides = input.flags?.overrides ?? {};
  if (input.flags?.preset !== undefined) {
    preset = input.flags.preset;
  }
  overrides = { ...overrides, ...flagOverrides };

  const perManager: Policy["perManager"] = {};
  for (const [name, table] of Object.entries(tables) as [
    PackageManager,
    Record<string, unknown>,
  ][]) {
    perManager[name] = { ...overrides, ...table, ...flagOverrides };
  }

  return { preset, enabledManagers, overrides, perManager };
}

function parseLayer(toml: string): {
  preset?: PresetName;
  enabledManagers?: PackageManager[];
  overrides: Record<string, unknown>;
  perManager: Partial<Record<PackageManager, Record<string, unknown>>>;
} {
  const overrides: Record<string, unknown> = {};
  const perManager: Partial<Record<PackageManager, Record<string, unknown>>> =
    {};
  let preset: PresetName | undefined;
  let enabledManagers: PackageManager[] | undefined;

  let parsed: Record<string, unknown>;
  try {
    const raw: unknown = parse(toml);
    if (!isPlainObject(raw)) {
      return { overrides: {}, perManager: {} };
    }
    parsed = raw;
  } catch {
    return { overrides: {}, perManager: {} };
  }

  for (const [key, value] of Object.entries(parsed)) {
    if (key === "preset" && isPresetName(value)) {
      preset = value;
      continue;
    }
    if (key === "enabledManagers" && Array.isArray(value)) {
      enabledManagers = value.filter(isPackageManager);
      continue;
    }
    if (isConfigManager(key) && isPlainObject(value)) {
      perManager[key] = { ...value };
      continue;
    }
    if (!RESERVED_KEYS.has(key) && !isPackageManager(key)) {
      overrides[key] = value;
    }
  }

  return { preset, enabledManagers, overrides, perManager };
}

function isPresetName(value: unknown): value is PresetName {
  return value === "relaxed" || value === "standard" || value === "strict";
}

function isConfigManager(value: unknown): value is PackageManager {
  return typeof value === "string" && CONFIG_MANAGERS.has(value);
}

function isPackageManager(value: unknown): value is PackageManager {
  return typeof value === "string" && PACKAGE_MANAGERS.has(value);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

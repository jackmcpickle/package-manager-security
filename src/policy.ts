import { parse } from "smol-toml";

import type { PackageManager, Policy, PresetName } from "./domain";

export const PRESET_DEFAULTS = {
  relaxed: {
    auditLevel: "critical",
    ignoreScripts: false,
    minReleaseAgeDays: 0,
    requireLockfile: true,
    requirePmPin: false,
  },
  standard: {
    auditLevel: "high",
    ignoreScripts: true,
    minReleaseAgeDays: 1,
    requireLockfile: true,
    requirePmPin: true,
  },
  strict: {
    auditLevel: "moderate",
    ignoreScripts: true,
    minReleaseAgeDays: 14,
    requireLockfile: true,
    requirePmPin: true,
  },
} as const;

const DEFAULT_ENABLED_MANAGERS: PackageManager[] = [
  "npm",
  "pnpm",
  "yarn",
  "bun",
  "uv",
  "bundler",
  "cargo",
];

const CONFIG_MANAGERS = new Set<string>([
  "npm",
  "pnpm",
  "yarn",
  "bun",
  "uv",
  "bundler",
  "cargo",
]);

const PACKAGE_MANAGERS = new Set<string>([
  ...CONFIG_MANAGERS,
  "poetry",
  "pip",
  "pipenv",
]);

const RESERVED_KEYS = new Set(["preset", "enabledManagers"]);

const isPresetName = (value: unknown): value is PresetName =>
  value === "relaxed" || value === "standard" || value === "strict";

const isConfigManager = (value: unknown): value is PackageManager =>
  typeof value === "string" && CONFIG_MANAGERS.has(value);

const isPackageManager = (value: unknown): value is PackageManager =>
  typeof value === "string" && PACKAGE_MANAGERS.has(value);

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

interface LayerAcc {
  preset?: PresetName;
  enabledManagers?: PackageManager[];
  overrides: Record<string, unknown>;
  perManager: Partial<Record<PackageManager, Record<string, unknown>>>;
}

interface PolicyState {
  preset: PresetName;
  enabledManagers: PackageManager[];
  overrides: Record<string, unknown>;
  tables: Partial<Record<PackageManager, Record<string, unknown>>>;
}

const applySpecialLayerKey = (
  key: string,
  value: unknown,
  acc: LayerAcc
): boolean => {
  if (key === "preset") {
    if (isPresetName(value)) {
      acc.preset = value;
    }
    return true;
  }
  if (key === "enabledManagers") {
    if (Array.isArray(value)) {
      acc.enabledManagers = value.filter(isPackageManager);
    }
    return true;
  }
  return false;
};

const applyLayerKey = (key: string, value: unknown, acc: LayerAcc): void => {
  if (applySpecialLayerKey(key, value, acc)) {
    return;
  }
  if (isConfigManager(key) && isPlainObject(value)) {
    acc.perManager[key] = { ...value };
    return;
  }
  if (!RESERVED_KEYS.has(key) && !isPackageManager(key)) {
    acc.overrides[key] = value;
  }
};

const parseLayer = (toml: string): LayerAcc => {
  const acc: LayerAcc = { overrides: {}, perManager: {} };
  try {
    const raw: unknown = parse(toml);
    if (!isPlainObject(raw)) {
      return acc;
    }
    for (const [key, value] of Object.entries(raw)) {
      applyLayerKey(key, value, acc);
    }
  } catch {
    return { overrides: {}, perManager: {} };
  }
  return acc;
};

const applyParsedLayer = (state: PolicyState, layer: LayerAcc): void => {
  const { preset, enabledManagers, overrides, perManager } = layer;
  if (preset !== undefined) {
    state.preset = preset;
  }
  if (enabledManagers !== undefined) {
    state.enabledManagers = enabledManagers;
  }
  Object.assign(state.overrides, overrides);
  for (const [name, table] of Object.entries(perManager) as [
    PackageManager,
    Record<string, unknown>,
  ][]) {
    state.tables[name] = { ...state.tables[name], ...table };
  }
};

const applyTomlLayer = (state: PolicyState, toml: string | undefined): void => {
  if (toml === undefined) {
    return;
  }
  applyParsedLayer(state, parseLayer(toml));
};

const applyFlagLayer = (
  state: PolicyState,
  flags?: { preset?: PresetName; overrides?: Record<string, unknown> }
): Record<string, unknown> => {
  const { preset, overrides = {} } = flags ?? {};
  if (preset !== undefined) {
    state.preset = preset;
  }
  Object.assign(state.overrides, overrides);
  return overrides;
};

export const loadPolicy = (input: {
  userToml?: string;
  scanToml?: string;
  repoToml?: string;
  flags?: { preset?: PresetName; overrides?: Record<string, unknown> };
}): Policy => {
  const state: PolicyState = {
    enabledManagers: [...DEFAULT_ENABLED_MANAGERS],
    overrides: {},
    preset: "standard",
    tables: {},
  };
  applyTomlLayer(state, input.userToml);
  applyTomlLayer(state, input.scanToml);
  applyTomlLayer(state, input.repoToml);
  const flagOverrides = applyFlagLayer(state, input.flags);

  const perManager: Policy["perManager"] = {};
  for (const [name, table] of Object.entries(state.tables) as [
    PackageManager,
    Record<string, unknown>,
  ][]) {
    perManager[name] = { ...state.overrides, ...table, ...flagOverrides };
  }

  return {
    enabledManagers: state.enabledManagers,
    overrides: state.overrides,
    perManager,
    preset: state.preset,
  };
};

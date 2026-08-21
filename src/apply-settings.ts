import { parse as parseToml, stringify as stringifyToml } from "smol-toml";

import { APP_NAME } from "./app-name";
import { parseBundleConfig, stringifyBundleConfig } from "./bundle-config";
import type {
  ConfigEdit,
  ConfigEditValue,
  ConfigFormat,
  Finding,
  Policy,
  Project,
  SettingsFix,
} from "./domain";

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

type ParsedTable = { ok: true; value: Record<string, unknown> } | { ok: false };

type FormatEditor = (
  raw: string,
  edits: readonly ConfigEdit[]
) => string | null;

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

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

const parseJsonObject = (raw: string): ParsedTable => {
  try {
    const parsed: unknown = JSON.parse(raw);
    return isPlainObject(parsed) ? { ok: true, value: parsed } : { ok: false };
  } catch {
    return { ok: false };
  }
};

const cloneEditValue = (value: ConfigEditValue): unknown => {
  if (Array.isArray(value)) {
    return [...value];
  }
  if (typeof value === "object" && value !== null) {
    return { ...value };
  }
  return value;
};

const omitKey = (
  table: Record<string, unknown>,
  key: string
): Record<string, unknown> =>
  Object.fromEntries(Object.entries(table).filter(([name]) => name !== key));

const setPath = (
  table: Record<string, unknown>,
  key: string,
  value: unknown
): Record<string, unknown> => {
  const parts = key.split(".");
  const last = parts.at(-1);
  if (last === undefined) {
    return table;
  }
  if (parts.length === 1) {
    return { ...table, [last]: value };
  }
  const [head, ...rest] = parts;
  if (head === undefined) {
    return table;
  }
  const child = isPlainObject(table[head]) ? table[head] : {};
  return { ...table, [head]: setPath(child, rest.join("."), value) };
};

const unsetPath = (
  table: Record<string, unknown>,
  key: string
): Record<string, unknown> => {
  const parts = key.split(".");
  const last = parts.at(-1);
  if (last === undefined) {
    return table;
  }
  if (parts.length === 1) {
    return omitKey(table, last);
  }
  const [head, ...rest] = parts;
  if (head === undefined || !isPlainObject(table[head])) {
    return table;
  }
  return { ...table, [head]: unsetPath(table[head], rest.join(".")) };
};

const applyEdits = (
  table: Record<string, unknown>,
  edits: readonly ConfigEdit[]
): Record<string, unknown> => {
  let current = table;
  for (const edit of edits) {
    current =
      edit.op === "unset"
        ? unsetPath(current, edit.key)
        : setPath(current, edit.key, cloneEditValue(edit.value));
  }
  return current;
};

const stringifyNpmrcValue = (value: ConfigEditValue): string => {
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "boolean" || typeof value === "number") {
    return String(value);
  }
  return JSON.stringify(value);
};

const rewriteNpmrcLine = (
  line: string,
  updates: Record<string, string>,
  removed: ReadonlySet<string>,
  seen: Set<string>
): string | null => {
  const trimmed = line.trim();
  if (trimmed === "" || trimmed.startsWith("#") || trimmed.startsWith(";")) {
    return line;
  }
  const eq = trimmed.indexOf("=");
  if (eq <= 0) {
    return line;
  }
  const key = trimmed.slice(0, eq).trim();
  if (removed.has(key)) {
    return null;
  }
  if (key in updates) {
    seen.add(key);
    return `${key}=${updates[key]}`;
  }
  return line;
};

const editNpmrc = (raw: string, edits: readonly ConfigEdit[]): string => {
  let updates: Record<string, string> = {};
  const removed = new Set<string>();
  for (const edit of edits) {
    if (edit.op === "unset") {
      removed.add(edit.key);
      updates = omitKey(updates, edit.key) as Record<string, string>;
      continue;
    }
    removed.delete(edit.key);
    updates = { ...updates, [edit.key]: stringifyNpmrcValue(edit.value) };
  }
  const seen = new Set<string>();
  const lines = raw
    .split(/\r?\n/u)
    .map((line) => rewriteNpmrcLine(line, updates, removed, seen))
    .filter((line): line is string => line !== null);
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

const editYaml = (raw: string, edits: readonly ConfigEdit[]): string | null => {
  const parsed = parseYaml(raw);
  if (!parsed.ok) {
    return null;
  }
  return stringifyYaml(applyEdits(parsed.value, edits));
};

const editToml = (raw: string, edits: readonly ConfigEdit[]): string | null => {
  const parsed = parseTomlObject(raw);
  if (!parsed.ok) {
    return null;
  }
  return `${stringifyToml(applyEdits(parsed.value, edits)).trimEnd()}\n`;
};

const editBundleConfig = (
  raw: string,
  edits: readonly ConfigEdit[]
): string => {
  const config = parseBundleConfig(raw);
  const table = applyEdits({ ...config }, edits);
  const next: Record<string, string> = {};
  for (const [key, value] of Object.entries(table)) {
    if (typeof value === "string") {
      next[key] = value;
      continue;
    }
    if (typeof value === "boolean" || typeof value === "number") {
      next[key] = String(value);
    }
  }
  return stringifyBundleConfig(next);
};

const editJson = (raw: string, edits: readonly ConfigEdit[]): string | null => {
  const parsed = parseJsonObject(raw);
  if (!parsed.ok) {
    return null;
  }
  return `${JSON.stringify(applyEdits(parsed.value, edits), null, 4)}\n`;
};

const EDITORS: Record<ConfigFormat, FormatEditor> = {
  "bundle-config": editBundleConfig,
  json: editJson,
  npmrc: editNpmrc,
  toml: editToml,
  yaml: editYaml,
};

const collectFixes = (
  project: Project,
  findings: Finding[]
): Map<string, { format: ConfigFormat; edits: ConfigEdit[] }> => {
  const targets = new Map<
    string,
    { format: ConfigFormat; edits: ConfigEdit[] }
  >();
  for (const finding of findings) {
    const fix: SettingsFix | undefined = finding.fix;
    if (fix === undefined || isForbiddenWrite(fix.file, project.root)) {
      continue;
    }
    const entry = targets.get(fix.file) ?? {
      edits: [],
      format: fix.format,
    };
    entry.edits.push(...fix.edits);
    targets.set(fix.file, entry);
  }
  return targets;
};

const writeSettings = (
  project: Project,
  findings: Finding[],
  deps: ApplySettingsDeps
): string[] => {
  const written: string[] = [];
  for (const [filePath, target] of collectFixes(project, findings)) {
    const next = EDITORS[target.format](
      deps.readFile(filePath) ?? "",
      target.edits
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
    written.push(...writeSettings(item.project, item.findings, deps));
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

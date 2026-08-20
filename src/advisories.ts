import type { AdvisoryResult, Cache, PackageAdvisory } from "./cache";
import type {
  Finding,
  FindingKind,
  PackageManager,
  Policy,
  Project,
  Severity,
} from "./domain";

export type { AdvisoryResult, PackageAdvisory } from "./cache";

const LIVE_MANAGERS = new Set<PackageManager>([
  "npm",
  "pnpm",
  "yarn",
  "bun",
  "uv",
]);
const OSV_MANAGERS = new Set<PackageManager>(["poetry", "pip", "pipenv"]);

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const incompleteError = (): Error & { incomplete: true } =>
  Object.assign(new Error("advisory audit incomplete"), {
    incomplete: true as const,
  });

const auditArgv = (name: PackageManager): string[] | null => {
  switch (name) {
    case "npm": {
      return ["npm", "audit", "--json"];
    }
    case "pnpm": {
      return ["pnpm", "audit", "--json"];
    }
    case "bun": {
      return ["bun", "audit", "--json"];
    }
    case "yarn": {
      return ["yarn", "npm", "audit", "--json"];
    }
    case "uv": {
      return ["uv", "audit", "--output-format", "json", "--frozen"];
    }
    default: {
      return null;
    }
  }
};

const parseJson = (stdout: string): unknown => {
  try {
    return JSON.parse(stdout);
  } catch {
    // Yarn Berry's `yarn npm audit --json` emits newline-delimited JSON
    // (one advisory object per line) rather than a single JSON document.
    const lines = stdout
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
    if (lines.length > 1) {
      try {
        return lines.map((line) => JSON.parse(line));
      } catch {
        throw incompleteError();
      }
    }
    throw incompleteError();
  }
};

const concreteVersion = (value: unknown): string | undefined => {
  if (typeof value !== "string") {
    return undefined;
  }
  const trimmed = value.trim();
  if (trimmed === "" || /[<> =|^~*]/u.test(trimmed)) {
    return undefined;
  }
  // Core segments (before any prerelease/build suffix) must all be numeric,
  // so x-ranges like `1.2.x` or `1.X` never count as an installed version.
  const core = trimmed.split(/[-+]/u, 1)[0] ?? "";
  const segments = core.split(".");
  if (segments.length < 2) {
    return undefined;
  }
  if (!segments.every((segment) => /^\d+$/u.test(segment))) {
    return undefined;
  }
  return trimmed;
};

const versionFromRange = (range: string): string | undefined => {
  const match = range.match(/(?<version>\d+\.\d+\.\d+[\w.-]*)/u);
  return match?.groups?.version;
};

const kindFromItem = (
  item: Record<string, unknown>,
  fallback: FindingKind
): FindingKind => {
  const status = String(item.status ?? "").toLowerCase();
  if (status === "deprecated" || item.deprecated === true) {
    return "deprecated";
  }
  if (status === "quarantine" || item.quarantine === true) {
    return "quarantine";
  }
  return fallback;
};

const packageName = (value: unknown): string | undefined => {
  if (isPlainObject(value) && typeof value.name === "string") {
    return value.name;
  }
  return undefined;
};

const packageVersion = (value: unknown): string | undefined => {
  if (isPlainObject(value) && typeof value.version === "string") {
    return value.version;
  }
  return undefined;
};

const versionFromRecord = (
  record: Record<string, unknown>
): string | undefined =>
  concreteVersion(record.version) ?? concreteVersion(record.installedVersion);

const firstArrayVersion = (items: unknown): string | undefined => {
  if (!Array.isArray(items)) {
    return;
  }
  for (const item of items) {
    if (!isPlainObject(item)) {
      continue;
    }
    const version = versionFromRecord(item);
    if (version !== undefined) {
      return version;
    }
  }
};

const firstVersion = (item: Record<string, unknown>): string =>
  concreteVersion(item.version) ??
  concreteVersion(item.installedVersion) ??
  concreteVersion(packageVersion(item.package)) ??
  firstArrayVersion(item.findings) ??
  firstArrayVersion(item.via) ??
  "unknown";

const ghsaFromUrl = (url: string): string | undefined => {
  const match = url.match(/GHSA-[a-z0-9-]+/iu);
  return match?.[0];
};

const rawAdvisoryId = (item: Record<string, unknown>): unknown =>
  item.github_advisory_id ??
  item.id ??
  item.source ??
  (typeof item.url === "string" ? ghsaFromUrl(item.url) : undefined);

const advisoryId = (item: Record<string, unknown>): string => {
  const raw = rawAdvisoryId(item);
  if (raw === undefined || raw === null || raw === "") {
    return "";
  }
  return String(raw);
};

const SEVERITIES = new Set<string>([
  "critical",
  "high",
  "moderate",
  "low",
  "info",
]);

const asSeverity = (value: unknown): Severity => {
  const raw = Array.isArray(value) ? value[0] : value;
  const s = String(raw ?? "").toLowerCase();
  if (SEVERITIES.has(s)) {
    return s as Severity;
  }
  if (s === "medium") {
    return "moderate";
  }
  return "info";
};

const PATCH_KEYS = [
  "first_patched_version",
  "firstPatchedVersion",
  "patched_version",
] as const;

const fixFromAvailableObject = (available: unknown): string | undefined => {
  if (!isPlainObject(available) || typeof available.version !== "string") {
    return;
  }
  if (available.version === "") {
    return;
  }
  return available.version;
};

const fixFromAvailableString = (available: unknown): string | undefined => {
  if (
    typeof available !== "string" ||
    available === "" ||
    available === "true"
  ) {
    return;
  }
  return versionFromRange(available);
};

const fixFromAvailable = (available: unknown): string | undefined =>
  fixFromAvailableObject(available) ?? fixFromAvailableString(available);

const fixFromPatchKeys = (
  item: Record<string, unknown>
): string | undefined => {
  for (const key of PATCH_KEYS) {
    const raw = item[key];
    if (typeof raw !== "string") {
      continue;
    }
    const version = versionFromRange(raw);
    if (version !== undefined) {
      return version;
    }
  }
};

const fixFromPatchedOrFixed = (
  item: Record<string, unknown>
): string | undefined => {
  if (typeof item.patched_versions === "string") {
    return versionFromRange(item.patched_versions);
  }
  if (Array.isArray(item.fixed) && typeof item.fixed[0] === "string") {
    return item.fixed[0];
  }
};

const extractFix = (item: Record<string, unknown>): string | undefined =>
  fixFromAvailable(item.fixAvailable) ??
  fixFromPatchKeys(item) ??
  fixFromPatchedOrFixed(item);

type AdvisoryPush = (
  name: string,
  version: string,
  severity: Severity,
  id: string,
  message: string,
  kind: FindingKind,
  fix?: string
) => void;

const yarnTreeId = (children: Record<string, unknown>): string => {
  const rawId = children.ID;
  if (typeof rawId === "number" || typeof rawId === "string") {
    return String(rawId);
  }
  return advisoryId(children);
};

const yarnTreeVersion = (children: Record<string, unknown>): string => {
  const treeVersions = children["Tree Versions"];
  if (Array.isArray(treeVersions) && typeof treeVersions[0] === "string") {
    return concreteVersion(treeVersions[0]) ?? "unknown";
  }
  return "unknown";
};

const walkYarnTree = (
  item: Record<string, unknown>,
  push: AdvisoryPush
): boolean => {
  if (typeof item.value !== "string" || !isPlainObject(item.children)) {
    return false;
  }
  const name = item.value;
  const { children } = item;
  const severity = asSeverity(children.Severity ?? children.severity);
  const message = String(
    children.Issue ?? children.issue ?? `${name} ${severity} advisory`
  );
  const patched = children["Patched Versions"];
  const fix =
    typeof patched === "string" ? versionFromRange(patched) : undefined;
  push(
    name,
    yarnTreeVersion(children),
    severity,
    yarnTreeId(children),
    message,
    "advisory",
    fix
  );
  return true;
};

const pushAdvisoryRow = (
  item: Record<string, unknown>,
  via: Record<string, unknown>,
  name: string,
  version: string,
  kind: FindingKind,
  fallbackFix: string | undefined,
  push: AdvisoryPush
): void => {
  const severity = asSeverity(via.severity ?? item.severity);
  const message = String(
    via.title ?? via.summary ?? `${name} ${severity} advisory`
  );
  push(
    name,
    version,
    severity,
    advisoryId(via),
    message,
    kind,
    extractFix(via) ?? fallbackFix
  );
};

const pushStringViaFallback = (
  item: Record<string, unknown>,
  name: string,
  version: string,
  kind: FindingKind,
  fix: string | undefined,
  push: AdvisoryPush
): void => {
  if (!Array.isArray(item.via)) {
    return;
  }
  if (
    !(
      item.via.every((value) => typeof value === "string") &&
      item.via.length > 0
    )
  ) {
    return;
  }
  const severity = asSeverity(item.severity);
  push(
    name,
    version,
    severity,
    advisoryId(item),
    String(item.title ?? `${name} ${severity} advisory`),
    kind,
    fix
  );
};

const walkViaEntries = (
  item: Record<string, unknown>,
  kind: FindingKind,
  push: AdvisoryPush
): void => {
  const name = String(item.name ?? item.module_name ?? "unknown");
  const version = firstVersion(item);
  const fix = extractFix(item);
  if (!Array.isArray(item.via)) {
    return;
  }
  for (const via of item.via) {
    if (isPlainObject(via)) {
      pushAdvisoryRow(item, via, name, version, kind, fix, push);
    }
  }
  pushStringViaFallback(item, name, version, kind, fix, push);
};

const pushVulnRow = (
  item: Record<string, unknown>,
  vuln: Record<string, unknown>,
  name: string,
  version: string,
  kind: FindingKind,
  fallbackFix: string | undefined,
  push: AdvisoryPush
): void => {
  const severity = asSeverity(vuln.severity ?? item.severity);
  const message = String(
    vuln.summary ?? vuln.title ?? `${name} ${severity} advisory`
  );
  push(
    name,
    version,
    severity,
    advisoryId(vuln),
    message,
    kind,
    extractFix(vuln) ?? fallbackFix
  );
};

const walkVulnEntries = (
  item: Record<string, unknown>,
  kind: FindingKind,
  push: AdvisoryPush
): void => {
  const name = String(item.name ?? packageName(item.package) ?? "unknown");
  const version = firstVersion(item);
  const fix = extractFix(item);
  if (!Array.isArray(item.vulns)) {
    return;
  }
  for (const vuln of item.vulns) {
    if (isPlainObject(vuln)) {
      pushVulnRow(item, vuln, name, version, kind, fix, push);
    }
  }
};

const shouldWalkFindings = (
  item: Record<string, unknown>,
  kind: FindingKind
): boolean =>
  Array.isArray(item.findings) ||
  item.module_name !== undefined ||
  item.advisory !== undefined ||
  kind === "deprecated" ||
  kind === "quarantine";

const findingRowVersion = (
  finding: unknown,
  item: Record<string, unknown>
): string => {
  if (!isPlainObject(finding)) {
    return firstVersion(item);
  }
  return (
    concreteVersion(finding.version) ??
    concreteVersion(finding.installedVersion) ??
    firstVersion(item)
  );
};

const versionsForItem = (item: Record<string, unknown>): string[] => {
  if (!Array.isArray(item.findings) || item.findings.length === 0) {
    return [firstVersion(item)];
  }
  return item.findings.map((finding) => findingRowVersion(finding, item));
};

const itemPackageName = (item: Record<string, unknown>): string =>
  String(
    item.module_name ?? item.name ?? packageName(item.package) ?? "unknown"
  );

const itemAdvisoryMessage = (
  advisory: Record<string, unknown>,
  item: Record<string, unknown>,
  name: string,
  severity: Severity
): string =>
  String(
    advisory.title ??
      advisory.summary ??
      item.title ??
      `${name} ${severity} advisory`
  );

const walkFindingEntries = (
  item: Record<string, unknown>,
  kind: FindingKind,
  push: AdvisoryPush
): void => {
  const name = itemPackageName(item);
  const advisory = isPlainObject(item.advisory) ? item.advisory : item;
  const severity = asSeverity(advisory.severity ?? item.severity);
  const message = itemAdvisoryMessage(advisory, item, name, severity);
  const fix = extractFix(item);
  const id = advisoryId(advisory);
  for (const version of versionsForItem(item)) {
    push(name, version, severity, id, message, kindFromItem(item, kind), fix);
  }
};

const walkItem = (item: unknown, push: AdvisoryPush): void => {
  if (!isPlainObject(item)) {
    return;
  }
  if (walkYarnTree(item, push)) {
    return;
  }
  const kind = kindFromItem(item, "advisory");
  if (Array.isArray(item.via)) {
    walkViaEntries(item, kind, push);
    return;
  }
  if (Array.isArray(item.vulns)) {
    walkVulnEntries(item, kind, push);
    return;
  }
  if (shouldWalkFindings(item, kind)) {
    walkFindingEntries(item, kind, push);
  }
};

interface PackageBucket {
  name: string;
  version: string;
  rows: PackageAdvisory[];
}

const createAdvisoryPush =
  (
    findings: Finding[],
    packages: Map<string, PackageBucket>,
    manager: PackageManager,
    filePath: string
  ): AdvisoryPush =>
  (name, version, severity, id, message, kind, fix) => {
    findings.push({
      code: id || "advisory.unknown",
      currentVersion: concreteVersion(version),
      fixVersion: fix,
      fixable: Boolean(fix),
      kind,
      manager,
      message,
      package: name === "unknown" || name === "" ? undefined : name,
      path: filePath,
      severity,
    });
    const key = `${name}\0${version}`;
    const row: PackageAdvisory = {
      id: id || "advisory.unknown",
      name,
      severity,
      version,
    };
    const entry = packages.get(key) ?? { name, rows: [], version };
    entry.rows.push(row);
    packages.set(key, entry);
  };

const walkCollection = (value: unknown, push: AdvisoryPush): void => {
  if (isPlainObject(value)) {
    for (const item of Object.values(value)) {
      walkItem(item, push);
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      walkItem(item, push);
    }
  }
};

const mappedPackages = (
  findings: Finding[],
  packages: Map<string, PackageBucket>
): { findings: Finding[]; packages: PackageBucket[] } => ({
  findings,
  packages: [...packages.values()],
});

const mapAuditJson = (
  parsed: unknown,
  manager: PackageManager,
  filePath: string
): { findings: Finding[]; packages: PackageBucket[] } => {
  const findings: Finding[] = [];
  const packages = new Map<string, PackageBucket>();
  const push = createAdvisoryPush(findings, packages, manager, filePath);

  if (parsed === null || typeof parsed !== "object") {
    return { findings, packages: [] };
  }
  if (Array.isArray(parsed)) {
    walkCollection(parsed, push);
    return mappedPackages(findings, packages);
  }
  const obj = parsed as Record<string, unknown>;
  // Yarn Berry's `yarn npm audit --json` tree-reporter shape: a single
  // `{ value, children }` node (one per ndjson line, already unwrapped above
  // when there were multiple lines).
  if (typeof obj.value === "string" && isPlainObject(obj.children)) {
    walkItem(obj, push);
    return mappedPackages(findings, packages);
  }
  walkCollection(obj.advisories, push);
  walkCollection(obj.vulnerabilities, push);
  walkCollection(obj.dependencies, push);
  walkCollection(obj.audits, push);
  return mappedPackages(findings, packages);
};

interface AuditRunDeps {
  cache: Cache;
  digest: (lockfileBytes: string) => string;
  readFile: (path: string) => string | null;
  run: (
    argv: string[],
    cwd: string
  ) => Promise<{ code: number; stdout: string; stderr: string }>;
  refresh?: boolean;
  noCache?: boolean;
}

const mapSerial = async <T, R>(
  items: readonly T[],
  fn: (item: T) => Promise<R>
): Promise<R[]> => {
  const out: R[] = [];
  const runAt = async (index: number): Promise<void> => {
    if (index >= items.length) {
      return;
    }
    const item = items[index];
    if (item !== undefined) {
      out.push(await fn(item));
    }
    await runAt(index + 1);
  };
  await runAt(0);
  return out;
};

const readCachedFindings = (
  manager: Project["managers"][number],
  digest: string | null,
  skipCacheRead: boolean,
  cache: Cache
): Finding[] | null => {
  if (digest === null || skipCacheRead) {
    return null;
  }
  const cached = cache.getLockfile(digest);
  if (!cached) {
    return null;
  }
  const filePath = manager.lockfilePath ?? manager.manifestPath;
  return cached.findings.map((finding) => ({ ...finding, path: filePath }));
};

const runLiveAudit = async (
  manager: Project["managers"][number],
  project: Project,
  deps: AuditRunDeps
): Promise<{ findings: Finding[]; packages: PackageBucket[] } | null> => {
  const argv = auditArgv(manager.name);
  if (!argv) {
    return null;
  }
  let output: { code: number; stdout: string; stderr: string };
  try {
    output = await deps.run(argv, project.root);
  } catch {
    throw incompleteError();
  }
  if (output.code !== 0 && output.code !== 1) {
    throw incompleteError();
  }
  const parsed = output.stdout.trim() === "" ? {} : parseJson(output.stdout);
  return mapAuditJson(
    parsed,
    manager.name,
    manager.lockfilePath ?? manager.manifestPath
  );
};

const cacheLiveResult = (
  digest: string | null,
  live: { findings: Finding[]; packages: PackageBucket[] },
  deps: AuditRunDeps
): void => {
  if (digest !== null && deps.noCache !== true) {
    deps.cache.putLockfile(digest, {
      findings: live.findings,
      fromCache: false,
      ranLive: true,
    });
  }
  if (deps.noCache !== true) {
    for (const entry of live.packages) {
      deps.cache.putPackage(entry.name, entry.version, entry.rows);
    }
  }
};

const runOnePrimary = async (
  manager: Project["managers"][number],
  project: Project,
  deps: AuditRunDeps,
  skipCacheRead: boolean
): Promise<{ findings: Finding[]; fromCache: boolean; ranLive: boolean }> => {
  const lockfileBytes = manager.lockfilePath
    ? deps.readFile(manager.lockfilePath)
    : null;
  const digest = lockfileBytes === null ? null : deps.digest(lockfileBytes);
  const cached = readCachedFindings(manager, digest, skipCacheRead, deps.cache);
  if (cached !== null) {
    return { findings: cached, fromCache: true, ranLive: false };
  }
  const live = await runLiveAudit(manager, project, deps);
  if (live === null) {
    return { findings: [], fromCache: false, ranLive: false };
  }
  cacheLiveResult(digest, live, deps);
  return { findings: live.findings, fromCache: false, ranLive: true };
};

const runPrimaries = async (
  project: Project,
  primaries: Project["managers"],
  deps: AuditRunDeps
): Promise<AdvisoryResult> => {
  const skipCacheRead = deps.refresh === true || deps.noCache === true;
  const parts = await mapSerial(primaries, (manager) =>
    runOnePrimary(manager, project, deps, skipCacheRead)
  );
  return {
    findings: parts.flatMap((part) => part.findings),
    fromCache:
      parts.some((part) => part.fromCache) &&
      !parts.some((part) => part.ranLive),
    ranLive: parts.some((part) => part.ranLive),
  };
};

const isLivePrimary = (
  manager: Project["managers"][number],
  enabled: PackageManager[]
): boolean =>
  manager.role === "primary" &&
  LIVE_MANAGERS.has(manager.name) &&
  enabled.includes(manager.name);

const isOsvPrimary = (manager: Project["managers"][number]): boolean =>
  manager.role === "primary" && OSV_MANAGERS.has(manager.name);

const emptyLive = (): AdvisoryResult => ({
  findings: [],
  fromCache: false,
  ranLive: false,
});

const osvLockPath = (manager: Project["managers"][number]): string =>
  manager.lockfilePath ?? manager.manifestPath;

const mergeOsv = (
  live: AdvisoryResult,
  osvFindings: Finding[]
): AdvisoryResult => ({
  findings: [...live.findings, ...osvFindings],
  fromCache: live.fromCache && osvFindings.length === 0,
  ranLive: live.ranLive || osvFindings.length > 0,
});

export const auditAdvisories = async (
  project: Project,
  policy: Policy,
  deps: {
    cache: Cache;
    now: () => number;
    digest: (lockfileBytes: string) => string;
    readFile: (path: string) => string | null;
    run: (
      argv: string[],
      cwd: string
    ) => Promise<{ code: number; stdout: string; stderr: string }>;
    runOsv?: (lockOrRequirements: string) => Promise<Finding[]>;
    refresh?: boolean;
    noCache?: boolean;
  }
): Promise<AdvisoryResult> => {
  void deps.now;
  const primaries = project.managers.filter((manager) =>
    isLivePrimary(manager, policy.enabledManagers)
  );
  const python = project.managers.filter(isOsvPrimary);
  const live =
    primaries.length === 0
      ? emptyLive()
      : await runPrimaries(project, primaries, deps);
  const { runOsv } = deps;
  if (python.length === 0 || runOsv === undefined) {
    return live;
  }
  const osvResults = await Promise.all(
    python.map((manager) => runOsv(osvLockPath(manager)))
  );
  return mergeOsv(live, osvResults.flat());
};

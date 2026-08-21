import { parseAuditOutput } from "./advisory-report";
import type { ParsedAuditReport } from "./advisory-report";
import type { AdvisoryResult, Cache, PackageAdvisory } from "./cache";
import type { Finding, PackageManager, Policy, Project } from "./domain";
import { profileFor } from "./managers/profile";
import { mapSerial } from "./std";

export type { AdvisoryResult, PackageAdvisory } from "./cache";

const incompleteError = (): Error & { incomplete: true } =>
  Object.assign(new Error("advisory audit incomplete"), {
    incomplete: true as const,
  });

const auditArgv = (name: PackageManager): string[] | null => {
  const argv = profileFor(name).auditArgv;
  return argv ? [...argv] : null;
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

const emptyReport = (): ParsedAuditReport => ({
  findings: [],
  packages: [],
});

const runLiveAudit = async (
  manager: Project["managers"][number],
  project: Project,
  deps: AuditRunDeps
): Promise<ParsedAuditReport | null> => {
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
  if (output.stdout.trim() === "") {
    return emptyReport();
  }
  const parsed = parseAuditOutput(
    manager.name,
    output.stdout,
    manager.lockfilePath ?? manager.manifestPath
  );
  if (parsed === null) {
    throw incompleteError();
  }
  return parsed;
};

interface PackageBucket {
  name: string;
  version: string;
  rows: PackageAdvisory[];
}

const groupPackageRows = (rows: PackageAdvisory[]): PackageBucket[] => {
  const packages = new Map<string, PackageBucket>();
  for (const row of rows) {
    const key = `${row.name}\0${row.version}`;
    const entry = packages.get(key) ?? {
      name: row.name,
      rows: [],
      version: row.version,
    };
    entry.rows.push(row);
    packages.set(key, entry);
  }
  return [...packages.values()];
};

const cacheLiveResult = (
  digest: string | null,
  live: ParsedAuditReport,
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
    for (const entry of groupPackageRows(live.packages)) {
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
  profileFor(manager.name).kind === "config" &&
  enabled.includes(manager.name);

const isOsvPrimary = (manager: Project["managers"][number]): boolean =>
  manager.role === "primary" &&
  profileFor(manager.name).kind === "python-legacy";

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

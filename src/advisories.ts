import type { AdvisoryResult, Cache, PackageAdvisory } from "./cache";
import type {
  Finding,
  FindingKind,
  PackageManager,
  Policy,
  Project,
  Severity,
} from "./domain";

export type { AdvisoryResult, PackageAdvisory };

const LIVE_MANAGERS = new Set<PackageManager>(["npm", "pnpm", "yarn", "bun", "uv"]);
const OSV_MANAGERS = new Set<PackageManager>(["poetry", "pip", "pipenv"]);

export async function auditAdvisories(
  project: Project,
  _policy: Policy,
  deps: {
    cache: Cache;
    now: () => number;
    digest: (lockfileBytes: string) => string;
    readFile: (path: string) => string | null;
    run: (
      argv: string[],
      cwd: string,
    ) => Promise<{ code: number; stdout: string; stderr: string }>;
    runOsv?: (lockOrRequirements: string) => Promise<Finding[]>;
  },
): Promise<AdvisoryResult> {
  void deps.now;
  const primaries = project.managers.filter(
    (m) => m.role === "primary" && LIVE_MANAGERS.has(m.name),
  );
  const python = project.managers.filter(
    (m) => m.role === "primary" && OSV_MANAGERS.has(m.name),
  );

  const live =
    primaries.length === 0
      ? { findings: [] as Finding[], fromCache: false, ranLive: false }
      : await runPrimaries(project, primaries, deps);

  if (python.length === 0 || !deps.runOsv) {
    return live;
  }

  const osvFindings: Finding[] = [];
  for (const manager of python) {
    const lockOrRequirements = manager.lockfilePath ?? manager.manifestPath;
    osvFindings.push(...(await deps.runOsv(lockOrRequirements)));
  }
  return {
    findings: [...live.findings, ...osvFindings],
    fromCache: live.fromCache && osvFindings.length === 0,
    ranLive: live.ranLive || osvFindings.length > 0,
  };
}

async function runPrimaries(
  project: Project,
  primaries: Project["managers"],
  deps: {
    cache: Cache;
    digest: (lockfileBytes: string) => string;
    readFile: (path: string) => string | null;
    run: (
      argv: string[],
      cwd: string,
    ) => Promise<{ code: number; stdout: string; stderr: string }>;
  },
): Promise<AdvisoryResult> {
  const findings: Finding[] = [];
  let ranLive = false;
  let fromCache = false;

  for (const manager of primaries) {
    const lockfileBytes = manager.lockfilePath
      ? deps.readFile(manager.lockfilePath)
      : null;
    const canCacheLockfile = lockfileBytes !== null;
    const digest = canCacheLockfile ? deps.digest(lockfileBytes) : null;
    if (digest !== null) {
      const cached = deps.cache.getLockfile(digest);
      if (cached) {
        fromCache = true;
        findings.push(...cached.findings);
        continue;
      }
    }

    const argv = auditArgv(manager.name);
    if (!argv) continue;

    let output: { code: number; stdout: string; stderr: string };
    try {
      output = await deps.run(argv, project.root);
    } catch {
      throw incompleteError();
    }
    if (output.code !== 0 && output.code !== 1) {
      throw incompleteError();
    }

    const parsed = parseJson(output.stdout);
    const live = mapAuditJson(parsed, manager.name, manager.lockfilePath ?? manager.manifestPath);
    ranLive = true;
    findings.push(...live.findings);
    if (digest !== null) {
      deps.cache.putLockfile(digest, {
        findings: live.findings,
        fromCache: false,
        ranLive: true,
      });
    }
    for (const entry of live.packages) {
      deps.cache.putPackage(entry.name, entry.version, entry.rows);
    }
  }

  return { findings, fromCache: fromCache && !ranLive, ranLive };
}

function auditArgv(name: PackageManager): string[] | null {
  switch (name) {
    case "npm":
      return ["npm", "audit", "--json"];
    case "pnpm":
      return ["pnpm", "audit", "--json"];
    case "bun":
      return ["bun", "audit", "--json"];
    case "yarn":
      return ["yarn", "npm", "audit", "--json"];
    case "uv":
      return ["uv", "audit", "--output-format", "json", "--frozen"];
    default:
      return null;
  }
}

function parseJson(stdout: string): unknown {
  try {
    return JSON.parse(stdout);
  } catch {
    throw incompleteError();
  }
}

function incompleteError(): Error & { incomplete: true } {
  return Object.assign(new Error("advisory audit incomplete"), { incomplete: true });
}

function mapAuditJson(
  parsed: unknown,
  manager: PackageManager,
  path: string,
): { findings: Finding[]; packages: Array<{ name: string; version: string; rows: PackageAdvisory[] }> } {
  const findings: Finding[] = [];
  const packages = new Map<string, { name: string; version: string; rows: PackageAdvisory[] }>();

  const push = (
    name: string,
    version: string,
    severity: Severity,
    id: string,
    message: string,
    kind: FindingKind,
  ) => {
    findings.push({
      kind,
      code: id || "advisory.unknown",
      message,
      severity,
      path,
      fixable: false,
      manager,
    });
    const key = `${name}\0${version}`;
    const row: PackageAdvisory = { name, version, severity, id: id || "advisory.unknown" };
    const entry = packages.get(key) ?? { name, version, rows: [] };
    entry.rows.push(row);
    packages.set(key, entry);
  };

  if (parsed === null || typeof parsed !== "object") {
    return { findings, packages: [] };
  }

  if (Array.isArray(parsed)) {
    for (const item of parsed) walkItem(item, push);
    return { findings, packages: [...packages.values()] };
  }

  const obj = parsed as Record<string, unknown>;
  if (isPlainObject(obj.advisories)) {
    for (const value of Object.values(obj.advisories)) walkItem(value, push);
  }
  if (isPlainObject(obj.vulnerabilities)) {
    for (const value of Object.values(obj.vulnerabilities)) walkItem(value, push);
  } else if (Array.isArray(obj.vulnerabilities)) {
    for (const value of obj.vulnerabilities) walkItem(value, push);
  }
  if (Array.isArray(obj.dependencies)) {
    for (const value of obj.dependencies) walkItem(value, push);
  }
  if (Array.isArray(obj.audits)) {
    for (const value of obj.audits) walkItem(value, push);
  }

  return { findings, packages: [...packages.values()] };
}

function walkItem(
  item: unknown,
  push: (
    name: string,
    version: string,
    severity: Severity,
    id: string,
    message: string,
    kind: FindingKind,
  ) => void,
): void {
  if (!isPlainObject(item)) return;

  const status = String(item.status ?? "").toLowerCase();
  const kind: FindingKind =
    status === "deprecated" || item.deprecated === true
      ? "deprecated"
      : status === "quarantine" || item.quarantine === true
        ? "quarantine"
        : "advisory";

  if (Array.isArray(item.via)) {
    const name = String(item.name ?? item.module_name ?? "unknown");
    const version = firstVersion(item);
    for (const via of item.via) {
      if (!isPlainObject(via)) continue;
      const id = advisoryId(via);
      const severity = asSeverity(via.severity ?? item.severity);
      const message = String(via.title ?? via.summary ?? `${name} ${severity} advisory`);
      push(name, version, severity, id, message, kind);
    }
    if (item.via.every((v) => typeof v === "string") && item.via.length > 0) {
      const id = advisoryId(item);
      const severity = asSeverity(item.severity);
      push(name, version, severity, id, String(item.title ?? `${name} ${severity} advisory`), kind);
    }
    return;
  }

  if (Array.isArray(item.vulns)) {
    const name = String(item.name ?? packageName(item.package) ?? "unknown");
    const version = String(item.version ?? packageVersion(item.package) ?? firstVersion(item));
    for (const vuln of item.vulns) {
      if (!isPlainObject(vuln)) continue;
      const id = advisoryId(vuln);
      const severity = asSeverity(vuln.severity ?? item.severity);
      const message = String(vuln.summary ?? vuln.title ?? `${name} ${severity} advisory`);
      push(name, version, severity, id, message, kind);
    }
    return;
  }

  if (
    Array.isArray(item.findings) ||
    item.module_name !== undefined ||
    item.advisory !== undefined ||
    kind === "deprecated" ||
    kind === "quarantine"
  ) {
    const name = String(
      item.module_name ?? item.name ?? packageName(item.package) ?? "unknown",
    );
    const advisory = isPlainObject(item.advisory) ? item.advisory : item;
    const id = advisoryId(advisory);
    const severity = asSeverity(advisory.severity ?? item.severity);
    const message = String(
      advisory.title ?? advisory.summary ?? item.title ?? `${name} ${severity} advisory`,
    );
    const versions =
      Array.isArray(item.findings) && item.findings.length > 0
        ? item.findings.map((f) =>
            isPlainObject(f) ? String(f.version ?? firstVersion(item)) : firstVersion(item),
          )
        : [String(packageVersion(item.package) ?? firstVersion(item))];
    for (const version of versions) {
      push(name, version, severity, id, message, kindFromItem(item, kind));
    }
  }
}

function kindFromItem(item: Record<string, unknown>, fallback: FindingKind): FindingKind {
  const status = String(item.status ?? "").toLowerCase();
  if (status === "deprecated" || item.deprecated === true) return "deprecated";
  if (status === "quarantine" || item.quarantine === true) return "quarantine";
  return fallback;
}

function packageName(value: unknown): string | undefined {
  if (isPlainObject(value) && typeof value.name === "string") return value.name;
  return undefined;
}

function packageVersion(value: unknown): string | undefined {
  if (isPlainObject(value) && typeof value.version === "string") return value.version;
  return undefined;
}

function firstVersion(item: Record<string, unknown>): string {
  if (typeof item.version === "string") return item.version;
  if (Array.isArray(item.findings)) {
    const first = item.findings[0];
    if (isPlainObject(first) && first.version != null) return String(first.version);
  }
  if (typeof item.range === "string") return item.range;
  return "unknown";
}

function advisoryId(item: Record<string, unknown>): string {
  const raw =
    item.github_advisory_id ??
    item.id ??
    item.source ??
    (typeof item.url === "string" ? ghsaFromUrl(item.url) : undefined);
  if (raw === undefined || raw === null || raw === "") return "";
  return String(raw);
}

function ghsaFromUrl(url: string): string | undefined {
  const match = url.match(/GHSA-[a-z0-9-]+/i);
  return match?.[0];
}

function asSeverity(value: unknown): Severity {
  const raw = Array.isArray(value) ? value[0] : value;
  const s = String(raw ?? "").toLowerCase();
  if (s === "critical" || s === "high" || s === "moderate" || s === "low" || s === "info") {
    return s;
  }
  if (s === "medium") return "moderate";
  return "info";
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

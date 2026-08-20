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
    refresh?: boolean;
    noCache?: boolean;
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
    refresh?: boolean;
    noCache?: boolean;
  },
): Promise<AdvisoryResult> {
  const findings: Finding[] = [];
  let ranLive = false;
  let fromCache = false;
  const skipCacheRead = deps.refresh === true || deps.noCache === true;

  for (const manager of primaries) {
    const lockfileBytes = manager.lockfilePath
      ? deps.readFile(manager.lockfilePath)
      : null;
    const canCacheLockfile = lockfileBytes !== null;
    const digest = canCacheLockfile ? deps.digest(lockfileBytes) : null;
    if (digest !== null && !skipCacheRead) {
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

    const parsed = output.stdout.trim() === "" ? {} : parseJson(output.stdout);
    const live = mapAuditJson(parsed, manager.name, manager.lockfilePath ?? manager.manifestPath);
    ranLive = true;
    findings.push(...live.findings);
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
    fix?: string,
  ) => {
    findings.push({
      kind,
      code: id || "advisory.unknown",
      message,
      severity,
      path,
      fixable: Boolean(fix),
      manager,
      package: name === "unknown" || name === "" ? undefined : name,
      currentVersion: concreteVersion(version),
      fixVersion: fix,
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

  // Yarn Berry's `yarn npm audit --json` tree-reporter shape: a single
  // `{ value, children }` node (one per ndjson line, already unwrapped above
  // when there were multiple lines).
  if (typeof obj.value === "string" && isPlainObject(obj.children)) {
    walkItem(obj, push);
    return { findings, packages: [...packages.values()] };
  }

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
    fix?: string,
  ) => void,
): void {
  if (!isPlainObject(item)) return;

  if (typeof item.value === "string" && isPlainObject(item.children)) {
    const name = item.value;
    const children = item.children;
    const rawId = children.ID;
    const id =
      typeof rawId === "number" || typeof rawId === "string"
        ? String(rawId)
        : advisoryId(children);
    const severity = asSeverity(children.Severity ?? children.severity);
    const message = String(
      children.Issue ?? children.issue ?? `${name} ${severity} advisory`,
    );
    const treeVersions = children["Tree Versions"];
    const version =
      Array.isArray(treeVersions) && typeof treeVersions[0] === "string"
        ? (concreteVersion(treeVersions[0]) ?? "unknown")
        : "unknown";
    const patched = children["Patched Versions"];
    const fix = typeof patched === "string" ? versionFromRange(patched) : undefined;
    push(name, version, severity, id, message, "advisory", fix);
    return;
  }

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
    const fix = extractFix(item);
    for (const via of item.via) {
      if (!isPlainObject(via)) continue;
      const id = advisoryId(via);
      const severity = asSeverity(via.severity ?? item.severity);
      const message = String(via.title ?? via.summary ?? `${name} ${severity} advisory`);
      push(name, version, severity, id, message, kind, extractFix(via) ?? fix);
    }
    if (item.via.every((v) => typeof v === "string") && item.via.length > 0) {
      const id = advisoryId(item);
      const severity = asSeverity(item.severity);
      push(name, version, severity, id, String(item.title ?? `${name} ${severity} advisory`), kind, fix);
    }
    return;
  }

  if (Array.isArray(item.vulns)) {
    const name = String(item.name ?? packageName(item.package) ?? "unknown");
    const version = firstVersion(item);
    const fix = extractFix(item);
    for (const vuln of item.vulns) {
      if (!isPlainObject(vuln)) continue;
      const id = advisoryId(vuln);
      const severity = asSeverity(vuln.severity ?? item.severity);
      const message = String(vuln.summary ?? vuln.title ?? `${name} ${severity} advisory`);
      push(name, version, severity, id, message, kind, extractFix(vuln) ?? fix);
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
            isPlainObject(f)
              ? (concreteVersion(f.version) ??
                concreteVersion(f.installedVersion) ??
                firstVersion(item))
              : firstVersion(item),
          )
        : [firstVersion(item)];
    const fix = extractFix(item);
    for (const version of versions) {
      push(name, version, severity, id, message, kindFromItem(item, kind), fix);
    }
  }
}

function extractFix(item: Record<string, unknown>): string | undefined {
  const available = item.fixAvailable;
  if (isPlainObject(available) && typeof available.version === "string" && available.version !== "") {
    return available.version;
  }
  if (typeof available === "string" && available !== "" && available !== "true") {
    return versionFromRange(available);
  }
  for (const key of ["first_patched_version", "firstPatchedVersion", "patched_version"] as const) {
    const raw = item[key];
    if (typeof raw === "string") {
      const version = versionFromRange(raw);
      if (version !== undefined) return version;
    }
  }
  if (typeof item.patched_versions === "string") return versionFromRange(item.patched_versions);
  if (Array.isArray(item.fixed) && typeof item.fixed[0] === "string") return item.fixed[0];
  return undefined;
}

function versionFromRange(range: string): string | undefined {
  const match = range.match(/(\d+\.\d+\.\d+[\w.-]*)/);
  return match?.[1];
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
  const direct =
    concreteVersion(item.version) ??
    concreteVersion(item.installedVersion) ??
    concreteVersion(packageVersion(item.package));
  if (direct !== undefined) return direct;
  if (Array.isArray(item.findings)) {
    for (const finding of item.findings) {
      if (!isPlainObject(finding)) continue;
      const version = concreteVersion(finding.version) ?? concreteVersion(finding.installedVersion);
      if (version !== undefined) return version;
    }
  }
  if (Array.isArray(item.via)) {
    for (const via of item.via) {
      if (!isPlainObject(via)) continue;
      const version = concreteVersion(via.version) ?? concreteVersion(via.installedVersion);
      if (version !== undefined) return version;
    }
  }
  return "unknown";
}

function concreteVersion(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (trimmed === "" || /[<> =|^~*]/.test(trimmed)) return undefined;
  // Core segments (before any prerelease/build suffix) must all be numeric,
  // so x-ranges like `1.2.x` or `1.X` never count as an installed version.
  const core = trimmed.split(/[-+]/, 1)[0] ?? "";
  const segments = core.split(".");
  if (segments.length < 2) return undefined;
  if (!segments.every((segment) => /^\d+$/.test(segment))) return undefined;
  return trimmed;
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

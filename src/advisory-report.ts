import type { PackageAdvisory } from "./cache";
import type { Finding, FindingKind, PackageManager, Severity } from "./domain";

export interface ParsedAuditReport {
  findings: Finding[];
  packages: PackageAdvisory[];
}

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const parseStdoutJson = (stdout: string): unknown | undefined => {
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
        return undefined;
      }
    }
    return undefined;
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

const advisoryKindOverride = (
  item: Record<string, unknown>
): FindingKind | null => {
  const status = String(item.status ?? "").toLowerCase();
  if (status === "deprecated" || item.deprecated === true) {
    return "deprecated";
  }
  if (status === "quarantine" || item.quarantine === true) {
    return "quarantine";
  }
  return null;
};

const kindFromItem = (
  item: Record<string, unknown>,
  fallback: FindingKind
): FindingKind => advisoryKindOverride(item) ?? fallback;

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

const directVersion = (item: Record<string, unknown>): string | undefined => {
  for (const field of [
    item.version,
    item.installedVersion,
    packageVersion(item.package),
    packageVersion(item.gem),
  ]) {
    const version = concreteVersion(field);
    if (version !== undefined) {
      return version;
    }
  }
};

const firstVersion = (item: Record<string, unknown>): string =>
  directVersion(item) ??
  firstArrayVersion(item.findings) ??
  firstArrayVersion(item.via) ??
  "unknown";

const ghsaFromUrl = (url: string): string | undefined => {
  const match = url.match(/GHSA-[a-z0-9-]+/iu);
  return match?.[0];
};

const rawAdvisoryId = (item: Record<string, unknown>): unknown =>
  item.advisoryId ??
  item.github_advisory_id ??
  item.id ??
  item.cve ??
  item.remoteId ??
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

const fixFromPatchedVersions = (value: unknown): string | undefined => {
  if (typeof value === "string") {
    return versionFromRange(value);
  }
  if (!Array.isArray(value)) {
    return;
  }
  for (const entry of value) {
    if (typeof entry !== "string") {
      continue;
    }
    const version = versionFromRange(entry);
    if (version !== undefined) {
      return version;
    }
  }
};

const fixFromPatchedOrFixed = (
  item: Record<string, unknown>
): string | undefined => {
  const patched = fixFromPatchedVersions(item.patched_versions);
  if (patched !== undefined) {
    return patched;
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
  item.advisoryId !== undefined ||
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
    item.module_name ??
      item.packageName ??
      item.name ??
      packageName(item.package) ??
      packageName(item.gem) ??
      "unknown"
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
  const severity = asSeverity(
    advisory.severity ?? advisory.criticality ?? item.severity
  );
  const message = itemAdvisoryMessage(advisory, item, name, severity);
  const fix = extractFix(advisory) ?? extractFix(item);
  const id = advisoryId(advisory);
  for (const version of versionsForItem(item)) {
    push(name, version, severity, id, message, kindFromItem(item, kind), fix);
  }
};

const walk = {
  collection: (value: unknown, push: AdvisoryPush): void => {
    if (isPlainObject(value)) {
      for (const item of Object.values(value)) {
        walk.item(item, push);
      }
      return;
    }
    if (Array.isArray(value)) {
      for (const item of value) {
        walk.item(item, push);
      }
    }
  },
  item: (item: unknown, push: AdvisoryPush): void => {
    if (Array.isArray(item)) {
      walk.collection(item, push);
      return;
    }
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
      return;
    }
    walk.collection(item, push);
  },
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

const mappedPackages = (
  findings: Finding[],
  packages: Map<string, PackageBucket>
): ParsedAuditReport => ({
  findings,
  packages: [...packages.values()].flatMap((bucket) => bucket.rows),
});

const walkAbandoned = (abandoned: unknown, push: AdvisoryPush): void => {
  if (!isPlainObject(abandoned)) {
    return;
  }
  for (const name of Object.keys(abandoned)) {
    if (name === "") {
      continue;
    }
    push(
      name,
      "unknown",
      "info",
      "advisory.abandoned",
      `${name} is abandoned`,
      "deprecated",
      undefined
    );
  }
};

const walkAuditRoots = (
  obj: Record<string, unknown>,
  push: AdvisoryPush
): void => {
  walk.collection(obj.advisories, push);
  if (
    isPlainObject(obj.vulnerabilities) &&
    Array.isArray(obj.vulnerabilities.list)
  ) {
    walk.collection(obj.vulnerabilities.list, push);
  } else {
    walk.collection(obj.vulnerabilities, push);
  }
  walk.collection(obj.results, push);
  walk.collection(obj.dependencies, push);
  walk.collection(obj.audits, push);
  walkAbandoned(obj.abandoned, push);
};

const mapAuditJson = (
  parsed: unknown,
  manager: PackageManager,
  filePath: string
): ParsedAuditReport => {
  const findings: Finding[] = [];
  const packages = new Map<string, PackageBucket>();
  const push = createAdvisoryPush(findings, packages, manager, filePath);

  if (parsed === null || typeof parsed !== "object") {
    return { findings, packages: [] };
  }
  if (Array.isArray(parsed)) {
    walk.collection(parsed, push);
    return mappedPackages(findings, packages);
  }
  const obj = parsed as Record<string, unknown>;
  // Yarn Berry's `yarn npm audit --json` tree-reporter shape: a single
  // `{ value, children }` node (one per ndjson line, already unwrapped above
  // when there were multiple lines).
  if (typeof obj.value === "string" && isPlainObject(obj.children)) {
    walk.item(obj, push);
    return mappedPackages(findings, packages);
  }
  walkAuditRoots(obj, push);
  return mappedPackages(findings, packages);
};

/** Normalize one manager's `… audit --json` stdout. Returns null when stdout is not parseable as that manager's report shape. */
export const parseAuditOutput = (
  manager: PackageManager,
  stdout: string,
  lockPath: string
): ParsedAuditReport | null => {
  const parsed = parseStdoutJson(stdout);
  if (parsed === undefined) {
    return null;
  }
  return mapAuditJson(parsed, manager, lockPath);
};

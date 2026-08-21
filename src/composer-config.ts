import { isPlainObject } from "./std";

export type ComposerAuditMode = "ignore" | "report" | "fail";

export interface ComposerSecurity {
  allowPlugins: unknown;
  disableTls: boolean;
  secureHttp: boolean;
  sourceFallback: boolean;
  policyDisabled: boolean;
  advisoriesBlock: boolean;
  advisoriesAudit: ComposerAuditMode;
  malwareBlock: boolean;
  httpRepoUrls: string[];
}

const asObject = (value: unknown): Record<string, unknown> =>
  isPlainObject(value) ? value : {};

const asBoolean = (value: unknown, fallback: boolean): boolean =>
  typeof value === "boolean" ? value : fallback;

const asAuditMode = (
  value: unknown,
  fallback: ComposerAuditMode
): ComposerAuditMode =>
  value === "ignore" || value === "report" || value === "fail"
    ? value
    : fallback;

export const parseComposerManifest = (
  raw: string
): Record<string, unknown> | null => {
  try {
    const parsed: unknown = JSON.parse(raw);
    return isPlainObject(parsed) ? parsed : null;
  } catch {
    return null;
  }
};

const httpUrl = (value: unknown): string | null => {
  if (typeof value !== "string" || !value.startsWith("http://")) {
    return null;
  }
  return value;
};

const repoUrl = (value: unknown): string | null => {
  if (!isPlainObject(value)) {
    return null;
  }
  return httpUrl(value.url);
};

const collectHttpRepoUrls = (repositories: unknown): string[] => {
  const urls: string[] = [];
  if (Array.isArray(repositories)) {
    for (const entry of repositories) {
      const url = repoUrl(entry);
      if (url !== null) {
        urls.push(url);
      }
    }
    return urls;
  }
  if (!isPlainObject(repositories)) {
    return urls;
  }
  for (const entry of Object.values(repositories)) {
    const url = repoUrl(entry);
    if (url !== null) {
      urls.push(url);
    }
  }
  return urls;
};

const policyTable = (
  config: Record<string, unknown>
): Record<string, unknown> | false | null => {
  if (config.policy === false) {
    return false;
  }
  return isPlainObject(config.policy) ? config.policy : null;
};

const advisoriesFromLegacy = (
  audit: Record<string, unknown>
): { block: boolean; mode: ComposerAuditMode } => ({
  block: asBoolean(audit["block-insecure"], true),
  mode: "fail",
});

const advisoriesFromPolicy = (
  policy: Record<string, unknown>,
  audit: Record<string, unknown>
): { block: boolean; mode: ComposerAuditMode } => {
  if (policy.advisories !== undefined) {
    const advisories = asObject(policy.advisories);
    return {
      block: asBoolean(advisories.block, true),
      mode: asAuditMode(advisories.audit, "fail"),
    };
  }
  return advisoriesFromLegacy(audit);
};

const malwareBlockFromPolicy = (policy: Record<string, unknown>): boolean => {
  if (policy.malware === undefined) {
    return true;
  }
  return asBoolean(asObject(policy.malware).block, true);
};

const advisoriesFromManifest = (
  policy: Record<string, unknown> | false | null,
  audit: Record<string, unknown>
): { block: boolean; mode: ComposerAuditMode } => {
  if (policy === false) {
    return { block: false, mode: "ignore" };
  }
  if (policy === null) {
    return advisoriesFromLegacy(audit);
  }
  return advisoriesFromPolicy(policy, audit);
};

const malwareBlockFromManifest = (
  policy: Record<string, unknown> | false | null
): boolean => {
  if (policy === false || policy === null) {
    return true;
  }
  return malwareBlockFromPolicy(policy);
};

export const readComposerSecurity = (
  manifest: Record<string, unknown>
): ComposerSecurity => {
  const config = asObject(manifest.config);
  const policy = policyTable(config);
  const audit = asObject(config.audit);
  const advisories = advisoriesFromManifest(policy, audit);
  return {
    advisoriesAudit: advisories.mode,
    advisoriesBlock: advisories.block,
    allowPlugins: config["allow-plugins"],
    disableTls: asBoolean(config["disable-tls"], false),
    httpRepoUrls: collectHttpRepoUrls(manifest.repositories),
    malwareBlock: malwareBlockFromManifest(policy),
    policyDisabled: policy === false,
    secureHttp: asBoolean(config["secure-http"], true),
    sourceFallback: asBoolean(config["source-fallback"], false),
  };
};

const ensureConfig = (
  manifest: Record<string, unknown>
): Record<string, unknown> => {
  const config = asObject(manifest.config);
  manifest.config = config;
  return config;
};

const ensurePolicyObject = (
  config: Record<string, unknown>
): Record<string, unknown> => {
  if (!isPlainObject(config.policy)) {
    config.policy = {};
  }
  return config.policy;
};

const ensureNested = (
  parent: Record<string, unknown>,
  key: string
): Record<string, unknown> => {
  if (!isPlainObject(parent[key])) {
    parent[key] = {};
  }
  return parent[key];
};

const applyScriptsFix = (
  config: Record<string, unknown>,
  codes: ReadonlySet<string>
): void => {
  if (codes.has("scripts.unrestricted")) {
    config["allow-plugins"] = false;
  }
};

const applyTlsFix = (
  config: Record<string, unknown>,
  codes: ReadonlySet<string>
): void => {
  if (!codes.has("registry.unpinned")) {
    return;
  }
  delete config["disable-tls"];
  config["secure-http"] = true;
};

const needsPolicyFix = (codes: ReadonlySet<string>): boolean =>
  codes.has("audit.disabled") ||
  codes.has("audit.blocking-disabled") ||
  codes.has("audit.malware-disabled");

const applyAdvisoriesPolicyFix = (
  policy: Record<string, unknown>,
  codes: ReadonlySet<string>
): void => {
  const auditDisabled = codes.has("audit.disabled");
  const blockingDisabled = codes.has("audit.blocking-disabled");
  if (!auditDisabled && !blockingDisabled) {
    return;
  }
  const advisories = ensureNested(policy, "advisories");
  if (auditDisabled) {
    advisories.audit = "fail";
  }
  if (blockingDisabled || auditDisabled) {
    advisories.block = true;
  }
};

const applyMalwarePolicyFix = (
  policy: Record<string, unknown>,
  codes: ReadonlySet<string>
): void => {
  if (codes.has("audit.malware-disabled") || codes.has("audit.disabled")) {
    ensureNested(policy, "malware").block = true;
  }
};

const applyPolicyFixes = (
  config: Record<string, unknown>,
  codes: ReadonlySet<string>
): void => {
  if (!needsPolicyFix(codes)) {
    return;
  }
  if (config.policy === false) {
    delete config.policy;
  }
  const policy = ensurePolicyObject(config);
  applyAdvisoriesPolicyFix(policy, codes);
  applyMalwarePolicyFix(policy, codes);
};

const applySourceFallbackFix = (
  config: Record<string, unknown>,
  codes: ReadonlySet<string>
): void => {
  if (codes.has("source-fallback.enabled")) {
    config["source-fallback"] = false;
  }
};

export const mergeComposerManifest = (
  manifest: Record<string, unknown>,
  codes: Iterable<string>
): Record<string, unknown> => {
  const next = { ...manifest };
  const config = { ...ensureConfig(next) };
  next.config = config;
  const codeSet = codes instanceof Set ? codes : new Set(codes);
  applyScriptsFix(config, codeSet);
  applyTlsFix(config, codeSet);
  applyPolicyFixes(config, codeSet);
  applySourceFallbackFix(config, codeSet);
  return next;
};

export const stringifyComposerManifest = (
  manifest: Record<string, unknown>
): string => `${JSON.stringify(manifest, null, 4)}\n`;

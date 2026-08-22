import { expect, test } from "bun:test";

import type { Project } from "../src/domain";
import { loadPolicy } from "../src/policy";
import { auditSettings } from "../src/settings";

const npmProject = (root: string): Project => ({
  gitRoot: root,
  managers: [
    {
      configPath: `${root}/.npmrc`,
      lockfilePath: `${root}/package-lock.json`,
      manifestPath: `${root}/package.json`,
      name: "npm",
      role: "primary",
    },
  ],
  root,
});

test("standard preset flags npm without ignore-scripts", () => {
  const files: Record<string, string> = {
    "/p/.npmrc": `registry=https://registry.npmjs.org/\n`,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/package.json": `{"name":"x"}`,
  };
  const findings = auditSettings(npmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "scripts.unrestricted")).toBe(true);
});

test("standard preset is quiet on ignore-scripts when set", () => {
  const files: Record<string, string> = {
    "/p/.npmrc": `ignore-scripts=true\nallow-scripts-pin=true\naudit=true\naudit-level=high\nmin-release-age=7\nregistry=https://registry.npmjs.org/\n`,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/package.json": `{"name":"x","packageManager":"npm@10.9.0"}`,
  };
  const findings = auditSettings(npmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.filter((f) => f.kind === "settings")).toEqual([]);
});

const pnpmProject = (root: string): Project => ({
  gitRoot: root,
  managers: [
    {
      configPath: `${root}/pnpm-workspace.yaml`,
      lockfilePath: `${root}/pnpm-lock.yaml`,
      manifestPath: `${root}/package.json`,
      name: "pnpm",
      role: "primary",
    },
  ],
  root,
});

test("pnpm bare minimumReleaseAge is minutes so 720 fails the standard 1-day bar", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"pnpm@10.0.0"}`,
    "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "/p/pnpm-workspace.yaml":
      "packages:\n  - '.'\nminimumReleaseAge: 720\nonlyBuiltDependencies: []\n",
  };
  const findings = auditSettings(pnpmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "min-age.disabled")).toBe(true);
});

test("pnpm bare minimumReleaseAge of 1440 minutes meets the standard 1-day bar", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"pnpm@10.0.0"}`,
    "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "/p/pnpm-workspace.yaml":
      "packages:\n  - '.'\nminimumReleaseAge: 1440\nonlyBuiltDependencies: []\n",
  };
  const findings = auditSettings(pnpmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "min-age.disabled")).toBe(false);
});

test("leftover npm lockfile is a leftover finding and is not fixable", () => {
  const project: Project = {
    gitRoot: "/p",
    managers: [
      {
        configPath: "/p/pnpm-workspace.yaml",
        lockfilePath: "/p/pnpm-lock.yaml",
        manifestPath: "/p/package.json",
        name: "pnpm",
        role: "primary",
      },
      {
        configPath: null,
        lockfilePath: "/p/package-lock.json",
        manifestPath: "/p/package.json",
        name: "npm",
        role: "leftover",
      },
    ],
    root: "/p",
  };
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"pnpm@10.0.0"}`,
    "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "/p/pnpm-workspace.yaml": "packages:\n  - '.'\nminimumReleaseAge: 1440\n",
  };
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  const leftover = findings.find((f) => f.code === "lockfile.leftover");
  expect(leftover?.fixable).toBe(false);
  expect(leftover?.severity).toBe("high");
});

test("yarn v1 is unsupported and not fixable", () => {
  const project: Project = {
    gitRoot: "/y",
    managers: [
      {
        configPath: null,
        lockfilePath: "/y/yarn.lock",
        manifestPath: "/y/package.json",
        name: "yarn",
        role: "unsupported",
      },
    ],
    root: "/y",
  };
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => (p.endsWith("package.json") ? `{"name":"y"}` : null),
  });
  expect(findings).toEqual([
    expect.objectContaining({
      code: "pm.unsupported",
      fixable: false,
      kind: "unsupported-pm",
      severity: "high",
    }),
  ]);
});

test("yarn berry without enableScripts false is unrestricted under standard", () => {
  const project: Project = {
    gitRoot: "/y",
    managers: [
      {
        configPath: "/y/.yarnrc.yml",
        lockfilePath: "/y/yarn.lock",
        manifestPath: "/y/package.json",
        name: "yarn",
        role: "primary",
      },
    ],
    root: "/y",
  };
  const files: Record<string, string> = {
    "/y/.yarnrc.yml": `nodeLinker: node-modules\n`,
    "/y/package.json": `{"name":"y","packageManager":"yarn@4.5.0"}`,
    "/y/yarn.lock": "# yarn lockfile v1\n",
  };
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "scripts.unrestricted")).toBe(true);
});

test("poetry primary emits python.not-uv and is not fixable", () => {
  const project: Project = {
    gitRoot: "/p",
    managers: [
      {
        configPath: "/p/pyproject.toml",
        lockfilePath: "/p/poetry.lock",
        manifestPath: "/p/pyproject.toml",
        name: "poetry",
        role: "primary",
      },
    ],
    root: "/p",
  };
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) =>
      p.endsWith("pyproject.toml") ? `[tool.poetry]\nname = "x"\n` : null,
  });
  expect(findings).toEqual([
    expect.objectContaining({
      code: "python.not-uv",
      fixable: false,
      kind: "not-using-uv",
      severity: "high",
    }),
  ]);
});

const bunProject = (root: string): Project => ({
  gitRoot: root,
  managers: [
    {
      configPath: `${root}/bunfig.toml`,
      lockfilePath: `${root}/bun.lock`,
      manifestPath: `${root}/package.json`,
      name: "bun",
      role: "primary",
    },
  ],
  root,
});

const uvProject = (root: string): Project => ({
  gitRoot: root,
  managers: [
    {
      configPath: `${root}/pyproject.toml`,
      lockfilePath: `${root}/uv.lock`,
      manifestPath: `${root}/pyproject.toml`,
      name: "uv",
      role: "primary",
    },
  ],
  root,
});

test("bun primary with bare bunfig.toml has no trustedDependencies so scripts are unrestricted", () => {
  const files: Record<string, string> = {
    "/p/bun.lock": `{"lockfileVersion":1}`,
    "/p/bunfig.toml": `[install]\nregistry = "https://registry.npmjs.org/"\n`,
    "/p/package.json": `{"name":"x"}`,
  };
  const findings = auditSettings(bunProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "scripts.unrestricted")).toBe(true);
});

test("bun primary fully configured is quiet under standard", () => {
  const files: Record<string, string> = {
    "/p/bun.lock": `{"lockfileVersion":1}`,
    "/p/bunfig.toml": `trustedDependencies = ["foo"]\n\n[install]\nregistry = "https://registry.npmjs.org/"\nminimumReleaseAge = 86400\n`,
    "/p/package.json": `{"name":"x"}`,
  };
  const findings = auditSettings(bunProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.filter((f) => f.kind === "settings")).toEqual([]);
});

test("bun primary with no lockfile emits lockfile.missing", () => {
  const files: Record<string, string> = {
    "/p/bunfig.toml": `trustedDependencies = ["foo"]\n\n[install]\nregistry = "https://registry.npmjs.org/"\n`,
    "/p/package.json": `{"name":"x"}`,
  };
  const findings = auditSettings(bunProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "lockfile.missing")).toBe(true);
});

test("uv primary with uv.lock absent emits lockfile.missing", () => {
  const files: Record<string, string> = {
    "/p/pyproject.toml": `[tool.uv]\nexclude-newer = 30\n`,
  };
  const findings = auditSettings(uvProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "lockfile.missing")).toBe(true);
});

test("uv primary with compliant exclude-newer and lock present is quiet, and uv never emits pm.unpinned", () => {
  const files: Record<string, string> = {
    "/p/pyproject.toml": `[tool.uv]\nexclude-newer = 30\n\n[tool.uv.audit]\nmalware-check = true\n`,
    "/p/uv.lock": `version = 1\n`,
  };
  const findings = auditSettings(uvProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.filter((f) => f.kind === "settings")).toEqual([]);
  expect(findings.some((f) => f.code === "pm.unpinned")).toBe(false);
});

test("uv primary missing exclude-newer emits min-age.disabled under standard", () => {
  const files: Record<string, string> = {
    "/p/pyproject.toml": `[tool.uv]\n`,
    "/p/uv.lock": `version = 1\n`,
  };
  const findings = auditSettings(uvProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "min-age.disabled")).toBe(true);
});

test("uv exclude-newer as an ISO date ~12 hours ago emits min-age.disabled under standard", () => {
  const twelveHoursAgo = new Date(Date.now() - 12 * 3_600_000).toISOString();
  const files: Record<string, string> = {
    "/p/pyproject.toml": `[tool.uv]\nexclude-newer = "${twelveHoursAgo}"\n`,
    "/p/uv.lock": `version = 1\n`,
  };
  const findings = auditSettings(uvProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "min-age.disabled")).toBe(true);
});

test("uv exclude-newer as an ISO date ~30 days ago is quiet under standard", () => {
  const thirtyDaysAgo = new Date(Date.now() - 30 * 86_400_000).toISOString();
  const files: Record<string, string> = {
    "/p/pyproject.toml": `[tool.uv]\nexclude-newer = "${thirtyDaysAgo}"\n`,
    "/p/uv.lock": `version = 1\n`,
  };
  const findings = auditSettings(uvProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "min-age.disabled")).toBe(false);
});

test("uv strict flags an extra index without index-strategy first-index, standard does not", () => {
  const files: Record<string, string> = {
    "/p/pyproject.toml": `[tool.uv]\nexclude-newer = 30\nextra-index-url = "https://extra.example/simple"\n`,
    "/p/uv.lock": `version = 1\n`,
  };
  const strictFindings = auditSettings(
    uvProject("/p"),
    loadPolicy({ flags: { preset: "strict" } }),
    { readFile: (p) => files[p] ?? null }
  );
  expect(strictFindings.some((f) => f.code === "registry.unpinned")).toBe(true);

  const standardFindings = auditSettings(uvProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(standardFindings.some((f) => f.code === "registry.unpinned")).toBe(
    false
  );
});

test("relaxed preset does not require ignore-scripts, min-release-age, or pm pin", () => {
  const files: Record<string, string> = {
    "/p/.npmrc": `registry=https://registry.npmjs.org/\n`,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/package.json": `{"name":"x"}`,
  };
  const findings = auditSettings(
    npmProject("/p"),
    loadPolicy({ flags: { preset: "relaxed" } }),
    { readFile: (p) => files[p] ?? null }
  );
  expect(findings.some((f) => f.code === "scripts.unrestricted")).toBe(false);
  expect(findings.some((f) => f.code === "min-age.disabled")).toBe(false);
  expect(findings.some((f) => f.code === "pm.unpinned")).toBe(false);
});

test("strict preset flags unpinned registry and pm as high, standard flags the same as info", () => {
  const files: Record<string, string> = {
    "/p/.npmrc": `ignore-scripts=true\naudit=true\nmin-release-age=14\n`,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/package.json": `{"name":"x"}`,
  };
  const strictFindings = auditSettings(
    npmProject("/p"),
    loadPolicy({ flags: { preset: "strict" } }),
    { readFile: (p) => files[p] ?? null }
  );
  expect(
    strictFindings.find((f) => f.code === "registry.unpinned")?.severity
  ).toBe("high");
  expect(strictFindings.find((f) => f.code === "pm.unpinned")?.severity).toBe(
    "high"
  );

  const standardFindings = auditSettings(npmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(
    standardFindings.find((f) => f.code === "registry.unpinned")?.severity
  ).toBe("info");
  expect(standardFindings.find((f) => f.code === "pm.unpinned")?.severity).toBe(
    "info"
  );
});

const validNpmrc =
  "ignore-scripts=true\naudit=true\naudit-level=high\nmin-release-age=7\nregistry=https://registry.npmjs.org/\n";

test("npm missing package-lock.json emits lockfile.missing under standard", () => {
  const files: Record<string, string> = {
    "/p/.npmrc": validNpmrc,
    "/p/package.json": `{"name":"x","packageManager":"npm@10.9.0"}`,
  };
  const findings = auditSettings(npmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "lockfile.missing")).toBe(true);
});

test("npm .npmrc with no audit config emits audit.disabled under standard", () => {
  const files: Record<string, string> = {
    "/p/.npmrc": `ignore-scripts=true\nmin-release-age=7\nregistry=https://registry.npmjs.org/\n`,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/package.json": `{"name":"x","packageManager":"npm@10.9.0"}`,
  };
  const findings = auditSettings(npmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "audit.disabled")).toBe(true);
});

test("npm with no min-release-age emits min-age.disabled under standard", () => {
  const files: Record<string, string> = {
    "/p/.npmrc": `ignore-scripts=true\naudit=true\naudit-level=high\nregistry=https://registry.npmjs.org/\n`,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/package.json": `{"name":"x","packageManager":"npm@10.9.0"}`,
  };
  const findings = auditSettings(npmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "min-age.disabled")).toBe(true);
});

test("npm with no registry= emits registry.unpinned under standard", () => {
  const files: Record<string, string> = {
    "/p/.npmrc": `ignore-scripts=true\naudit=true\naudit-level=high\nmin-release-age=7\n`,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/package.json": `{"name":"x","packageManager":"npm@10.9.0"}`,
  };
  const findings = auditSettings(npmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "registry.unpinned")).toBe(true);
});

const CORP_REGISTRY = "https://npm.corp.example/";

const corpPolicy = () =>
  loadPolicy({ repoToml: `registry = "${CORP_REGISTRY}"\n` });

const registrySetValue = (
  findings: ReturnType<typeof auditSettings>,
  code: string,
  key: string
): unknown => {
  const edit = findings
    .find((f) => f.code === code)
    ?.fix?.edits.find((item) => item.op === "set" && item.key === key);
  return edit?.op === "set" ? edit.value : undefined;
};

test("npm unpinned apply writes the configured registry", () => {
  const files: Record<string, string> = {
    "/p/.npmrc": `ignore-scripts=true\naudit=true\naudit-level=high\nmin-release-age=7\n`,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/package.json": `{"name":"x","packageManager":"npm@10.9.0"}`,
  };
  const findings = auditSettings(npmProject("/p"), corpPolicy(), {
    readFile: (p) => files[p] ?? null,
  });
  expect(registrySetValue(findings, "registry.unpinned", "registry")).toBe(
    CORP_REGISTRY
  );
});

test("npm registry that differs from config emits registry.mismatch", () => {
  const files: Record<string, string> = {
    "/p/.npmrc": `ignore-scripts=true\nallow-scripts-pin=true\naudit=true\naudit-level=high\nmin-release-age=7\nregistry=https://registry.npmjs.org/\n`,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/package.json": `{"name":"x","packageManager":"npm@10.9.0"}`,
  };
  const findings = auditSettings(npmProject("/p"), corpPolicy(), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "registry.mismatch")).toBe(true);
  expect(registrySetValue(findings, "registry.mismatch", "registry")).toBe(
    CORP_REGISTRY
  );
});

test("npm registry matching config including trailing slash is quiet", () => {
  const files: Record<string, string> = {
    "/p/.npmrc": `ignore-scripts=true\nallow-scripts-pin=true\naudit=true\naudit-level=high\nmin-release-age=7\nregistry=https://npm.corp.example\n`,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/package.json": `{"name":"x","packageManager":"npm@10.9.0"}`,
  };
  const findings = auditSettings(npmProject("/p"), corpPolicy(), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "registry.mismatch")).toBe(false);
  expect(findings.some((f) => f.code === "registry.unpinned")).toBe(false);
});

test("npm with a company registry and no config registry is not a mismatch", () => {
  const files: Record<string, string> = {
    "/p/.npmrc": `ignore-scripts=true\nallow-scripts-pin=true\naudit=true\naudit-level=high\nmin-release-age=7\nregistry=${CORP_REGISTRY}\n`,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/package.json": `{"name":"x","packageManager":"npm@10.9.0"}`,
  };
  const findings = auditSettings(npmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "registry.mismatch")).toBe(false);
  expect(findings.some((f) => f.code === "registry.unpinned")).toBe(false);
});

test("npm with no packageManager field emits pm.unpinned under standard", () => {
  const files: Record<string, string> = {
    "/p/.npmrc": validNpmrc,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/package.json": `{"name":"x"}`,
  };
  const findings = auditSettings(npmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "pm.unpinned")).toBe(true);
});

const validPnpmWorkspace =
  "packages:\n  - '.'\nminimumReleaseAge: 1440\nonlyBuiltDependencies: []\naudit: true\naudit-level: high\nregistry: https://registry.npmjs.org/\n";

test("pnpm dangerouslyAllowAllBuilds true emits scripts.unrestricted under standard", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"pnpm@10.0.0"}`,
    "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "/p/pnpm-workspace.yaml":
      "packages:\n  - '.'\nminimumReleaseAge: 1440\naudit: true\naudit-level: high\nregistry: https://registry.npmjs.org/\ndangerouslyAllowAllBuilds: true\n",
  };
  const findings = auditSettings(pnpmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "scripts.unrestricted")).toBe(true);
});

test("pnpm missing pnpm-lock.yaml emits lockfile.missing under standard", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"pnpm@10.0.0"}`,
    "/p/pnpm-workspace.yaml": validPnpmWorkspace,
  };
  const findings = auditSettings(pnpmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "lockfile.missing")).toBe(true);
});

test("pnpm with audit disabled emits audit.disabled under standard", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"pnpm@10.0.0"}`,
    "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "/p/pnpm-workspace.yaml":
      "packages:\n  - '.'\nminimumReleaseAge: 1440\nonlyBuiltDependencies: []\nregistry: https://registry.npmjs.org/\n",
  };
  const findings = auditSettings(pnpmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "audit.disabled")).toBe(true);
});

test("pnpm with no registry emits registry.unpinned under standard", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"pnpm@10.0.0"}`,
    "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "/p/pnpm-workspace.yaml":
      "packages:\n  - '.'\nminimumReleaseAge: 1440\nonlyBuiltDependencies: []\naudit: true\naudit-level: high\n",
  };
  const findings = auditSettings(pnpmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "registry.unpinned")).toBe(true);
});

test("pnpm unpinned apply writes the configured registry", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"pnpm@10.0.0"}`,
    "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "/p/pnpm-workspace.yaml":
      "packages:\n  - '.'\nminimumReleaseAge: 1440\nonlyBuiltDependencies: []\naudit: true\naudit-level: high\n",
  };
  const findings = auditSettings(pnpmProject("/p"), corpPolicy(), {
    readFile: (p) => files[p] ?? null,
  });
  expect(registrySetValue(findings, "registry.unpinned", "registry")).toBe(
    CORP_REGISTRY
  );
});

test("pnpm registries.default that differs from config emits registry.mismatch", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"pnpm@10.0.0"}`,
    "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "/p/pnpm-workspace.yaml":
      "packages:\n  - '.'\nminimumReleaseAge: 1440\nonlyBuiltDependencies: []\naudit: true\naudit-level: high\nregistries:\n  default: https://registry.npmjs.org/\n",
  };
  const findings = auditSettings(pnpmProject("/p"), corpPolicy(), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "registry.mismatch")).toBe(true);
});

test("pnpm with no pnpm@ pin emits pm.unpinned under standard", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x"}`,
    "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "/p/pnpm-workspace.yaml": validPnpmWorkspace,
  };
  const findings = auditSettings(pnpmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "pm.unpinned")).toBe(true);
});

test("enabledManagers omitting pnpm skips pnpm settings findings but still reports leftover lockfile", () => {
  const project: Project = {
    gitRoot: "/p",
    managers: [
      {
        configPath: "/p/pnpm-workspace.yaml",
        lockfilePath: "/p/pnpm-lock.yaml",
        manifestPath: "/p/package.json",
        name: "pnpm",
        role: "primary",
      },
      {
        configPath: null,
        lockfilePath: "/p/package-lock.json",
        manifestPath: "/p/package.json",
        name: "npm",
        role: "leftover",
      },
    ],
    root: "/p",
  };
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x"}`,
    "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "/p/pnpm-workspace.yaml": "packages:\n  - '.'\n",
  };
  const policy = loadPolicy({
    scanToml: 'enabledManagers = ["npm", "yarn", "bun", "uv"]\n',
  });
  const findings = auditSettings(project, policy, {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "lockfile.leftover")).toBe(true);
  expect(findings.some((f) => f.manager === "pnpm")).toBe(false);
});

test("pip and pipenv primaries emit python.not-uv and are not fixable", () => {
  for (const name of ["pip", "pipenv"] as const) {
    const project: Project = {
      gitRoot: "/py",
      managers: [
        {
          configPath: null,
          lockfilePath: name === "pip" ? null : "/py/Pipfile.lock",
          manifestPath: name === "pip" ? "/py/requirements.txt" : "/py/Pipfile",
          name,
          role: "primary",
        },
      ],
      root: "/py",
    };
    const findings = auditSettings(project, loadPolicy({}), {
      readFile: () => null,
    });
    expect(findings).toEqual([
      expect.objectContaining({
        code: "python.not-uv",
        fixable: false,
        kind: "not-using-uv",
        manager: name,
        severity: "high",
      }),
    ]);
  }
});

const yarnProject = (root: string): Project => ({
  gitRoot: root,
  managers: [
    {
      configPath: `${root}/.yarnrc.yml`,
      lockfilePath: `${root}/yarn.lock`,
      manifestPath: `${root}/package.json`,
      name: "yarn",
      role: "primary",
    },
  ],
  root,
});

test("yarn berry missing yarn.lock emits lockfile.missing", () => {
  const files: Record<string, string> = {
    "/y/.yarnrc.yml": `enableScripts: false\nnpmRegistryServer: "https://registry.npmjs.org/"\n`,
    "/y/package.json": `{"name":"y","packageManager":"yarn@4.5.0"}`,
  };
  const project = yarnProject("/y");
  const [yarnManager] = project.managers;
  if (yarnManager === undefined) {
    throw new Error("expected yarn manager");
  }
  yarnManager.lockfilePath = "/y/yarn.lock";
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "lockfile.missing")).toBe(true);
});

test("yarn berry with npmAudit false emits audit.disabled", () => {
  const files: Record<string, string> = {
    "/y/.yarnrc.yml": `enableScripts: false\nnpmRegistryServer: "https://registry.npmjs.org/"\nnpmAudit: false\n`,
    "/y/package.json": `{"name":"y","packageManager":"yarn@4.5.0"}`,
    "/y/yarn.lock": "# yarn\n",
  };
  const findings = auditSettings(yarnProject("/y"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "audit.disabled")).toBe(true);
});

test("yarn berry without npmRegistryServer emits registry.unpinned", () => {
  const files: Record<string, string> = {
    "/y/.yarnrc.yml": `enableScripts: false\n`,
    "/y/package.json": `{"name":"y","packageManager":"yarn@4.5.0"}`,
    "/y/yarn.lock": "# yarn\n",
  };
  const findings = auditSettings(yarnProject("/y"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "registry.unpinned")).toBe(true);
});

test("yarn unpinned apply writes the configured registry", () => {
  const files: Record<string, string> = {
    "/y/.yarnrc.yml": `enableScripts: false\n`,
    "/y/package.json": `{"name":"y","packageManager":"yarn@4.5.0"}`,
    "/y/yarn.lock": "# yarn\n",
  };
  const findings = auditSettings(yarnProject("/y"), corpPolicy(), {
    readFile: (p) => files[p] ?? null,
  });
  expect(
    registrySetValue(findings, "registry.unpinned", "npmRegistryServer")
  ).toBe(CORP_REGISTRY);
});

test("yarn npmRegistryServer that differs from config emits registry.mismatch", () => {
  const files: Record<string, string> = {
    "/y/.yarnrc.yml": `enableScripts: false\nnpmRegistryServer: "https://registry.npmjs.org/"\n`,
    "/y/package.json": `{"name":"y","packageManager":"yarn@4.5.0"}`,
    "/y/yarn.lock": "# yarn\n",
  };
  const findings = auditSettings(yarnProject("/y"), corpPolicy(), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "registry.mismatch")).toBe(true);
});

test("bun without install.registry emits registry.unpinned", () => {
  const files: Record<string, string> = {
    "/p/bun.lock": `{"lockfileVersion":1}`,
    "/p/bunfig.toml": `trustedDependencies = ["foo"]\n`,
    "/p/package.json": `{"name":"x"}`,
  };
  const findings = auditSettings(bunProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "registry.unpinned")).toBe(true);
});

test("bun unpinned apply writes the configured registry", () => {
  const files: Record<string, string> = {
    "/p/bun.lock": `{"lockfileVersion":1}`,
    "/p/bunfig.toml": `trustedDependencies = ["foo"]\n`,
    "/p/package.json": `{"name":"x"}`,
  };
  const findings = auditSettings(bunProject("/p"), corpPolicy(), {
    readFile: (p) => files[p] ?? null,
  });
  expect(
    registrySetValue(findings, "registry.unpinned", "install.registry")
  ).toBe(CORP_REGISTRY);
});

test("bun install.registry.url that differs from config emits registry.mismatch", () => {
  const files: Record<string, string> = {
    "/p/bun.lock": `{"lockfileVersion":1}`,
    "/p/bunfig.toml": `trustedDependencies = ["foo"]\n\n[install.registry]\nurl = "https://registry.npmjs.org/"\n`,
    "/p/package.json": `{"name":"x"}`,
  };
  const findings = auditSettings(bunProject("/p"), corpPolicy(), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "registry.mismatch")).toBe(true);
});

test("leftover yarn bun and uv lockfiles are high and not fixable", () => {
  const project: Project = {
    gitRoot: "/p",
    managers: [
      {
        configPath: "/p/.npmrc",
        lockfilePath: "/p/package-lock.json",
        manifestPath: "/p/package.json",
        name: "npm",
        role: "primary",
      },
      {
        configPath: null,
        lockfilePath: "/p/yarn.lock",
        manifestPath: "/p/package.json",
        name: "yarn",
        role: "leftover",
      },
      {
        configPath: null,
        lockfilePath: "/p/bun.lock",
        manifestPath: "/p/package.json",
        name: "bun",
        role: "leftover",
      },
      {
        configPath: null,
        lockfilePath: "/p/uv.lock",
        manifestPath: "/p/pyproject.toml",
        name: "uv",
        role: "leftover",
      },
    ],
    root: "/p",
  };
  const files: Record<string, string> = {
    "/p/.npmrc": validNpmrc,
    "/p/bun.lock": "{}\n",
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/package.json": `{"name":"x","packageManager":"npm@10.9.0"}`,
    "/p/uv.lock": "version = 1\n",
    "/p/yarn.lock": "# yarn\n",
  };
  const leftovers = auditSettings(project, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  }).filter((f) => f.code === "lockfile.leftover");
  expect(leftovers).toEqual([
    expect.objectContaining({
      fixable: false,
      manager: "yarn",
      path: "/p/yarn.lock",
      severity: "high",
    }),
    expect.objectContaining({
      fixable: false,
      manager: "bun",
      path: "/p/bun.lock",
      severity: "high",
    }),
    expect.objectContaining({
      fixable: false,
      manager: "uv",
      path: "/p/uv.lock",
      severity: "high",
    }),
  ]);
});

test("malformed yarn packageManager pin is unpinned", () => {
  const project: Project = {
    gitRoot: "/y",
    managers: [
      {
        configPath: "/y/.yarnrc.yml",
        lockfilePath: "/y/yarn.lock",
        manifestPath: "/y/package.json",
        name: "yarn",
        role: "primary",
      },
    ],
    root: "/y",
  };
  const files: Record<string, string> = {
    "/y/.yarnrc.yml": `enableScripts: false\nnpmRegistryServer: "https://registry.npmjs.org/"\n`,
    "/y/package.json": `{"name":"y","packageManager":"yarn@4garbage"}`,
    "/y/yarn.lock": "# yarn lockfile v1\n",
  };
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "pm.unpinned")).toBe(true);
});

const bundlerProject = (root: string): Project => ({
  gitRoot: root,
  managers: [
    {
      configPath: `${root}/.bundle/config`,
      lockfilePath: `${root}/Gemfile.lock`,
      manifestPath: `${root}/Gemfile`,
      name: "bundler",
      role: "primary",
    },
  ],
  root,
});

test("bundler without BUNDLE_COOLDOWN emits min-age.disabled under standard", () => {
  const files: Record<string, string> = {
    "/r/Gemfile": 'source "https://rubygems.org"\n',
    "/r/Gemfile.lock": "GEM\n",
  };
  const findings = auditSettings(bundlerProject("/r"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "min-age.disabled")).toBe(true);
});

test("bundler BUNDLE_COOLDOWN below preset emits min-age.disabled", () => {
  const files: Record<string, string> = {
    "/r/.bundle/config": '---\nBUNDLE_COOLDOWN: "0"\n',
    "/r/Gemfile": 'source "https://rubygems.org"\n',
    "/r/Gemfile.lock": "GEM\n",
  };
  const findings = auditSettings(bundlerProject("/r"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "min-age.disabled")).toBe(true);
});

test("bundler BUNDLE_COOLDOWN meeting standard preset is quiet", () => {
  const files: Record<string, string> = {
    "/r/.bundle/config": '---\nBUNDLE_COOLDOWN: "1"\n',
    "/r/Gemfile": 'source "https://rubygems.org"\n',
    "/r/Gemfile.lock": "GEM\n",
  };
  const findings = auditSettings(bundlerProject("/r"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.filter((f) => f.kind === "settings")).toEqual([]);
});

test("npm scripts.unrestricted finding carries an npmrc ignore-scripts fix", () => {
  const files: Record<string, string> = {
    "/p/.npmrc": "registry=https://registry.npmjs.org/\n",
    "/p/package-lock.json": '{"lockfileVersion":3}',
    "/p/package.json": '{"name":"x"}',
  };
  const findings = auditSettings(npmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  const found = findings.find((f) => f.code === "scripts.unrestricted");
  expect(found?.fix).toEqual({
    edits: [{ key: "ignore-scripts", op: "set", value: true }],
    file: "/p/.npmrc",
    format: "npmrc",
  });
});

test("lockfile.missing and pm.unpinned stay fixless", () => {
  const files: Record<string, string> = {
    "/p/package.json": '{"name":"x"}',
  };
  const findings = auditSettings(npmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(
    findings.find((f) => f.code === "lockfile.missing")?.fix
  ).toBeUndefined();
  expect(findings.find((f) => f.code === "pm.unpinned")?.fix).toBeUndefined();
});

test("bundler min-age finding carries a BUNDLE_COOLDOWN fix in days", () => {
  const files: Record<string, string> = {
    "/r/Gemfile": 'source "https://rubygems.org"\n',
    "/r/Gemfile.lock": "GEM\n",
  };
  const findings = auditSettings(bundlerProject("/r"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  const found = findings.find((f) => f.code === "min-age.disabled");
  expect(found?.fix).toEqual({
    edits: [{ key: "BUNDLE_COOLDOWN", op: "set", value: "1" }],
    file: "/r/.bundle/config",
    format: "bundle-config",
  });
});

test("bundler without Gemfile.lock emits lockfile.missing", () => {
  const project: Project = {
    gitRoot: "/r",
    managers: [
      {
        configPath: null,
        lockfilePath: null,
        manifestPath: "/r/Gemfile",
        name: "bundler",
        role: "primary",
      },
    ],
    root: "/r",
  };
  const files: Record<string, string> = {
    "/r/Gemfile": 'source "https://rubygems.org"\n',
  };
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "lockfile.missing")).toBe(true);
});

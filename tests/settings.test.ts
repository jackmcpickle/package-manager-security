import { expect, test } from "bun:test";
import { auditSettings } from "../src/settings";
import { loadPolicy } from "../src/policy";
import type { Project } from "../src/domain";

function npmProject(root: string): Project {
  return {
    root,
    gitRoot: root,
    managers: [
      {
        name: "npm",
        role: "primary",
        manifestPath: `${root}/package.json`,
        lockfilePath: `${root}/package-lock.json`,
        configPath: `${root}/.npmrc`,
      },
    ],
  };
}

test("standard preset flags npm without ignore-scripts", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x"}`,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/.npmrc": `registry=https://registry.npmjs.org/\n`,
  };
  const findings = auditSettings(npmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "scripts.unrestricted")).toBe(true);
});

test("standard preset is quiet on ignore-scripts when set", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"npm@10.9.0"}`,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/.npmrc": `ignore-scripts=true\naudit=true\naudit-level=high\nmin-release-age=7\nregistry=https://registry.npmjs.org/\n`,
  };
  const findings = auditSettings(npmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.filter((f) => f.kind === "settings")).toEqual([]);
});

function pnpmProject(root: string): Project {
  return {
    root,
    gitRoot: root,
    managers: [
      {
        name: "pnpm",
        role: "primary",
        manifestPath: `${root}/package.json`,
        lockfilePath: `${root}/pnpm-lock.yaml`,
        configPath: `${root}/pnpm-workspace.yaml`,
      },
    ],
  };
}

test("pnpm bare minimumReleaseAge is minutes so 1440 fails the standard 7-day bar", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"pnpm@10.0.0"}`,
    "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "/p/pnpm-workspace.yaml":
      "packages:\n  - '.'\nminimumReleaseAge: 1440\nonlyBuiltDependencies: []\n",
  };
  const findings = auditSettings(pnpmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "min-age.disabled")).toBe(true);
});

test("pnpm bare minimumReleaseAge of 10080 minutes meets the standard 7-day bar", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"pnpm@10.0.0"}`,
    "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "/p/pnpm-workspace.yaml":
      "packages:\n  - '.'\nminimumReleaseAge: 10080\nonlyBuiltDependencies: []\n",
  };
  const findings = auditSettings(pnpmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "min-age.disabled")).toBe(false);
});

test("leftover npm lockfile is a leftover finding and is not fixable", () => {
  const project: Project = {
    root: "/p",
    gitRoot: "/p",
    managers: [
      {
        name: "pnpm",
        role: "primary",
        manifestPath: "/p/package.json",
        lockfilePath: "/p/pnpm-lock.yaml",
        configPath: "/p/pnpm-workspace.yaml",
      },
      {
        name: "npm",
        role: "leftover",
        manifestPath: "/p/package.json",
        lockfilePath: "/p/package-lock.json",
        configPath: null,
      },
    ],
  };
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"pnpm@10.0.0"}`,
    "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "/p/pnpm-workspace.yaml": "packages:\n  - '.'\nminimumReleaseAge: 10080\n",
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
    root: "/y",
    gitRoot: "/y",
    managers: [
      {
        name: "yarn",
        role: "unsupported",
        manifestPath: "/y/package.json",
        lockfilePath: "/y/yarn.lock",
        configPath: null,
      },
    ],
  };
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => (p.endsWith("package.json") ? `{"name":"y"}` : null),
  });
  expect(findings).toEqual([
    expect.objectContaining({
      code: "pm.unsupported",
      fixable: false,
      severity: "high",
      kind: "unsupported-pm",
    }),
  ]);
});

test("yarn berry without enableScripts false is unrestricted under standard", () => {
  const project: Project = {
    root: "/y",
    gitRoot: "/y",
    managers: [
      {
        name: "yarn",
        role: "primary",
        manifestPath: "/y/package.json",
        lockfilePath: "/y/yarn.lock",
        configPath: "/y/.yarnrc.yml",
      },
    ],
  };
  const files: Record<string, string> = {
    "/y/package.json": `{"name":"y","packageManager":"yarn@4.5.0"}`,
    "/y/yarn.lock": "# yarn lockfile v1\n",
    "/y/.yarnrc.yml": `nodeLinker: node-modules\n`,
  };
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "scripts.unrestricted")).toBe(true);
});

test("poetry primary emits python.not-uv and is not fixable", () => {
  const project: Project = {
    root: "/p",
    gitRoot: "/p",
    managers: [
      {
        name: "poetry",
        role: "primary",
        manifestPath: "/p/pyproject.toml",
        lockfilePath: "/p/poetry.lock",
        configPath: "/p/pyproject.toml",
      },
    ],
  };
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => (p.endsWith("pyproject.toml") ? `[tool.poetry]\nname = "x"\n` : null),
  });
  expect(findings).toEqual([
    expect.objectContaining({
      code: "python.not-uv",
      kind: "not-using-uv",
      severity: "high",
      fixable: false,
    }),
  ]);
});

function bunProject(root: string): Project {
  return {
    root,
    gitRoot: root,
    managers: [
      {
        name: "bun",
        role: "primary",
        manifestPath: `${root}/package.json`,
        lockfilePath: `${root}/bun.lock`,
        configPath: `${root}/bunfig.toml`,
      },
    ],
  };
}

function uvProject(root: string): Project {
  return {
    root,
    gitRoot: root,
    managers: [
      {
        name: "uv",
        role: "primary",
        manifestPath: `${root}/pyproject.toml`,
        lockfilePath: `${root}/uv.lock`,
        configPath: `${root}/pyproject.toml`,
      },
    ],
  };
}

test("bun primary with bare bunfig.toml has no trustedDependencies so scripts are unrestricted", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x"}`,
    "/p/bun.lock": `{"lockfileVersion":1}`,
    "/p/bunfig.toml": `[install]\nregistry = "https://registry.npmjs.org/"\n`,
  };
  const findings = auditSettings(bunProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "scripts.unrestricted")).toBe(true);
});

test("bun primary fully configured is quiet under standard", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x"}`,
    "/p/bun.lock": `{"lockfileVersion":1}`,
    "/p/bunfig.toml":
      `trustedDependencies = ["foo"]\n\n[install]\nregistry = "https://registry.npmjs.org/"\nminimumReleaseAge = 604800\n`,
  };
  const findings = auditSettings(bunProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.filter((f) => f.kind === "settings")).toEqual([]);
});

test("bun primary with no lockfile emits lockfile.missing", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x"}`,
    "/p/bunfig.toml":
      `trustedDependencies = ["foo"]\n\n[install]\nregistry = "https://registry.npmjs.org/"\n`,
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
    "/p/pyproject.toml": `[tool.uv]\nexclude-newer = 30\n`,
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

test("uv exclude-newer as an ISO date ~1 day ago emits min-age.disabled under standard", () => {
  const oneDayAgo = new Date(Date.now() - 1 * 86_400_000).toISOString();
  const files: Record<string, string> = {
    "/p/pyproject.toml": `[tool.uv]\nexclude-newer = "${oneDayAgo}"\n`,
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
    "/p/pyproject.toml":
      `[tool.uv]\nexclude-newer = 30\nextra-index-url = "https://extra.example/simple"\n`,
    "/p/uv.lock": `version = 1\n`,
  };
  const strictFindings = auditSettings(
    uvProject("/p"),
    loadPolicy({ flags: { preset: "strict" } }),
    { readFile: (p) => files[p] ?? null },
  );
  expect(strictFindings.some((f) => f.code === "registry.unpinned")).toBe(true);

  const standardFindings = auditSettings(uvProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(standardFindings.some((f) => f.code === "registry.unpinned")).toBe(false);
});

test("relaxed preset does not require ignore-scripts, min-release-age, or pm pin", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x"}`,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/.npmrc": `registry=https://registry.npmjs.org/\n`,
  };
  const findings = auditSettings(
    npmProject("/p"),
    loadPolicy({ flags: { preset: "relaxed" } }),
    { readFile: (p) => files[p] ?? null },
  );
  expect(findings.some((f) => f.code === "scripts.unrestricted")).toBe(false);
  expect(findings.some((f) => f.code === "min-age.disabled")).toBe(false);
  expect(findings.some((f) => f.code === "pm.unpinned")).toBe(false);
});

test("strict preset flags unpinned registry and pm as high, standard flags the same as info", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x"}`,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/.npmrc": `ignore-scripts=true\naudit=true\nmin-release-age=14\n`,
  };
  const strictFindings = auditSettings(
    npmProject("/p"),
    loadPolicy({ flags: { preset: "strict" } }),
    { readFile: (p) => files[p] ?? null },
  );
  expect(
    strictFindings.find((f) => f.code === "registry.unpinned")?.severity,
  ).toBe("high");
  expect(strictFindings.find((f) => f.code === "pm.unpinned")?.severity).toBe(
    "high",
  );

  const standardFindings = auditSettings(npmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(
    standardFindings.find((f) => f.code === "registry.unpinned")?.severity,
  ).toBe("info");
  expect(
    standardFindings.find((f) => f.code === "pm.unpinned")?.severity,
  ).toBe("info");
});

const validNpmrc =
  "ignore-scripts=true\naudit=true\naudit-level=high\nmin-release-age=7\nregistry=https://registry.npmjs.org/\n";

test("npm missing package-lock.json emits lockfile.missing under standard", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"npm@10.9.0"}`,
    "/p/.npmrc": validNpmrc,
  };
  const findings = auditSettings(npmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "lockfile.missing")).toBe(true);
});

test("npm .npmrc with no audit config emits audit.disabled under standard", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"npm@10.9.0"}`,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/.npmrc": `ignore-scripts=true\nmin-release-age=7\nregistry=https://registry.npmjs.org/\n`,
  };
  const findings = auditSettings(npmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "audit.disabled")).toBe(true);
});

test("npm with no min-release-age emits min-age.disabled under standard", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"npm@10.9.0"}`,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/.npmrc": `ignore-scripts=true\naudit=true\naudit-level=high\nregistry=https://registry.npmjs.org/\n`,
  };
  const findings = auditSettings(npmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "min-age.disabled")).toBe(true);
});

test("npm with no registry= emits registry.unpinned under standard", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"npm@10.9.0"}`,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/.npmrc": `ignore-scripts=true\naudit=true\naudit-level=high\nmin-release-age=7\n`,
  };
  const findings = auditSettings(npmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "registry.unpinned")).toBe(true);
});

test("npm with no packageManager field emits pm.unpinned under standard", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x"}`,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/.npmrc": validNpmrc,
  };
  const findings = auditSettings(npmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "pm.unpinned")).toBe(true);
});

const validPnpmWorkspace =
  "packages:\n  - '.'\nminimumReleaseAge: 10080\nonlyBuiltDependencies: []\naudit: true\naudit-level: high\nregistry: https://registry.npmjs.org/\n";

test("pnpm dangerouslyAllowAllBuilds true emits scripts.unrestricted under standard", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"pnpm@10.0.0"}`,
    "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "/p/pnpm-workspace.yaml":
      "packages:\n  - '.'\nminimumReleaseAge: 10080\naudit: true\naudit-level: high\nregistry: https://registry.npmjs.org/\ndangerouslyAllowAllBuilds: true\n",
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
      "packages:\n  - '.'\nminimumReleaseAge: 10080\nonlyBuiltDependencies: []\nregistry: https://registry.npmjs.org/\n",
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
      "packages:\n  - '.'\nminimumReleaseAge: 10080\nonlyBuiltDependencies: []\naudit: true\naudit-level: high\n",
  };
  const findings = auditSettings(pnpmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "registry.unpinned")).toBe(true);
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
    root: "/p",
    gitRoot: "/p",
    managers: [
      {
        name: "pnpm",
        role: "primary",
        manifestPath: "/p/package.json",
        lockfilePath: "/p/pnpm-lock.yaml",
        configPath: "/p/pnpm-workspace.yaml",
      },
      {
        name: "npm",
        role: "leftover",
        manifestPath: "/p/package.json",
        lockfilePath: "/p/package-lock.json",
        configPath: null,
      },
    ],
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
      root: "/py",
      gitRoot: "/py",
      managers: [
        {
          name,
          role: "primary",
          manifestPath: name === "pip" ? "/py/requirements.txt" : "/py/Pipfile",
          lockfilePath: name === "pip" ? null : "/py/Pipfile.lock",
          configPath: null,
        },
      ],
    };
    const findings = auditSettings(project, loadPolicy({}), { readFile: () => null });
    expect(findings).toEqual([
      expect.objectContaining({
        code: "python.not-uv",
        kind: "not-using-uv",
        severity: "high",
        fixable: false,
        manager: name,
      }),
    ]);
  }
});

function yarnProject(root: string): Project {
  return {
    root,
    gitRoot: root,
    managers: [
      {
        name: "yarn",
        role: "primary",
        manifestPath: `${root}/package.json`,
        lockfilePath: `${root}/yarn.lock`,
        configPath: `${root}/.yarnrc.yml`,
      },
    ],
  };
}

test("yarn berry missing yarn.lock emits lockfile.missing", () => {
  const files: Record<string, string> = {
    "/y/package.json": `{"name":"y","packageManager":"yarn@4.5.0"}`,
    "/y/.yarnrc.yml": `enableScripts: false\nnpmRegistryServer: "https://registry.npmjs.org/"\n`,
  };
  const project = yarnProject("/y");
  project.managers[0]!.lockfilePath = "/y/yarn.lock";
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "lockfile.missing")).toBe(true);
});

test("yarn berry with npmAudit false emits audit.disabled", () => {
  const files: Record<string, string> = {
    "/y/package.json": `{"name":"y","packageManager":"yarn@4.5.0"}`,
    "/y/yarn.lock": "# yarn\n",
    "/y/.yarnrc.yml":
      `enableScripts: false\nnpmRegistryServer: "https://registry.npmjs.org/"\nnpmAudit: false\n`,
  };
  const findings = auditSettings(yarnProject("/y"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "audit.disabled")).toBe(true);
});

test("yarn berry without npmRegistryServer emits registry.unpinned", () => {
  const files: Record<string, string> = {
    "/y/package.json": `{"name":"y","packageManager":"yarn@4.5.0"}`,
    "/y/yarn.lock": "# yarn\n",
    "/y/.yarnrc.yml": `enableScripts: false\n`,
  };
  const findings = auditSettings(yarnProject("/y"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "registry.unpinned")).toBe(true);
});

test("bun without install.registry emits registry.unpinned", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x"}`,
    "/p/bun.lock": `{"lockfileVersion":1}`,
    "/p/bunfig.toml": `trustedDependencies = ["foo"]\n`,
  };
  const findings = auditSettings(bunProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "registry.unpinned")).toBe(true);
});

test("leftover yarn bun and uv lockfiles are high and not fixable", () => {
  const project: Project = {
    root: "/p",
    gitRoot: "/p",
    managers: [
      {
        name: "npm",
        role: "primary",
        manifestPath: "/p/package.json",
        lockfilePath: "/p/package-lock.json",
        configPath: "/p/.npmrc",
      },
      {
        name: "yarn",
        role: "leftover",
        manifestPath: "/p/package.json",
        lockfilePath: "/p/yarn.lock",
        configPath: null,
      },
      {
        name: "bun",
        role: "leftover",
        manifestPath: "/p/package.json",
        lockfilePath: "/p/bun.lock",
        configPath: null,
      },
      {
        name: "uv",
        role: "leftover",
        manifestPath: "/p/pyproject.toml",
        lockfilePath: "/p/uv.lock",
        configPath: null,
      },
    ],
  };
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"npm@10.9.0"}`,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/.npmrc": validNpmrc,
    "/p/yarn.lock": "# yarn\n",
    "/p/bun.lock": "{}\n",
    "/p/uv.lock": "version = 1\n",
  };
  const leftovers = auditSettings(project, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  }).filter((f) => f.code === "lockfile.leftover");
  expect(leftovers).toEqual([
    expect.objectContaining({ manager: "yarn", severity: "high", fixable: false, path: "/p/yarn.lock" }),
    expect.objectContaining({ manager: "bun", severity: "high", fixable: false, path: "/p/bun.lock" }),
    expect.objectContaining({ manager: "uv", severity: "high", fixable: false, path: "/p/uv.lock" }),
  ]);
});

test("malformed yarn packageManager pin is unpinned", () => {
  const project: Project = {
    root: "/y",
    gitRoot: "/y",
    managers: [
      {
        name: "yarn",
        role: "primary",
        manifestPath: "/y/package.json",
        lockfilePath: "/y/yarn.lock",
        configPath: "/y/.yarnrc.yml",
      },
    ],
  };
  const files: Record<string, string> = {
    "/y/package.json": `{"name":"y","packageManager":"yarn@4garbage"}`,
    "/y/yarn.lock": "# yarn lockfile v1\n",
    "/y/.yarnrc.yml": `enableScripts: false\nnpmRegistryServer: "https://registry.npmjs.org/"\n`,
  };
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "pm.unpinned")).toBe(true);
});

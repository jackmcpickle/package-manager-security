import { expect, test } from "bun:test";

import { auditAdvisories } from "../src/advisories";
import { applySettings } from "../src/apply-settings";
import { discoverProjects } from "../src/discover";
import type { Policy, Project } from "../src/domain";
import { createMemoryCache } from "../src/memory-cache";
import { loadPolicy } from "../src/policy";
import { auditSettings } from "../src/settings";
import { memoryFs } from "./helpers/memory-fs";

const composerProject = (
  configPath: string | null = "/p/composer.json"
): Project => ({
  gitRoot: "/p",
  managers: [
    {
      configPath,
      lockfilePath: "/p/composer.lock",
      manifestPath: "/p/composer.json",
      name: "composer",
      role: "primary",
    },
  ],
  root: "/p",
});

const json = (value: unknown): string => `${JSON.stringify(value, null, 4)}\n`;

const composerJson = (config: Record<string, unknown> = {}): string =>
  json({
    config,
    name: "acme/app",
    require: {},
  });

const composerBase = (): Record<string, string> => ({
  "/p/composer.json": composerJson(),
  "/p/composer.lock": '{"packages":[]}\n',
});

const composerFiles = (
  config: Record<string, unknown>
): Record<string, string> => ({
  ...composerBase(),
  "/p/composer.json": composerJson(config),
});

const codes = (
  files: Record<string, string>,
  policy: Policy = loadPolicy({}),
  configPath: string | null = "/p/composer.json"
): string[] =>
  auditSettings(composerProject(configPath), policy, {
    readFile: (p) => files[p] ?? null,
  }).map((f) => f.code);

const apply = (
  files: Record<string, string>,
  policy: Policy = loadPolicy({}),
  configPath: string | null = "/p/composer.json"
) => {
  const project = composerProject(configPath);
  const findings = auditSettings(project, policy, {
    readFile: (p) => files[p] ?? null,
  });
  const result = applySettings(project, findings, policy, {
    commit: false,
    force: false,
    gitStatus: () => "clean",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, body) => {
      files[p] = body;
    },
  });
  return { files, result };
};

// --- audit: baseline --------------------------------------------------------

test("composer defaults are quiet under the standard preset", () => {
  expect(codes(composerBase())).toEqual([]);
});

test("composer does not emit min-age.disabled", () => {
  expect(codes(composerBase())).not.toContain("min-age.disabled");
});

// --- audit: allow-plugins ---------------------------------------------------

test("composer allow-plugins true emits scripts.unrestricted under standard", () => {
  expect(codes(composerFiles({ "allow-plugins": true }))).toContain(
    "scripts.unrestricted"
  );
});

test("composer allow-plugins allowlist or false is quiet", () => {
  expect(
    codes(
      composerFiles({
        "allow-plugins": { "phpstan/extension-installer": true },
      })
    )
  ).toEqual([]);
  expect(codes(composerFiles({ "allow-plugins": false }))).toEqual([]);
});

test("composer allow-plugins true is quiet under relaxed", () => {
  const relaxed = loadPolicy({ flags: { preset: "relaxed" } });
  expect(codes(composerFiles({ "allow-plugins": true }), relaxed)).toEqual([]);
});

// --- audit: transport -------------------------------------------------------

test("composer disable-tls true emits registry.unpinned", () => {
  expect(codes(composerFiles({ "disable-tls": true }))).toContain(
    "registry.unpinned"
  );
});

test("composer secure-http false emits registry.unpinned", () => {
  expect(codes(composerFiles({ "secure-http": false }))).toContain(
    "registry.unpinned"
  );
});

test("composer http repository is an unfixable registry.unpinned finding", () => {
  const files = {
    "/p/composer.json": json({
      name: "acme/app",
      repositories: [{ type: "composer", url: "http://packagist.example" }],
      require: {},
    }),
    "/p/composer.lock": '{"packages":[]}\n',
  };
  const findings = auditSettings(composerProject(), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  const finding = findings.find((f) => f.code === "registry.unpinned");
  expect(finding?.fixable).toBe(false);
  expect(finding?.severity).toBe("info");
});

test("composer http repository is high under strict", () => {
  const files = {
    "/p/composer.json": json({
      name: "acme/app",
      repositories: [{ type: "composer", url: "http://packagist.example" }],
      require: {},
    }),
    "/p/composer.lock": '{"packages":[]}\n',
  };
  const findings = auditSettings(
    composerProject(),
    loadPolicy({ flags: { preset: "strict" } }),
    { readFile: (p) => files[p] ?? null }
  );
  expect(findings.find((f) => f.code === "registry.unpinned")?.severity).toBe(
    "high"
  );
});

// --- audit: policy ----------------------------------------------------------

test("composer policy false emits audit.disabled", () => {
  expect(codes(composerFiles({ policy: false }))).toContain("audit.disabled");
});

test("composer policy.advisories.audit ignore emits audit.disabled", () => {
  expect(
    codes(composerFiles({ policy: { advisories: { audit: "ignore" } } }))
  ).toContain("audit.disabled");
});

test("composer policy.advisories.block false emits audit.blocking-disabled", () => {
  expect(
    codes(composerFiles({ policy: { advisories: { block: false } } }))
  ).toContain("audit.blocking-disabled");
});

test("composer legacy audit.block-insecure false emits audit.blocking-disabled", () => {
  expect(
    codes(composerFiles({ audit: { "block-insecure": false } }))
  ).toContain("audit.blocking-disabled");
});

test("composer policy.advisories supersedes legacy audit.block-insecure", () => {
  expect(
    codes(
      composerFiles({
        audit: { "block-insecure": false },
        policy: { advisories: { block: true } },
      })
    )
  ).toEqual([]);
});

test("composer policy.malware.block false emits audit.malware-disabled", () => {
  expect(
    codes(composerFiles({ policy: { malware: { block: false } } }))
  ).toContain("audit.malware-disabled");
});

// --- audit: source-fallback + lockfile -------------------------------------

test("composer source-fallback true is info under standard and high under strict", () => {
  const files = composerFiles({ "source-fallback": true });
  const standard = auditSettings(composerProject(), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  }).find((f) => f.code === "source-fallback.enabled");
  expect(standard?.severity).toBe("info");
  expect(standard?.fixable).toBe(true);

  const strict = auditSettings(
    composerProject(),
    loadPolicy({ flags: { preset: "strict" } }),
    { readFile: (p) => files[p] ?? null }
  ).find((f) => f.code === "source-fallback.enabled");
  expect(strict?.severity).toBe("high");
});

test("composer without composer.lock emits lockfile.missing", () => {
  expect(codes({ "/p/composer.json": composerJson() })).toContain(
    "lockfile.missing"
  );
});

test("composer falls back to composer.json when no configPath was detected", () => {
  const findings = auditSettings(composerProject(null), loadPolicy({}), {
    readFile: (p) => composerFiles({ "allow-plugins": true })[p] ?? null,
  });
  expect(findings.find((f) => f.code === "scripts.unrestricted")?.path).toBe(
    "/p/composer.json"
  );
});

// --- apply ------------------------------------------------------------------

test("apply writes allow-plugins false into composer.json", () => {
  const { files, result } = apply(composerFiles({ "allow-plugins": true }));
  expect(result.skipped).toBeNull();
  expect(result.written).toContain("/p/composer.json");
  expect(
    JSON.parse(files["/p/composer.json"] as string).config["allow-plugins"]
  ).toBe(false);
});

test("apply restores TLS and drops disable-tls", () => {
  const { files } = apply(
    composerFiles({ "disable-tls": true, "secure-http": false })
  );
  const config = JSON.parse(files["/p/composer.json"] as string)
    .config as Record<string, unknown>;
  expect(config["disable-tls"]).toBeUndefined();
  expect(config["secure-http"]).toBe(true);
});

test("apply restores policy after policy false", () => {
  const { files } = apply(composerFiles({ policy: false }));
  expect(JSON.parse(files["/p/composer.json"] as string).config.policy).toEqual(
    {
      advisories: { audit: "fail", block: true },
      malware: { block: true },
    }
  );
});

test("apply does not rewrite http repositories", () => {
  const files = {
    "/p/composer.json": json({
      name: "acme/app",
      repositories: [{ type: "composer", url: "http://packagist.example" }],
      require: {},
    }),
    "/p/composer.lock": '{"packages":[]}\n',
  };
  const { result } = apply(files);
  expect(result.written).toEqual([]);
  expect(JSON.parse(files["/p/composer.json"] as string).repositories).toEqual([
    { type: "composer", url: "http://packagist.example" },
  ]);
});

test("apply preserves unrelated composer.json keys", () => {
  const files = {
    "/p/composer.json": json({
      config: { "allow-plugins": true, "sort-packages": true },
      name: "acme/app",
      require: { php: "^8.3" },
    }),
    "/p/composer.lock": '{"packages":[]}\n',
  };
  const { files: next } = apply(files);
  const parsed = JSON.parse(next["/p/composer.json"] as string) as {
    config: Record<string, unknown>;
    require: Record<string, string>;
  };
  expect(parsed.config["sort-packages"]).toBe(true);
  expect(parsed.require).toEqual({ php: "^8.3" });
  expect(parsed.config["allow-plugins"]).toBe(false);
});

test("apply leaves malformed composer.json untouched", () => {
  const files = {
    "/p/composer.json": "{",
    "/p/composer.lock": '{"packages":[]}\n',
  };
  const { result } = apply(files);
  expect(result.written).toEqual([]);
  expect(files["/p/composer.json"]).toBe("{");
});

test("apply never writes a lockfile for composer lockfile.missing", () => {
  const files = { "/p/composer.json": composerJson() };
  const { result } = apply(files);
  expect(result.written).toEqual([]);
  expect(files["/p/composer.lock"]).toBeUndefined();
});

test("apply is idempotent for composer", () => {
  const files = composerFiles({ "allow-plugins": true });
  apply(files);
  const first = files["/p/composer.json"];
  apply(files);
  expect(files["/p/composer.json"]).toBe(first as string);
});

test("apply disables source-fallback", () => {
  const { files } = apply(composerFiles({ "source-fallback": true }));
  expect(
    JSON.parse(files["/p/composer.json"] as string).config["source-fallback"]
  ).toBe(false);
});

// --- discover ---------------------------------------------------------------

test("composer.json is a primary composer manager", () => {
  const projects = discoverProjects(
    "/php",
    memoryFs({
      "/php/composer.json": '{"name":"acme/app"}',
      "/php/composer.lock": '{"packages":[]}',
    })
  );
  expect(projects[0]?.managers).toEqual([
    {
      configPath: "/php/composer.json",
      lockfilePath: "/php/composer.lock",
      manifestPath: "/php/composer.json",
      name: "composer",
      role: "primary",
    },
  ]);
});

test("composer.json without a lockfile still detects composer", () => {
  const projects = discoverProjects(
    "/php",
    memoryFs({ "/php/composer.json": '{"name":"acme/app"}' })
  );
  const composer = projects[0]?.managers.find((m) => m.name === "composer");
  expect(composer?.role).toBe("primary");
  expect(composer?.lockfilePath).toBeNull();
});

test("stray composer.lock beside npm without composer.json is leftover composer", () => {
  const projects = discoverProjects(
    "/app",
    memoryFs({
      "/app/composer.lock": '{"packages":[]}',
      "/app/package-lock.json": '{"lockfileVersion":3}',
      "/app/package.json": '{"name":"app","packageManager":"npm@10.9.0"}',
    })
  );
  expect(
    projects[0]?.managers.some(
      (m) => m.name === "composer" && m.role === "leftover"
    )
  ).toBe(true);
  expect(
    projects[0]?.managers.some(
      (m) => m.name === "composer" && m.role === "primary"
    )
  ).toBe(false);
});

test("composer coexists with a JS primary in the same root", () => {
  const projects = discoverProjects(
    "/app",
    memoryFs({
      "/app/composer.json": '{"name":"acme/app"}',
      "/app/composer.lock": '{"packages":[]}',
      "/app/package-lock.json": '{"lockfileVersion":3}',
      "/app/package.json": '{"name":"app","packageManager":"npm@10.9.0"}',
    })
  );
  const names = projects[0]?.managers
    .filter((m) => m.role === "primary")
    .map((m) => m.name)
    .toSorted();
  expect(names).toEqual(["composer", "npm"]);
});

test("nested composer.json is a separate PM root", () => {
  const projects = discoverProjects(
    "/mono",
    memoryFs(
      {
        "/mono/composer.json": '{"name":"acme/root"}',
        "/mono/composer.lock": '{"packages":[]}',
        "/mono/packages/api/composer.json": '{"name":"acme/api"}',
      },
      ["/mono/.git"]
    )
  );
  const roots = projects.map((p) => p.root).toSorted();
  expect(roots).toEqual(["/mono", "/mono/packages/api"]);
});

test("vendor directories are not walked for composer projects", () => {
  const projects = discoverProjects(
    "/php",
    memoryFs({
      "/php/composer.json": '{"name":"acme/app"}',
      "/php/vendor/foo/bar/composer.json": '{"name":"foo/bar"}',
    })
  );
  expect(projects.map((p) => p.root)).toEqual(["/php"]);
});

// --- advisories -------------------------------------------------------------

const advisoryProject: Project = {
  gitRoot: "/php",
  managers: [
    {
      configPath: "/php/composer.json",
      lockfilePath: "/php/composer.lock",
      manifestPath: "/php/composer.json",
      name: "composer",
      role: "primary",
    },
  ],
  root: "/php",
};

const runComposerAudit = (
  slot: string,
  stdout: string,
  code = 1
): ReturnType<typeof auditAdvisories> =>
  auditAdvisories(advisoryProject, loadPolicy({}), {
    cache: createMemoryCache(() => 1000, 86_400_000),
    digest: () => `composer-${slot}`,
    now: () => 1000,
    readFile: () => "lock",
    run: (argv, cwd) => {
      expect(argv).toEqual([
        "composer",
        "audit",
        "--format",
        "json",
        "--locked",
      ]);
      expect(cwd).toBe("/php");
      return Promise.resolve({ code, stderr: "", stdout });
    },
  });

test("composer audit parses an array of advisories", async () => {
  const result = await runComposerAudit(
    "array",
    JSON.stringify({
      abandoned: {},
      advisories: {
        "symfony/process": [
          {
            advisoryId: "PKSA-wws7-mr54-jsny",
            packageName: "symfony/process",
            severity: "high",
            title: "Command injection",
          },
        ],
      },
    })
  );
  const advisory = result.findings.find((f) => f.kind === "advisory");
  expect(advisory?.code).toBe("PKSA-wws7-mr54-jsny");
  expect(advisory?.package).toBe("symfony/process");
  expect(advisory?.severity).toBe("high");
  expect(advisory?.currentVersion).toBeUndefined();
  expect(advisory?.fixVersion).toBeUndefined();
});

test("composer audit parses a sparse object of advisories", async () => {
  const result = await runComposerAudit(
    "sparse",
    JSON.stringify({
      advisories: {
        "symfony/http-foundation": {
          "0": {
            advisoryId: "PKSA-aaaa-bbbb-cccc",
            cve: "CVE-2024-1234",
            packageName: "symfony/http-foundation",
            severity: "medium",
            title: "Header injection",
          },
          "3": {
            advisoryId: "PKSA-dddd-eeee-ffff",
            packageName: "symfony/http-foundation",
            severity: "critical",
            title: "RCE",
          },
        },
      },
    })
  );
  const advisories = result.findings
    .filter((f) => f.kind === "advisory")
    .map((f) => `${f.code}:${f.severity}`)
    .toSorted();
  expect(advisories).toEqual([
    "PKSA-aaaa-bbbb-cccc:moderate",
    "PKSA-dddd-eeee-ffff:critical",
  ]);
});

test("composer audit abandoned packages become deprecated findings", async () => {
  const result = await runComposerAudit(
    "abandoned",
    JSON.stringify({
      abandoned: { "vendor/old": "vendor/new" },
      advisories: {},
    }),
    1
  );
  const abandoned = result.findings.find((f) => f.kind === "deprecated");
  expect(abandoned?.package).toBe("vendor/old");
  expect(abandoned?.code).toBe("advisory.abandoned");
});

test("composer audit with no advisories yields no advisory findings", async () => {
  const result = await runComposerAudit(
    "clean",
    JSON.stringify({ abandoned: {}, advisories: {} }),
    0
  );
  expect(result.findings.filter((f) => f.kind === "advisory")).toEqual([]);
});

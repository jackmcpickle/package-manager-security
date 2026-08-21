import { afterAll, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { auditAdvisories } from "../src/advisories";
import { applySettings } from "../src/apply-settings";
import { createFsCache } from "../src/cache";
import { discoverProjects } from "../src/discover";
import type { Policy, Project } from "../src/domain";
import { loadPolicy } from "../src/policy";
import { auditSettings } from "../src/settings";
import { memoryFs } from "./helpers/memory-fs";

const cacheRoot = mkdtempSync(path.join(tmpdir(), "mailclad-test-cargo-"));

afterAll(() => {
  rmSync(cacheRoot, { force: true, recursive: true });
});

const cargoProject = (
  configPath: string | null = "/p/.cargo/config.toml"
): Project => ({
  gitRoot: "/p",
  managers: [
    {
      configPath,
      lockfilePath: "/p/Cargo.lock",
      manifestPath: "/p/Cargo.toml",
      name: "cargo",
      role: "primary",
    },
  ],
  root: "/p",
});

const cargoBase = (): Record<string, string> => ({
  "/p/Cargo.lock": "# cargo\n",
  "/p/Cargo.toml": '[package]\nname = "x"\nversion = "0.1.0"\n',
});

const cargoFiles = (config: string): Record<string, string> => ({
  ...cargoBase(),
  "/p/.cargo/config.toml": config,
});

const codes = (
  files: Record<string, string>,
  policy: Policy = loadPolicy({}),
  configPath: string | null = "/p/.cargo/config.toml"
): string[] =>
  auditSettings(cargoProject(configPath), policy, {
    readFile: (p) => files[p] ?? null,
  }).map((f) => f.code);

const apply = (
  files: Record<string, string>,
  policy: Policy = loadPolicy({}),
  configPath: string | null = "/p/.cargo/config.toml"
) => {
  const project = cargoProject(configPath);
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

// --- audit: config resolution ----------------------------------------------

test("cargo reads the legacy .cargo/config when config.toml is absent", () => {
  const files = {
    ...cargoBase(),
    "/p/.cargo/config": '[install]\nminimum-release-age = "1d"\n',
  };
  expect(codes(files, loadPolicy({}), "/p/.cargo/config")).toEqual([]);
});

test("cargo prefers .cargo/config.toml over the legacy .cargo/config", () => {
  const files = {
    ...cargoBase(),
    "/p/.cargo/config": '[install]\nminimum-release-age = "30d"\n',
    "/p/.cargo/config.toml": "[install]\n",
  };
  expect(codes(files)).toContain("min-age.disabled");
});

test("cargo falls back to .cargo/config.toml when no configPath was detected", () => {
  const findings = auditSettings(cargoProject(null), loadPolicy({}), {
    readFile: (p) => cargoBase()[p] ?? null,
  });
  const minAge = findings.find((f) => f.code === "min-age.disabled");
  expect(minAge?.path).toBe("/p/.cargo/config.toml");
});

test("cargo treats a malformed config.toml as no settings rather than throwing", () => {
  expect(codes(cargoFiles("[install\nnot toml"))).toContain("min-age.disabled");
});

test("cargo ignores a non-table install key", () => {
  expect(codes(cargoFiles('install = "nope"\n'))).toContain("min-age.disabled");
});

// --- audit: minimum-release-age --------------------------------------------

test("cargo minimum-release-age accepts duration strings", () => {
  expect(codes(cargoFiles('[install]\nminimum-release-age = "1d"\n'))).toEqual(
    []
  );
  expect(
    codes(cargoFiles('[install]\nminimum-release-age = "1 week"\n'))
  ).toEqual([]);
});

test("cargo minimum-release-age below the preset emits min-age.disabled", () => {
  expect(
    codes(cargoFiles('[install]\nminimum-release-age = "12h"\n'))
  ).toContain("min-age.disabled");
});

test("cargo minimum-release-age of an unparseable string emits min-age.disabled", () => {
  expect(
    codes(cargoFiles('[install]\nminimum-release-age = "soon"\n'))
  ).toContain("min-age.disabled");
});

test("cargo reads a bare minimum-release-age number as minutes", () => {
  // 10080 minutes is 7 days, which clears the standard 1-day gate.
  expect(codes(cargoFiles("[install]\nminimum-release-age = 10080\n"))).toEqual(
    []
  );
  expect(codes(cargoFiles("[install]\nminimum-release-age = 10\n"))).toContain(
    "min-age.disabled"
  );
});

test("cargo min-age is not checked under the relaxed preset", () => {
  const relaxed = loadPolicy({ flags: { preset: "relaxed" } });
  expect(codes(cargoBase(), relaxed)).toEqual([]);
});

test("cargo min-age uses the strict preset's 14-day threshold", () => {
  const strict = loadPolicy({ flags: { preset: "strict" } });
  expect(
    codes(cargoFiles('[install]\nminimum-release-age = "1d"\n'), strict)
  ).toContain("min-age.disabled");
  expect(
    codes(cargoFiles('[install]\nminimum-release-age = "2w"\n'), strict)
  ).toEqual([]);
});

// --- audit: lockfile --------------------------------------------------------

test("cargo without Cargo.lock emits lockfile.missing", () => {
  const files = {
    "/p/.cargo/config.toml": '[install]\nminimum-release-age = "1d"\n',
    "/p/Cargo.toml": '[package]\nname = "x"\nversion = "0.1.0"\n',
  };
  expect(codes(files)).toContain("lockfile.missing");
});

// --- apply ------------------------------------------------------------------

test("apply writes cargo minimum-release-age as days under the standard preset", () => {
  const { files, result } = apply(cargoBase());
  expect(result.skipped).toBeNull();
  expect(result.written).toContain("/p/.cargo/config.toml");
  expect(files["/p/.cargo/config.toml"]).toContain(
    'minimum-release-age = "1d"'
  );
});

test("apply writes cargo minimum-release-age as whole weeks when divisible by 7", () => {
  const strict = loadPolicy({ flags: { preset: "strict" } });
  const { files } = apply(cargoBase(), strict);
  expect(files["/p/.cargo/config.toml"]).toContain(
    'minimum-release-age = "2w"'
  );
});

test("apply preserves unrelated cargo config tables", () => {
  const { files } = apply(
    cargoFiles(
      '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[net]\nretry = 3\n'
    )
  );
  expect(files["/p/.cargo/config.toml"]).toContain("vendored-sources");
  expect(files["/p/.cargo/config.toml"]).toContain("retry = 3");
  expect(files["/p/.cargo/config.toml"]).toContain(
    'minimum-release-age = "1d"'
  );
});

test("apply leaves a malformed cargo config.toml untouched", () => {
  const raw = "[install\nnot toml";
  const { files, result } = apply(cargoFiles(raw));
  expect(files["/p/.cargo/config.toml"]).toBe(raw);
  expect(result.written).toEqual([]);
});

test("apply never writes a lockfile for cargo lockfile.missing", () => {
  const files: Record<string, string> = {
    "/p/.cargo/config.toml": '[install]\nminimum-release-age = "1d"\n',
    "/p/Cargo.toml": '[package]\nname = "x"\nversion = "0.1.0"\n',
  };
  const { result } = apply(files);
  expect(result.written).toEqual([]);
  expect(files["/p/Cargo.lock"]).toBeUndefined();
});

test("apply is idempotent for cargo", () => {
  const files = cargoBase();
  apply(files);
  const first = files["/p/.cargo/config.toml"];
  apply(files);
  expect(files["/p/.cargo/config.toml"]).toBe(first as string);
});

// --- discover ---------------------------------------------------------------

test("a cargo workspace member is its own package-manager root", () => {
  const projects = discoverProjects(
    "/ws",
    memoryFs({
      "/ws/Cargo.lock": "# cargo\n",
      "/ws/Cargo.toml": '[workspace]\nmembers = ["crates/a"]\n',
      "/ws/crates/a/Cargo.toml": '[package]\nname = "a"\nversion = "0.1.0"\n',
    })
  );
  const roots = projects.map((p) => p.root).toSorted();
  expect(roots).toEqual(["/ws", "/ws/crates/a"]);
});

test("Cargo.toml without a lockfile still detects cargo with a null lockfilePath", () => {
  const projects = discoverProjects(
    "/rust",
    memoryFs({
      "/rust/Cargo.toml": '[package]\nname = "rust"\nversion = "0.1.0"\n',
    })
  );
  const cargo = projects[0]?.managers.find((m) => m.name === "cargo");
  expect(cargo?.role).toBe("primary");
  expect(cargo?.lockfilePath).toBeNull();
});

test("a stray Cargo.lock with no JS primary is still a primary cargo manager", () => {
  const projects = discoverProjects(
    "/rust",
    memoryFs({ "/rust/Cargo.lock": "# cargo\n" })
  );
  const cargo = projects[0]?.managers.find((m) => m.name === "cargo");
  expect(cargo?.role).toBe("primary");
});

// --- advisories -------------------------------------------------------------

const advisoryProject: Project = {
  gitRoot: "/rs",
  managers: [
    {
      configPath: "/rs/.cargo/config.toml",
      lockfilePath: "/rs/Cargo.lock",
      manifestPath: "/rs/Cargo.toml",
      name: "cargo",
      role: "primary",
    },
  ],
  root: "/rs",
};

const runCargoAudit = (
  slot: string,
  stdout: string,
  code = 1
): ReturnType<typeof auditAdvisories> =>
  auditAdvisories(advisoryProject, loadPolicy({}), {
    cache: createFsCache(path.join(cacheRoot, slot), () => 1000, 86_400_000),
    digest: () => `cargo-${slot}`,
    now: () => 1000,
    readFile: () => "lock",
    run: () => Promise.resolve({ code, stderr: "", stdout }),
  });

test("cargo audit reports the patched version as fixVersion", async () => {
  const result = await runCargoAudit(
    "fix",
    JSON.stringify({
      vulnerabilities: {
        list: [
          {
            advisory: {
              id: "RUSTSEC-2024-0002",
              patched_versions: [">= 1.0.5"],
              severity: "critical",
              title: "openssl critical advisory",
            },
            package: { name: "openssl", version: "1.0.0" },
          },
        ],
      },
    })
  );
  const advisory = result.findings.find((f) => f.kind === "advisory");
  expect(advisory?.severity).toBe("critical");
  expect(advisory?.currentVersion).toBe("1.0.0");
  expect(advisory?.fixVersion).toBe("1.0.5");
});

test("cargo audit with an empty vulnerability list yields no advisory findings", async () => {
  const result = await runCargoAudit(
    "clean",
    JSON.stringify({ vulnerabilities: { count: 0, list: [] } }),
    0
  );
  expect(result.findings.filter((f) => f.kind === "advisory")).toEqual([]);
});

test("cargo audit output with no concrete version leaves currentVersion unset", async () => {
  const result = await runCargoAudit(
    "unknown",
    JSON.stringify({
      vulnerabilities: {
        list: [
          {
            advisory: { id: "RUSTSEC-2024-0003", severity: "high" },
            package: { name: "tokio" },
          },
        ],
      },
    })
  );
  const advisory = result.findings.find((f) => f.kind === "advisory");
  expect(advisory?.package).toBe("tokio");
  expect(advisory?.currentVersion).toBeUndefined();
});

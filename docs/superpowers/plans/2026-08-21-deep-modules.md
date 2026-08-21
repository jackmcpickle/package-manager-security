# Deep Modules Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restructure pmguard so each package manager has one deep module, fixes travel with findings, and every I/O seam has two adapters — without changing any observable CLI behavior.

**Architecture:** Eight sequential refactor tasks. Task 1 creates `src/managers/` profiles that absorb the nine per-manager tables. Task 2 makes findings carry their own config edits so `apply-settings` becomes a generic editor. Tasks 3–4 give advisories a memory cache adapter and a pure parse module. Task 5 concentrates policy layering in `policy.ts`. Task 6 shrinks `auditPath`'s interface to a mode union. Task 7 collects all real-world I/O into one Host adapter. Task 8 gives `domain.ts` behavior and deletes duplicated helpers.

**Tech Stack:** Bun ≥ 1.2, TypeScript, `smol-toml`, `bun test`, ultracite (oxlint/oxfmt).

**Spec:** The architecture review report (candidates 1–8). This plan is self-contained; the report's evidence is restated per task. Line numbers in the report predate commit `7c47f48` (composer) — locate code by symbol name, never by line number.

## Global Constraints

- **Behavior-preserving.** CLI output, exit codes, written config file contents, cache file format, and report formats must not change. If a task would change observable behavior, stop and report BLOCKED.
- All existing tests stay green: `bun test` from repo root, expect **379+ pass, 0 fail**. Existing tests may be edited only mechanically (imports, moved symbols, injected deps) — never weaken an assertion.
- Before every commit run: `bun x ultracite fix && bun run typecheck && bun test`. All three must pass.
- No new npm dependencies. No barrel files (index files that only re-export).
- Only adapter modules may import `node:fs`, `node:crypto`, or use `Bun.*` globals. Each task states which files those are; by end of Task 7 the full list is: `src/bun-host.ts`, `src/cache.ts` (fs adapter), `src/main.ts`, `scripts/*`.
- Conventional commit messages (`refactor: …`, `test: …`). One commit per task minimum; more is fine.
- Managers are exactly: `npm pnpm yarn bun uv cargo composer bundler poetry pip pipenv`. `poetry`/`pip`/`pipenv` are "python-legacy": flagged, never fixed, advisories via OSV only.
- Do not "fix" the two known product gaps in passing (bundler advisories unfixable; OSV runner returns `[]` in production). Preserve them; they are separate product decisions.
- Do NOT touch `.coverage-baseline` until Task 8, which refreshes it once at the end.

---

### Task 1: Manager profiles — one module per package manager

**Files:**
- Create: `src/managers/profile.ts` (the `ManagerProfile` interface + `profileFor` + `CONFIG_MANAGER_NAMES`)
- Create: `src/managers/npm.ts`, `src/managers/pnpm.ts`, `src/managers/yarn.ts`, `src/managers/bun.ts`, `src/managers/uv.ts`, `src/managers/cargo.ts`, `src/managers/composer.ts`, `src/managers/bundler.ts`, `src/managers/poetry.ts`, `src/managers/pip.ts`, `src/managers/pipenv.ts`
- Modify: `src/policy.ts`, `src/preflight.ts`, `src/advisories.ts`, `src/apply-advisories.ts`, `src/apply-settings.ts`, `src/settings.ts`, `src/discover.ts`
- Test: `tests/managers.test.ts` (new), existing suite unchanged

**Interfaces:**
- Consumes: `PackageManager` from `src/domain.ts`.
- Produces (later tasks rely on these exact names):

```ts
// src/managers/profile.ts
import type { PackageManager } from "../domain";

export interface ManagerProfile {
  readonly name: PackageManager;
  /** "config" = auditable+fixable; "python-legacy" = flagged only (poetry/pip/pipenv) */
  readonly kind: "config" | "python-legacy";
  /** binary preflight checks for; null when none required (poetry/pip/pipenv, bundler uses bundle-audit) */
  readonly binary: string | null;
  /** native audit command; null → OSV path */
  readonly auditArgv: readonly string[] | null;
  /** argv to upgrade one package; null = advisories not auto-fixable for this manager */
  readonly upgradeArgv: ((pkg: string, fixVersion: string) => string[]) | null;
  /** lockfile basenames in priority order, e.g. ["bun.lock", "bun.lockb"] */
  readonly lockfileNames: readonly string[];
  /** default config file path(s) relative to project root, in read-priority order,
      e.g. npm [".npmrc"], cargo [".cargo/config.toml", ".cargo/config"], uv ["uv.toml", "pyproject.toml"] */
  readonly configNames: readonly string[];
  /** the config file apply-settings writes, relative to root; null = not writable via profile default */
  readonly writeConfigName: string | null;
}

export const profileFor: (name: PackageManager) => ManagerProfile;
/** the 8 config-kind manager names, in the order of today's DEFAULT_ENABLED_MANAGERS */
export const CONFIG_MANAGER_NAMES: readonly PackageManager[];
```

Each `src/managers/<name>.ts` exports `const <name>Profile: ManagerProfile`. `profile.ts` imports all eleven into a `Record<PackageManager, ManagerProfile>` (a registry with an accessor is not a barrel file). Populate values by *moving* today's table entries verbatim:

| source table | destination field |
|---|---|
| `REQUIRED_BINARIES` (`src/preflight.ts`) | `binary` |
| `AUDIT_COMMANDS` + `LIVE_MANAGERS`/`OSV_MANAGERS` (`src/advisories.ts`) | `auditArgv` (null for OSV managers) |
| `upgradeArgv` switch + `NON_UV_PYTHON` (`src/apply-advisories.ts`) | `upgradeArgv`, `kind` |
| `DEFAULT_ENABLED_MANAGERS` / `CONFIG_MANAGERS` / `PACKAGE_MANAGERS` (`src/policy.ts`) | `CONFIG_MANAGER_NAMES` + `kind` |
| `PYTHON_LEGACY_MANAGERS` (`src/settings.ts`) | `kind === "python-legacy"` |
| `LOCAL_CONFIG_FILE` + `uvConfigPath` + cargo fallback (`src/apply-settings.ts`) | `writeConfigName`, `configNames` |
| per-auditor config/lockfile fallback strings in `src/settings.ts` (e.g. `".npmrc"`, `"pnpm-lock.yaml"`, the bun `bun.lock`/`bun.lockb` pair, `readCargoConfig`'s two paths, `readUvConfig`'s two paths) | `configNames`, `lockfileNames` |
| `cargoConfigPath` / `uvDetectedConfigPath` / `bunLockfilePath` name lists in `src/discover.ts` | `configNames`, `lockfileNames` |

Notes:
- bundler: `binary: "bundle-audit"`, `upgradeArgv: null` (keep today's gap — leave a one-line comment `// bundler advisories have no auto-upgrade yet`), `writeConfigName: ".bundle/config"`.
- uv `configNames: ["uv.toml", "pyproject.toml"]` — the *semantics* ("pyproject counts only with a `[tool.uv]` table") stay where they live today; only the name strings move to the profile.
- Out of scope: `discover.ts`'s directory-walk logic, `ROOT_PM_FILES`, `NESTED_CONFIGS`, `NESTED_PM_MARKER_FILES` (those tables key detection *heuristics*, not manager identity). Replace only the literal name strings that duplicate profile data (cargo/uv/bun paths above) with reads from `profileFor`.

- [ ] **Step 1: Write `tests/managers.test.ts` first** — assertions that pin the moved data so the migration can't drift:

```ts
import { describe, expect, it } from "bun:test";
import { CONFIG_MANAGER_NAMES, profileFor } from "../src/managers/profile";

describe("manager profiles", () => {
  it("keeps the config manager set stable", () => {
    expect([...CONFIG_MANAGER_NAMES].sort()).toEqual(
      ["bun", "bundler", "cargo", "composer", "npm", "pnpm", "uv", "yarn"].sort()
    );
  });
  it("marks python legacy managers as non-config", () => {
    for (const name of ["poetry", "pip", "pipenv"] as const) {
      const p = profileFor(name);
      expect(p.kind).toBe("python-legacy");
      expect(p.auditArgv).toBeNull();
      expect(p.upgradeArgv).toBeNull();
    }
  });
  it("keeps audit argvs byte-identical to the old table", () => {
    expect(profileFor("yarn").auditArgv).toEqual(["yarn", "npm", "audit", "--json"]);
    expect(profileFor("uv").auditArgv).toEqual(["uv", "audit", "--output-format", "json", "--frozen"]);
    expect(profileFor("composer").auditArgv).toEqual(["composer", "audit", "--format", "json", "--locked"]);
    expect(profileFor("bundler").auditArgv).toEqual(["bundle-audit", "check", "--format", "json"]);
  });
  it("keeps upgrade argvs identical", () => {
    expect(profileFor("npm").upgradeArgv?.("left-pad", "1.3.0")).toEqual(["npm", "install", "left-pad@1.3.0", "--save-exact"]);
    expect(profileFor("pnpm").upgradeArgv?.("left-pad", "1.3.0")).toEqual(["pnpm", "add", "left-pad@1.3.0"]);
    expect(profileFor("uv").upgradeArgv?.("requests", "2.0.0")).toEqual(["uv", "lock", "--upgrade-package", "requests"]);
    expect(profileFor("bundler").upgradeArgv).toBeNull();
  });
  it("keeps lockfile and config names", () => {
    expect(profileFor("bun").lockfileNames).toEqual(["bun.lock", "bun.lockb"]);
    expect(profileFor("cargo").configNames).toEqual([".cargo/config.toml", ".cargo/config"]);
    expect(profileFor("uv").configNames).toEqual(["uv.toml", "pyproject.toml"]);
    expect(profileFor("pnpm").writeConfigName).toBe("pnpm-workspace.yaml");
  });
});
```

Before writing the profiles, read the current tables and copy every entry **verbatim** — the test above pins only samples; the migration itself must move all eleven managers' data. Where the test's expectation disagrees with what the code actually contains today, the code wins: fix the test to match reality and note it in your report.

- [ ] **Step 2:** Run `bun test tests/managers.test.ts` — expect FAIL (module not found).
- [ ] **Step 3:** Create the 11 profile files + `profile.ts`. Run the new test — PASS.
- [ ] **Step 4:** Migrate consumers one file at a time, running `bun test` after each: `preflight.ts`, `advisories.ts`, `apply-advisories.ts`, `policy.ts`, `apply-settings.ts`, `settings.ts`, `discover.ts`. Delete each superseded table as its last reader moves. Grep at the end: `grep -rn "REQUIRED_BINARIES\|AUDIT_COMMANDS\|LIVE_MANAGERS\|NON_UV_PYTHON\|PYTHON_LEGACY_MANAGERS\|LOCAL_CONFIG_FILE\|DEFAULT_ENABLED_MANAGERS" src/` must return nothing.
- [ ] **Step 5:** `bun x ultracite fix && bun run typecheck && bun test` — all green.
- [ ] **Step 6:** Commit: `refactor: move per-manager knowledge into src/managers profiles`

---

### Task 2: Findings carry their fix

**Files:**
- Modify: `src/domain.ts` (add `ConfigEdit`, `SettingsFix`, `Finding.fix?`)
- Modify: `src/settings.ts` (auditors attach `fix` when emitting fixable settings findings)
- Modify: `src/apply-settings.ts` (becomes a generic editor over formats; deletes per-manager knowledge)
- Test: `tests/settings.test.ts`, `tests/settings-modern.test.ts`, `tests/apply-settings.test.ts` (extend, don't weaken)

**Interfaces:**
- Consumes: `profileFor` from Task 1 (units + `writeConfigName`).
- Produces:

```ts
// src/domain.ts additions
export type ConfigEditValue = string | number | boolean | readonly string[];
export type ConfigEdit =
  | { op: "set"; key: string; value: ConfigEditValue }   // key is a dotted path, e.g. "install.minimum-release-age"
  | { op: "unset"; key: string };
export type ConfigFormat = "npmrc" | "yaml" | "toml" | "bundle-config";
export interface SettingsFix {
  file: string;          // absolute path of the config file to edit
  format: ConfigFormat;
  edits: readonly ConfigEdit[];
}
// on Finding:
fix?: SettingsFix;
```

Rules:
1. In `settings.ts`, every finding that today has `fixable: true` **and** is written by `apply-settings` gains a `fix`. The auditor computes the concrete value — including the unit conversion (pnpm minutes, yarn minutes, bun seconds, uv duration string, cargo duration string, bundler days) — at emit time. `lockfile.missing` and `pm.unpinned` stay fixless (that is what `isSettingsFix` excludes today; the exclusion list dies with it).
2. Migration-style fixes are expressed as edit lists: the pnpm legacy-build-key migration becomes `unset` edits for each legacy key + one `set` for `allowBuilds`; emit `unset` edits only for keys actually present in the parsed config.
3. `apply-settings.ts` keeps its interface (`applySettingsGroup`, `applySettings`, `ApplyResult`, `ApplySettingsDeps`, `ApplySettingsItem`) but its implementation becomes: group `finding.fix` by `fix.file`, apply edits with one editor per `ConfigFormat`, write. The editors are refactored from today's `mergeNpmrc` / `mergePnpmYaml` / `mergeYarnYaml` / `mergeBunfig` / `mergeCargo` / `mergeBundleConfig` — keep their serialization quirks (comment preservation in npmrc, the hand-rolled YAML emitter, `.bundle/config` mirror keys) so written bytes don't change.
4. After the change, `apply-settings.ts` must contain **no** `PackageManager` name literals and no unit conversions. Grep check: `grep -n "pnpm\|yarn\|bunfig\|cargo\|24 \* 60\|60 \* 60" src/apply-settings.ts` → only hits allowed are in comments or the format editor filenames.
5. The duplicated predicates (`bunRegistryPinned`/`hasDefaultRegistry`, `resolveSettings` copy, `isBlanket`) die on the apply side; the audit side is the single owner.

- [ ] **Step 1:** Add the domain types; typecheck.
- [ ] **Step 2:** Write new tests first, in `tests/apply-settings.test.ts`: for each format, one test that a synthetic `Finding` with a `fix` produces exactly the same file content the current suite already asserts for the equivalent real finding. Also one test: a finding without `fix` is never written.
- [ ] **Step 3:** In `settings.ts`, attach fixes manager by manager (npm → pnpm → yarn → bun → uv → cargo → bundler), running the settings + apply-settings suites after each manager.
- [ ] **Step 4:** Rewrite `apply-settings.ts` internals to consume `fix` only. The existing `apply-settings.test.ts` fixtures assert exact written file contents — they are the byte-equality net; they must pass unmodified except for constructing findings via `auditSettings` (preferred) or adding `fix` fields to hand-built findings.
- [ ] **Step 5:** Delete dead code (`configPathFor`, `isSettingsFix`, per-manager `apply*` helpers, duplicated predicates). Full gate: `bun x ultracite fix && bun run typecheck && bun test`.
- [ ] **Step 6:** Commit: `refactor: findings carry their config fix; apply-settings becomes a generic editor`

---

### Task 3: Memory cache adapter

**Files:**
- Create: `src/memory-cache.ts`
- Modify: none in `src/` beyond that (the `Cache` interface in `src/cache.ts` already exists)
- Test: `tests/cache.test.ts` (add memory adapter tests); migrate temp-dir usage in `tests/advisories.test.ts`, `tests/apply-advisories.test.ts`, `tests/cli.test.ts`, `tests/cargo.test.ts`, `tests/bundler.test.ts`, `tests/composer.test.ts` (whichever of these create `mkdtempSync` cache dirs)

**Interfaces:**
- Consumes: `Cache`, `AdvisoryResult`, `PackageAdvisory` from `src/cache.ts`.
- Produces: `export const createMemoryCache: (now?: () => number, ttlMs?: number) => Cache` — defaults `now = Date.now`, `ttlMs = CACHE_TTL_MS`.

Complete implementation:

```ts
// src/memory-cache.ts
import { type AdvisoryResult, CACHE_TTL_MS, type Cache, type PackageAdvisory } from "./cache";

interface Envelope<T> {
  storedAt: number;
  value: T;
}

export const createMemoryCache = (
  now: () => number = Date.now,
  ttlMs: number = CACHE_TTL_MS
): Cache => {
  const lockfiles = new Map<string, Envelope<AdvisoryResult>>();
  const packages = new Map<string, Envelope<PackageAdvisory[]>>();

  const fresh = <T>(envelope: Envelope<T> | undefined): T | null =>
    envelope && now() - envelope.storedAt < ttlMs ? envelope.value : null;

  return {
    getLockfile: (digest) => fresh(lockfiles.get(digest)),
    getPackage: (name, version) => fresh(packages.get(`${name}@${version}`)),
    putLockfile: (digest, result) => {
      lockfiles.set(digest, { storedAt: now(), value: result });
    },
    putPackage: (name, version, rows) => {
      packages.set(`${name}@${version}`, { storedAt: now(), value: rows });
    },
  };
};
```

- [ ] **Step 1:** Write tests in `tests/cache.test.ts`: round-trip lockfile, round-trip package, TTL expiry (inject a fake `now` that jumps past `ttlMs`), miss returns null. Run — FAIL.
- [ ] **Step 2:** Add `src/memory-cache.ts`. Run — PASS.
- [ ] **Step 3:** In each test file that `mkdtempSync`s a cache dir purely to satisfy `auditAdvisories`/`auditPath`, replace `createFsCache(tmpdir, …)` with `createMemoryCache(...)` and delete the now-unused temp dirs and their `afterAll` cleanup. Keep the fs-cache round-trip tests in `cache.test.ts` on real temp dirs — they test the fs adapter itself. Keep any test that asserts on-disk cache files (e.g. the `tests/fixtures/empty-home` seeded caches) on the fs adapter.
- [ ] **Step 4:** Full gate: `bun x ultracite fix && bun run typecheck && bun test`.
- [ ] **Step 5:** Commit: `refactor: add in-memory Cache adapter and drop temp-dir scaffolding from tests`

---

### Task 4: Pure advisory-report parse module

**Files:**
- Create: `src/advisory-report.ts`
- Modify: `src/advisories.ts` (keeps orchestration: manager split, cache, subprocess, OSV; delegates parsing)
- Test: `tests/advisory-report.test.ts` (new, direct fixture tests), `tests/advisories.test.ts` (unchanged behavior)

**Interfaces:**
- Consumes: `Finding`, `PackageManager` from domain; `PackageAdvisory` from cache.
- Produces:

```ts
// src/advisory-report.ts
export interface ParsedAuditReport {
  findings: Finding[];
  packages: PackageAdvisory[];
}
/** Normalize one manager's `… audit --json` stdout. Returns null when stdout is not parseable as that manager's report shape. */
export const parseAuditOutput: (
  manager: PackageManager,
  stdout: string,
  lockPath: string
) => ParsedAuditReport | null;
```

Move the private normalizers out of `advisories.ts` — locate by name: `walkYarnTree`, `walkViaEntries`, `walkVulnEntries`, `walkFindingEntries`, `mapAuditJson`, plus whatever helpers only they use (follow the call graph; take a helper along only when the orchestrator no longer references it). `advisories.ts` calls `parseAuditOutput` where it called `mapAuditJson` before. If the current signatures need extra inputs (severity mapping, kind overrides), fold them into the module — they are parse concerns. Exact stdout→Finding output must be unchanged; the existing `tests/advisories.test.ts` (plus cargo/bundler/composer suites) is the regression net and must pass untouched.

- [ ] **Step 1:** Write `tests/advisory-report.test.ts` first: for each shape — npm `advisories`, npm `vulnerabilities`, pnpm, yarn ndjson tree, bun, uv, cargo `vulns`, bundle-audit `results`, composer — feed a small representative JSON string directly to `parseAuditOutput` and assert the normalized findings (package, severity, kind, id). Lift the sample JSON from the fake-`run` stdout strings already embedded in `tests/advisories.test.ts` / `tests/cargo.test.ts` / `tests/bundler.test.ts` / `tests/composer.test.ts` so expectations are known-good. Include one malformed-JSON case asserting `null`.
- [ ] **Step 2:** Run — FAIL (module not found).
- [ ] **Step 3:** Create the module by moving code; wire `advisories.ts` to it. Run new + old advisory suites — PASS.
- [ ] **Step 4:** Full gate: `bun x ultracite fix && bun run typecheck && bun test`.
- [ ] **Step 5:** Commit: `refactor: extract pure advisory-report parser with direct fixture tests`

---

### Task 5: policy.ts owns all layering

**Files:**
- Modify: `src/policy.ts` (add `PolicyLayers`, `ResolvedSettings`, `resolveSettings`; `loadPolicy` stays)
- Modify: `src/audit.ts` (delete `overlayRepoPolicy`, `mergePerManager`, `parseRepoKeys`; keep layers, call `loadPolicy` with all four)
- Modify: `src/cli.ts` (pass layers to `auditPath` instead of pre-merged policy + duplicate preset flag)
- Modify: `src/settings.ts`, `src/apply-settings.ts` (import the single `resolveSettings`)
- Test: `tests/policy.test.ts` (extend), existing `tests/audit`-related coverage via `tests/cli.test.ts` and fixture `tests/fixtures/audit/flag-wins` (precedence net — must pass unchanged)

**Interfaces:**
- Produces:

```ts
// src/policy.ts additions
export interface PolicyLayers {
  userToml?: string;
  scanToml?: string;
  flags?: { preset?: PresetName; overrides?: Record<string, unknown> };
}
/** Full stack for one repo: user < scan < repo < flags. One parse, one merge. */
export const policyForRepo: (layers: PolicyLayers, repoToml?: string) => Policy;

export interface ResolvedSettings {
  auditLevel: Severity;
  ignoreScripts: boolean;
  minReleaseAgeDays: number;
  requireLockfile: boolean;
  requirePmPin: boolean;
}
export const resolveSettings: (policy: Policy, manager: PackageManager) => ResolvedSettings;
```

- `policyForRepo` is `loadPolicy({ ...layers, repoToml })` — flags reapplied last is already `loadPolicy`'s behavior, which is exactly the re-assertion `overlayRepoPolicy` hand-rolls today.
- `resolveSettings` is today's private `resolveSettings` in `settings.ts` promoted to `policy.ts`; the 2-field copy in `apply-settings.ts` (if it survived Task 2) dies. Preserve today's exact fallback semantics (`typeof` guards falling back to `PRESET_DEFAULTS[preset]`).
- `AuditPathInput` gains `layers: PolicyLayers` and loses `policy` + `flags`. `auditPath` computes the per-project policy as `policyForRepo(layers, repoTomlIfPresent)`. The top-level policy (for `enabledManagers` and gate when no repo file exists) is `policyForRepo(layers)`.
- Precedence net: the fixture test `tests/fixtures/audit/flag-wins` asserts flag-beats-repo-TOML today. It must pass unmodified. Add to `tests/policy.test.ts`: repo beats scan beats user for `preset` and for a per-manager table key; flags beat repo.

- [ ] **Step 1:** Write the new `policy.test.ts` cases against `policyForRepo` — FAIL.
- [ ] **Step 2:** Implement `policyForRepo` + promote `resolveSettings`. New tests PASS.
- [ ] **Step 3:** Migrate `audit.ts` (delete the three helpers; grep `overlayRepoPolicy\|mergePerManager\|parseRepoKeys` → nothing), then `cli.ts`, then the two `resolveSettings` call sites. Full suite after each file.
- [ ] **Step 4:** Full gate: `bun x ultracite fix && bun run typecheck && bun test`.
- [ ] **Step 5:** Commit: `refactor: single policy layering path via policyForRepo and shared resolveSettings`

---

### Task 6: auditPath mode union

**Files:**
- Modify: `src/audit.ts`, `src/cli.ts`
- Test: `tests/cli.test.ts`, `tests/apply-settings.test.ts` coverage of apply paths (must pass; extend with type-level impossibility notes only if trivial)

**Interfaces:**
- Produces (replacing the flag soup in `AuditPathInput`):

```ts
// src/audit.ts
export interface WriteDeps {
  writeFile: (path: string, content: string) => void;
  gitStatus: (root: string) => string;
  gitCommit?: (root: string, message: string) => void;
  force: boolean;
  commit: boolean;
}
export type AuditMode =
  | { kind: "audit" }
  | { kind: "apply"; settings: boolean; advisories: boolean; allowMajors: boolean; write: WriteDeps }
  | { kind: "interactive"; prompt: ApplyPrompt; allowMajors: boolean; write: WriteDeps };
```

- `AuditPathInput` loses `apply`, `applyAdvisories`, `interactive`, `force`, `commit`, `allowMajors` and the corresponding optional members of `deps` (`writeFile`, `gitStatus`, `gitCommit`, `prompt`); it gains `mode: AuditMode`. A write capability now cannot be absent when a writing mode is chosen — the silent no-ops (`apply: true` without `writeFile`; `interactive: true` without `prompt`) become type errors.
- `cli.ts` builds the mode from parsed flags in one place; flag *parsing* is unchanged, and invalid CLI combinations behave exactly as today (derive the mode with the same precedence the current booleans produce: interactive wins over batch apply; `--apply` and `--apply-advisories` may both be set).
- Inside `audit.ts`, the apply phase returns `{ appliedRoots: Set<string>; skippedDirty: string[] }` instead of threading two mutable sets through six functions as out-params. Locate by name: `applyChoice`, `applyProjectSettings`, `applyProjectAdvisories`, `applyOneSettingsGroup`, `applyGroupedSettings`, `applyAllAdvisories`. The settings-before-advisories ordering and the `appliedRoots` dirty-tree compensation must be preserved — keep the explanatory comment next to it.
- Behavior net: `tests/cli.test.ts` covers apply, apply-advisories, interactive, dirty-tree skip, and force paths; all must pass with mechanical construction changes only (tests build `mode` instead of booleans).

- [ ] **Step 1:** Introduce `AuditMode` alongside the old fields; make `auditPath` consume the mode internally, derived from old fields — suite green.
- [ ] **Step 2:** Flip `cli.ts` and every test to construct `mode`; delete the old fields. Typecheck is the enforcement (`bun run typecheck`).
- [ ] **Step 3:** Convert the out-param sets to return values, function by function, suite after each.
- [ ] **Step 4:** Full gate: `bun x ultracite fix && bun run typecheck && bun test`.
- [ ] **Step 5:** Commit: `refactor: auditPath takes a mode union; apply phase returns its results`

---

### Task 7: One Host adapter for the real world

**Files:**
- Create: `src/host.ts` (interface + types only), `src/bun-host.ts` (the only file with `Bun.*` / `node:fs` / `node:crypto` besides `src/cache.ts` and `src/main.ts`)
- Modify: `src/main.ts` (builds the Bun host, passes it to `run`), `src/cli.ts` (all `default*` fns move to `bun-host.ts`; `run(argv, host)`), `src/discover.ts`, `src/settings.ts` (drop their `node:fs` defaults; deps become required), `src/audit.ts` (digest comes from host)
- Test: `tests/helpers/memory-fs.ts` grows a `fakeHost` builder; all suites migrate mechanically
- Test: `tests/cli.test.ts` gains one test for `resolveColor` honoring the host's `isTTY` (the current bug-adjacent behavior: color decision must come from the injected host, not `process.stdout`)

**Interfaces:**

```ts
// src/host.ts
export interface HostFiles {
  readFile: (path: string) => string | null;
  writeFile: (path: string, content: string) => void;
  readDir: (path: string) => string[];
  isDir: (path: string) => boolean;
}
export interface Host {
  files: HostFiles;
  run: AuditRun;                                  // subprocess exec
  which: (binary: string) => string | null;
  gitStatus: (root: string) => string;
  gitCommit: (root: string, message: string) => void;
  readStdinChunk: () => Promise<string | null>;
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  isTTY: boolean;
  env: Record<string, string | undefined>;
  cwd: () => string;
  now: () => number;
  digest: (bytes: string) => string;
  createCache: (dir: string) => Cache;
}
```

- `src/bun-host.ts` exports `createBunHost(): Host` assembled from today's `default*` implementations (`defaultRun`, `defaultWhich`, `defaultGitStatus`, `defaultGitCommit`, `createBunStdinChunkReader`, fs defaults from `discover.ts`/`settings.ts`/`cli.ts`, `defaultDigest` from `audit.ts`, `createFsCache`). Move, don't rewrite.
- `run(argv: string[], host: Host)` replaces `run(argv, deps?)`. Tests construct a fake host once via a helper in `tests/helpers/memory-fs.ts`:

```ts
export const fakeHost = (overrides: Partial<Host> & { fsMap?: Record<string, string> }): Host => { /* memoryFs-backed defaults, createMemoryCache, run/which throwing "not stubbed" unless overridden */ };
```

- `discoverProjects` / `auditSettings` keep their current parameter shapes (they already accept injected fns) but their hard-wired `?? default` fs fallbacks are deleted; callers (audit.ts, fed from the host) always pass them. `DiscoverFs`/`SettingsFs` members become required.
- `resolveColor` decides from `host.isTTY` + env only. Preserve today's *observable* CLI default (auto color on TTY, `--no-color`/`NO_COLOR` respected — check the current logic and keep flags' precedence identical); the "injected stdout disables color" coupling dies, which existing tests already route around via the explicit color dep.
- `defaultRunOsv` stays a stub returning `[]` (product gap, preserved) but moves to `bun-host.ts`.
- Grep gate at the end: `grep -rn "node:fs\|Bun\." src/ | grep -v "bun-host\|cache.ts\|main.ts"` → only type-only or comment hits allowed; `Bun.YAML.parse` call sites in `settings.ts`/`apply-settings.ts` are exempt (runtime YAML parser, not I/O — leave them).

- [ ] **Step 1:** Create `host.ts` + `bun-host.ts` by moving defaults; `main.ts` builds the host. Suite green (nothing else changed yet).
- [ ] **Step 2:** Change `run` to `(argv, host)`; add `fakeHost` helper; migrate `tests/cli.test.ts` mechanically. Suite after each block of tests.
- [ ] **Step 3:** Delete fs defaults from `discover.ts`/`settings.ts`; make members required; fix fallout callers/tests.
- [ ] **Step 4:** Rewire `resolveColor`; add its test.
- [ ] **Step 5:** Grep gate above; full gate: `bun x ultracite fix && bun run typecheck && bun test`.
- [ ] **Step 6:** Commit: `refactor: single Host adapter owns all real-world I/O`

---

### Task 8: Behavior into domain.ts, delete duplicated helpers, refresh coverage baseline

**Files:**
- Modify: `src/domain.ts` (add `SEVERITY_RANK`-backed `severityAtLeast`, `isAdvisoryKind`, `gitRootOf`)
- Create: `src/std.ts` (`isPlainObject`, `hasText`, `mapSerial`, `isStar`) — plain utility module, not a barrel
- Create: `src/version.ts` (`compareVersions` moved from `apply-advisories.ts`, exported)
- Modify: every file holding a duplicate: `settings.ts`, `audit.ts`, `report.ts`, `apply-advisories.ts`, `apply-settings.ts`, `advisories.ts`, `policy.ts`, `discover.ts`, `composer-config.ts`
- Test: `tests/version.test.ts` (new, direct `compareVersions` cases), `tests/coverage-check.test.ts` untouched
- Modify: `.coverage-baseline` via `bun run coverage:write` (final step only)

**Interfaces:**
- Produces:

```ts
// src/domain.ts additions
export const severityAtLeast: (a: Severity, b: Severity) => boolean; // rank(a) >= rank(b), critical highest
export const isAdvisoryKind: (kind: FindingKind) => boolean;         // advisory | deprecated | quarantine
export const gitRootOf: (project: Project) => string;                // gitRoot ?? root

// src/version.ts
export const compareVersions: (a: string, b: string) => number;      // moved verbatim, incl. its private helpers

// src/std.ts
export const isPlainObject: (v: unknown) => v is Record<string, unknown>;
export const hasText: (v: unknown) => v is string;                    // match today's settings.ts semantics exactly
export const mapSerial: <T, R>(items: T[], fn: (item: T) => Promise<R>) => Promise<R[]>; // match the existing copies' signature
export const isStar: (v: string) => boolean;                          // the /^\*+$/u wildcard test
```

Duplicates to delete (locate each by name, replace with the shared import):
- `AUDIT_RANK` (`settings.ts`) and `SEVERITY_RANK` (`audit.ts`) → one table behind `severityAtLeast`; keep whichever comparison direction each call site needs.
- `ADVISORY_KINDS` (`report.ts`, `apply-advisories.ts`) and the hand-rolled `isAdvisoryKind` variants in `audit.ts`.
- `isPlainObject` × 7, `mapSerial` × 3, `hasText` × 2, `isStar`/`isBlanket`.
- `projectGitRoot` in `audit.ts` and the inlined `project.gitRoot ?? project.root` expressions in `audit.ts` and `report.ts` → `gitRootOf`.
- Inline the seven single-use comparator predicates into `compareVersions`' module as private helpers (they move with it; do not inline into one giant expression — moving the file is enough).
- Take current signatures from the code, not from this plan, if they differ — the plan's signatures are intent, the code is truth; note any divergence in your report.

- [ ] **Step 1:** Write `tests/version.test.ts` first: equal versions → 0; simple order; prerelease vs release; numeric vs string prerelease parts; different segment counts. Derive expected values from the current behavior (run the current comparator mentally or via the existing apply-advisories tests) — this pins behavior before the move. FAIL (module not found).
- [ ] **Step 2:** Create `version.ts` (move), `std.ts`, domain additions. New tests PASS.
- [ ] **Step 3:** Sweep the duplicates file by file, suite after each. Grep gate: `grep -rn "isPlainObject = \|mapSerial = \|AUDIT_RANK\|SEVERITY_RANK\|ADVISORY_KINDS" src/` → only the single owners remain.
- [ ] **Step 4:** Full gate: `bun x ultracite fix && bun run typecheck && bun test`.
- [ ] **Step 5:** Refresh the ratchet: `bun run coverage:write`, then `bun run coverage:check` must pass. Inspect the diff of `.coverage-baseline` — hit ratios must not have regressed materially (fewer total lines is expected; a drop in *percentage* needs explanation in the report).
- [ ] **Step 6:** Commit: `refactor: shared domain behavior and std helpers; refresh coverage baseline`

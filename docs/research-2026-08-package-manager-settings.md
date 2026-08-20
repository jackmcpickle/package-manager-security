# Package manager security settings — research, August 2026

Checked against primary docs (npm docs, pnpm.io, yarnpkg.com, bun.com, docs.astral.sh)
on 2026-08-20. Local versions at time of writing: npm 11.17.0, pnpm 11.7.0,
yarn 1.22.22 (classic; berry via corepack), bun 1.3.13, uv 0.12.1.

Everything below is about the "cooldown" era: after the Shai-Hulud waves, every
major package manager shipped a minimum-release-age gate, and most now ship it
**on by default**. That changes what a good audit should assert.

---

## 1. Minimum release age (the big shift)

| Manager | Setting | File | Unit | Default |
|---|---|---|---|---|
| npm | `min-release-age` | `.npmrc` | days | `null` (off) — added in npm 11.10.0 |
| pnpm | `minimumReleaseAge` | `pnpm-workspace.yaml` / `~/.config/pnpm/config.yaml` | minutes | `1440` (24h) since pnpm 11 |
| yarn berry | `npmMinimalAgeGate` | `.yarnrc.yml` | minutes or duration string (`7d`) | `1w` |
| bun | `[install] minimumReleaseAge` | `bunfig.toml` | **seconds** | `null` (off), added in Bun 1.3 |
| uv | `exclude-newer` | `[tool.uv]` in `pyproject.toml` / `uv.toml` | RFC3339 timestamp, date, **or duration string** (`"7 days"`) | unset |

Escape hatches (needed so security patches aren't blocked by the gate):

- npm: `npm i --min-release-age 0 pkg@ver`. No config-level exclude list yet.
- pnpm: `minimumReleaseAgeExclude` (names, `@org/*` globs, or exact versions).
  `pnpm audit --fix` writes patched versions into it automatically.
- yarn: `npmPreapprovedPackages` (default `[]`), or `--no-time-gate` per command.
- bun: `minimumReleaseAgeExcludes` (array of names, default `[]`).
- uv: `exclude-newer-package` (per-package override; `false` exempts entirely).

Related pnpm knobs:

- `minimumReleaseAgeStrict` — default `true` **when `minimumReleaseAge` is set
  explicitly**, otherwise `false`. When false, pnpm falls back to a
  non-compliant version rather than failing. A gate that silently falls back is
  much weaker, so an audit should want this `true`.
- `minimumReleaseAgeIgnoreMissingTime` — default `true`. Packages whose registry
  metadata has no publish timestamp skip the gate. Set `false` to fail closed.

Known holes worth documenting rather than checking:

- Bun only applies the gate during **resolution**. A version already in
  `bun.lock` installs regardless, even with `--frozen-lockfile`
  (oven-sh/bun#30525). `$HOME/.bunfig.toml` is ignored for this setting
  (#30750), and `bunx` accepts `--minimum-release-age` as a no-op (#30748).
- npm's gate is global — it also delays your own private-registry packages.
- uv's `--exclude-newer` passed on the CLI is not persisted; only the config
  form gives a lasting cooldown. A bare date (`2023-12-12`) resolves to a
  different instant per machine — prefer a duration string for a rolling window.

---

## 2. Install scripts

**npm** is mid-migration and this is the biggest upcoming change:

- npm 11.16.0 added an `allowScripts` field in `package.json`, managed by
  `npm approve-scripts` / `npm deny-scripts` (also namespaced as
  `npm install-scripts approve|deny|ls|prune`). Entries are pinned to a version
  by default (`esbuild@0.2.5: true`); denials are always name-only.
- In npm 11.x the field is **advisory**: scripts still run, npm just warns about
  packages not covered. `--strict-allow-scripts` turns warnings into errors and
  previews v12 behaviour.
- npm 12 (targeted July 2026, not released as of the source discussion) flips
  the defaults: install scripts off unless allowed, plus `--allow-git` and
  `--allow-remote` defaulting to `none`, blocking git and HTTPS-tarball deps.
- Gotcha: `ignore-scripts=true` in `.npmrc` (or `npm_config_ignore_scripts`)
  outranks and hides the `allowScripts` tooling (npm/cli#9450). So the blunt
  `ignore-scripts=true` and the new allowlist are in tension.

**pnpm 11 removed the settings the tool currently checks.** `onlyBuiltDependencies`,
`neverBuiltDependencies`, `ignoredBuiltDependencies`, `onlyBuiltDependenciesFile`
and `ignoreDepScripts` are all gone, replaced by a single map:

```yaml
allowBuilds:
  electron: true
  core-js: false
```

Plus `dangerouslyAllowAllBuilds` (default `false`) and `strictDepBuilds`
(default `true` — install exits non-zero if any dependency has unreviewed build
scripts). A `pnpm-v10-to-v11` codemod does the migration.

**yarn berry** has not run dependency postinstalls by default since 4.14 —
`enableScripts` now defaults to `false`. Per-package carve-outs go in
`dependenciesMeta.<pkg>.built` in the root `package.json`. Workspaces still run
their own scripts.

**bun** uses `trustedDependencies` in `package.json` as the allowlist; scripts
for everything else are skipped by default.

---

## 3. Other settings worth auditing

- **yarn `enableHardenedMode`** — re-queries the registry to confirm the
  lockfile matches what the registry currently serves. Auto-on for PRs from
  public GitHub repos; worth forcing on in CI.
- **yarn `checksumBehavior`** — default `throw`. Anything else (`update`,
  `ignore`) silently accepts changed tarballs and should be a finding.
- **yarn `enableStrictSsl`** — default `true`.
- **pnpm `blockExoticSubdeps`** — default `true` since pnpm 11. Blocks git and
  tarball URLs for *transitive* deps only; direct deps still work.
- **pnpm `verifyDepsBeforeRun`** — default `install` since pnpm 11. Checks the
  node_modules state before `pnpm run`/`pnpm exec`.
- **pnpm `registries`** — new in 11.0.0, replaces scattered registry keys.
  pnpm 11 no longer reads non-auth settings from `.npmrc`, and `npm_config_*`
  env vars became `pnpm_config_*`.
- **bun `[install.security] scanner`** — plug in a security scanner that runs
  before install; setting it also disables auto-install.
- **uv malware check** — experimental, `--preview-features malware-check`. Only
  blocks packages already recorded as an advisory, so it complements rather than
  replaces the cooldown.
- **npm `before`** — still exists, a hard date pin, distinct from
  `min-release-age`.

---

## 4. Gaps this opened in pmsec

All resolved — see `src/settings.ts`, `src/apply-settings.ts`, and
`tests/settings-modern.test.ts`. Kept here as the rationale for each check.
Ordered roughly by impact.

1. **pnpm script check is against removed settings.** `src/settings.ts:212-228`
   asserts `onlyBuiltDependencies`/`neverBuiltDependencies` exist. On pnpm 11
   those keys are gone, so every correctly-configured pnpm 11 repo gets a false
   `scripts.unrestricted`. Should read `allowBuilds`, and also flag
   `dangerouslyAllowAllBuilds: true` and `strictDepBuilds: false`.
2. **Bun has no min-age check at all.** `auditBun` (`src/settings.ts:375`) skips
   `minReleaseAgeDays` entirely. Bun's unit is seconds — needs its own parser.
3. **Yarn has no min-age check at all.** `auditYarn` (`src/settings.ts:301`)
   never looks at `npmMinimalAgeGate`.
4. **Yarn `enableScripts` check is now a false positive source.**
   `src/settings.ts:312` requires `enableScripts: false` to be written
   explicitly, but yarn ≥4.14 defaults to false. Absent key should pass;
   `enableScripts: true` should fail.
5. **Default-aware checks generally.** pnpm 11 and yarn ship the gate on by
   default. "Key missing" no longer means "insecure" for those two — it means
   "inherits a safe default", and only an explicit `0`/low value is a finding.
   This needs the detected manager version to do properly.
6. **npm allowScripts / npm 12 readiness.** Nothing checks `allowScripts`,
   `strict-allow-scripts`, `allow-git`, or `allow-remote`. Worth an
   informational finding now and a real one once npm 12 ships.
7. **Weak-gate settings.** pnpm `minimumReleaseAgeStrict` and
   `minimumReleaseAgeIgnoreMissingTime` can neuter a configured gate; neither is
   checked.
8. **Exclude lists are unbounded.** A `minimumReleaseAgeExclude` /
   `npmPreapprovedPackages` / `minimumReleaseAgeExcludes` containing `*` or a
   large list defeats the gate silently.
9. **uv duration strings.** `uvExcludeNewerMeets` routes non-ISO strings through
   `parsePnpmAgeHours`. This turned out to already handle `"7 days"` and
   `"1 week"` correctly; regression tests now pin that behaviour.

## 5. Preset implications

Current presets are `standard: 7d`, `strict: 14d`, `relaxed: 0`. Against the new
ecosystem baselines (pnpm 1 day, yarn 1 week, Renovate `config:best-practices`
3 days), 7 days for `standard` is defensible and matches yarn's default.
`relaxed: 0` reads as if it demands a zero-day gate, but every release-age check
is guarded on `minReleaseAgeDays > 0`, so `relaxed` already means "don't check"
rather than "require 0" — it will never tell anyone to weaken a config. A test
now pins that.

## 6. Severity model

Two of these managers ship the safe behaviour as a default, which makes "key is
absent" ambiguous. pmsec resolves it by version, read from the `packageManager`
pin in `package.json`:

- Explicitly unsafe value (`enableScripts: true`, `dangerouslyAllowAllBuilds:
  true`, `minimumReleaseAgeStrict: false`, a `*` exclude) → **high**.
- Key absent, and the detected version's default is safe → **info** (**moderate**
  under the `strict` preset), meaning "you're relying on a default; pin it".
  Still auto-fixable, since writing the explicit value is equivalent.
- Key absent, and the default is unsafe or predates the feature → **high**.

With no `packageManager` pin, pmsec assumes a current release; the existing
`pm.unpinned` finding already covers the missing pin itself.

## Sources

- [npm config reference (v11)](https://docs.npmjs.com/cli/v11/using-npm/config)
- [npm-deny-scripts (v12 docs)](https://docs.npmjs.com/cli/v12/commands/npm-deny-scripts/)
- [Preparing for npm v12: install scripts and non-registry sources become opt-in](https://github.com/orgs/community/discussions/198547)
- [pnpm 11.0 release notes](https://pnpm.io/blog/releases/11.0)
- [pnpm dependency resolution settings](https://pnpm.io/settings/dependency-resolution)
- [pnpm build settings](https://pnpm.io/settings/build)
- [Yarn .yarnrc.yml configuration](https://yarnpkg.com/configuration/yarnrc)
- [Yarn security features](https://yarnpkg.com/features/security)
- [bunfig.toml docs](https://bun.com/docs/runtime/bunfig)
- [bun install docs](https://bun.com/docs/pm/cli/install)
- [bun#30525 — minimumReleaseAge bypassed for versions already in bun.lock](https://github.com/oven-sh/bun/issues/30525)
- [bun#30750 — global bunfig minimumReleaseAge ignored](https://github.com/oven-sh/bun/issues/30750)
- [uv settings reference](https://docs.astral.sh/uv/reference/settings/)
- [uv resolution concepts](https://docs.astral.sh/uv/concepts/resolution/)
- [Socket — npm introduces minimumReleaseAge](https://socket.dev/blog/npm-introduces-minimumreleaseage-and-bulk-oidc-configuration)
- [Renovate — Minimum Release Age](https://docs.renovatebot.com/key-concepts/minimum-release-age/)

# pmsec Testing Plan

> Audit of the current suite (2026-08-20, `feat/pmsec`, 94 tests / 10 files) plus the scenario catalog still needed. Tests stay at the eight seams in `PLAN.md`. Do not mock our own modules. Inject filesystem, PATH, runners, time, and cache dir.

**Goal:** Every product scenario from the grilling / `PLAN.md` has a named test at exactly one layer. No duplicate coverage across layers.

## 1. Audit — what exists

| Seam | File | Tests | Strength | Thin / missing |
|------|------|------:|----------|----------------|
| Policy | `tests/policy.test.ts` | 7 | Layering, flags-last, rejected `[poetry]` tables | `XDG_CONFIG_HOME` vs `HOME`; malformed TOML |
| Discovery | `tests/discover.test.ts` | 17 | Multi-repo, leftover lock, monorepo, yarn v1/berry, worktree `.git` file, skip dirs, TOML false positives | Un-git’d lone tree; pip/`requirements.txt` as primary; uv+poetry leftover |
| Settings | `tests/settings.test.ts` | 9 | npm scripts quiet/noisy, leftover, yarn v1, berry scripts, poetry.not-uv, yarn pin, pnpm minutes | **bun/uv full 7-check matrix**; npm/pnpm/yarn remaining codes; `enabledManagers` skip; relaxed vs strict severity |
| Preflight | `tests/preflight.test.ts` | 2 | Missing pnpm; leftover npm | yarn/bun/uv missing; poetry/pip require no binary; multiple missing binaries |
| Advisories | `tests/advisories.test.ts` | 11 | TTL skip, refresh/no-cache, package@version still live, lockless, npm JSON versions, ranges, x-range, uv adverse, OSV | **pnpm/bun/yarn/uv live argv**; exit≠0/1 → incomplete; `enabledManagers` skip |
| Cache | `tests/cache.test.ts` | 2 | Digest + package TTL | Corrupt cache file; `--refresh` at CLI already covered |
| Apply settings | `tests/apply-settings.test.ts` | 11 | npmrc, dirty, pnpm yaml+minutes, leftover, exit 2, monorepo group, not-git, invalid yaml, commit fail | **yarn/bun/uv writes**; create-missing-file; `--force`; `--commit` stages only written files; `lockfile.missing` / `pm.unpinned` not written |
| Apply advisories | `tests/apply-advisories.test.ts` | 18 | Majors, npm/pnpm/uv argv, non-uv no write, identity, dirty-after-settings, concurrency | yarn/bun upgrade argv (v1 gap); unknown current skip is covered |
| CLI / report | `tests/cli.test.ts` + `report.test.ts` | 12+5 | usage, exit 1 scripts, `--preset`, cache flags, missing-binary exit 0, OSV, json/sarif/md, `-i` | **zero projects → 2**; `--force`/`--commit` through `run()`; `--concurrency` parse; `--report` missing dir; migrate offer; warning-only settings exit 0 |

**Critical path that is already tested:** audit never writes by default; `--apply` writes npm/pnpm correctly; leftover is not fixable; yarn v1 is unsupported; Python not-uv; missing binary does not fail the run; cache TTL + refresh; no major bump; settings+advisories after self-dirty; unique git-root counts; flags beat repo TOML.

**Critical path that is not tested:** bun/uv settings and apply; create-if-missing config files; `--commit` one-commit-per-repo with real `git add` of written paths only; zero-project / subprocess-death exit 2; migrate-to-uv interactive; `enabledManagers` disable; advisory gate per preset (moderate ignored under standard).

## 2. Recommended pyramid

This is a local CLI, not a web app. Layers map like this:

| Layer | Job | Where | Share of new tests |
|-------|-----|-------|--------------------|
| **Unit** | Pure parsers / gates: versions, age units, severity rank, preset defaults | `tests/settings.test.ts`, `tests/advisories.test.ts` via public seams (not private helpers) | ~15% |
| **Business logic** | Discovery rules, 7-check matrix × PM × preset, leftover vs primary, apply write-rule, major-bump invariant, cache semantics | existing seam files | **~55%** |
| **Integration** | `run()` / `auditPath` over fixture trees: policy files on disk, exit codes, report files, interactive stdin | `tests/cli.test.ts` + `tests/fixtures/` | ~25% |
| **Contract** | Native audit JSON shapes we accept (npm classic `advisories`, npm v7+ `vulnerabilities`, pnpm, bun, yarn, uv) | `tests/advisories.test.ts` | ~5% |
| **E2E / smoke** | Compiled `dist/pmsec audit` on `tests/fixtures/discover/many-repos` | later, one smoke | 1 test |
| **Perf** | Not v1. Optional later: 40-repo fixture under 5s settings-only | out | 0 |

Do **not** add: browser e2e, tenant isolation, LLM evals, mutation testing on every PR.

**Coverage:** ratchet branch coverage from whatever `bun test --coverage` reports today. Domain/settings/apply ≥ 85% branch. `src/main.ts` can stay thin. Exclude `tests/`.

## 3. Scenario catalog

Status: **done** = existing test name. **add** = write in the wave listed. **out** = phase 2 or explicit non-goal.

### 3.1 Discovery

| ID | Scenario | Layer | Status |
|----|----------|-------|--------|
| D1 | Folder of git repos → one project per repo | business | done |
| D2 | Leftover `package-lock.json` beside pnpm → leftover npm | business | done |
| D3 | Monorepo packages without own config are not projects | business | done |
| D4 | Nested package with own `.npmrc` is its own PM root | business | done |
| D5 | Yarn Berry primary; Yarn classic unsupported | business | done |
| D6 | bun lock / bunfig and uv.lock / `[tool.uv]` are primary | business | done |
| D7 | `.git` file (worktree) counts as git root | business | done |
| D8 | `.yarnrc.yml` without `yarn.lock` is not yarn | business | done |
| D9 | Standalone `uv.toml` is not uv primary | business | done |
| D10 | Poetry at root | business | done |
| D11 | Nested `poetry.lock` | business | done |
| D12 | Pipenv stays primary when uv present | business | done |
| D13 | Commented / scalar / date TOML is not poetry/pip | business | done |
| D14 | Skip `node_modules`, `.git`, `dist`, `build`, `.venv`, `vendor`, `__pycache__`, `.pnpm-store` | business | done |
| D15 | Lone un-git’d tree with one `package.json` + lock is one project | business | **add W1** |
| D16 | `requirements.txt` / `requirements-dev.txt` without uv → pip primary | business | **add W1** |
| D17 | `pyproject.toml` `[project]` table, no uv/poetry → pip | business | **add W1** |
| D18 | uv + poetry → poetry leftover, uv primary | business | **add W1** |
| D19 | Nested git repos: parent without PM is not a project | business | **add W1** |
| D20 | `packageManager: yarn@4` without `.yarnrc.yml` still Berry if lock exists | business | **add W2** |

### 3.2 Policy

| ID | Scenario | Layer | Status |
|----|----------|-------|--------|
| P1 | Default `standard` + five enabled JS/uv managers | business | done |
| P2 | user → scan → repo → flags | business | done |
| P3 | Per-PM table only affects that PM | business | done |
| P4 | Flags beat per-PM tables | business | done |
| P5 | Reject `[poetry]`/`[pip]`/`[pipenv]` policy tables | business | done |
| P6 | CLI `--preset` beats repo `.pmsec.toml` | integration | done |
| P7 | `enabledManagers` omitting pnpm skips pnpm settings (leftover still reported) | business | **add W1** |
| P8 | Invalid TOML in a layer is skipped or fails closed (pick one, test it) | business | **add W2** |
| P9 | `XDG_CONFIG_HOME` wins over `~/.config/pmsec` when CLI loads files | integration | **add W2** |

### 3.3 Settings — 7 checks × manager × preset

Codes: `scripts.unrestricted`, `lockfile.missing`, `audit.disabled`, `min-age.disabled`, `registry.unpinned`, `pm.unpinned`, `lockfile.leftover`, `pm.unsupported`, `python.not-uv`.

For each **primary** manager, one **clean** fixture (no settings findings under `standard`) and one **dirty** fixture per code that manager emits.

| Manager | scripts | lockfile | audit | min-age | registry | pm pin | leftover | notes |
|---------|---------|----------|-------|---------|----------|--------|----------|-------|
| npm | done (dirty+clean scripts) | **add W1** | **add W1** | **add W1** (relaxed: no emit) | **add W1** (info vs high) | **add W1** | done | file `.npmrc` |
| pnpm | **add W1** | **add W1** | **add W1** | done (1440 / 10080) | **add W1** | **add W1** | done | file `pnpm-workspace.yaml` only |
| yarn Berry | done (scripts) | **add W1** | **add W1** | n/a | **add W1** | done (malformed) | **add W2** leftover yarn.lock | `.yarnrc.yml` |
| yarn v1 | n/a | n/a | n/a | n/a | n/a | n/a | n/a | done `pm.unsupported` only |
| bun | **add W1** dirty+clean | **add W1** | n/a in impl | n/a | **add W1** | n/a | **add W2** | `bunfig.toml` |
| uv | n/a scripts | **add W1** | n/a | **add W1** | **add W1** (strict extra index) | never emit | **add W2** | no `pm.unpinned` |
| poetry/pip/pipenv | n/a | n/a | n/a | n/a | n/a | n/a | n/a | poetry done; **pip+pipenv add W1** |

Preset severity:

| ID | Scenario | Status |
|----|----------|--------|
| S1 | `relaxed` does not emit `min-age.disabled` or require scripts deny | **add W1** |
| S2 | `strict` raises `registry.unpinned` / `pm.unpinned` to high | **add W1** |
| S3 | `standard` leftover is high, not fixable | done |

### 3.4 Preflight

| ID | Scenario | Status |
|----|----------|--------|
| F1 | Missing pnpm → `pm.missing-binary`, info, not fixable | done |
| F2 | Leftover npm does not need `npm` | done |
| F3 | Missing yarn/bun/uv for those primaries | **add W2** |
| F4 | poetry/pip/pipenv do not require a binary | **add W1** |
| F5 | Two primaries, one missing: warn that one, still check the other | **add W2** |

### 3.5 Advisories + cache

| ID | Scenario | Status |
|----|----------|--------|
| A1 | Digest+TTL skip live | done |
| A2 | `--refresh` / `--no-cache` still live | done |
| A3 | `--no-cache` does not write | done |
| A4 | package@version hit still live | done |
| A5 | Lockless projects do not share a digest | done |
| A6 | npm JSON fills package/current/fix | done |
| A7 | Range / `^` / x-range never become `currentVersion` | done |
| A8 | uv deprecated + quarantine kinds | done |
| A9 | poetry + `runOsv` | done |
| A10 | Live argv: `npm audit --json`, `pnpm audit --json`, `bun audit --json`, `yarn npm audit --json`, `uv audit --output-format json --frozen` | **add W1** (one test, table of argv) |
| A11 | Runner exit 1 + JSON = success; exit 2 / throw → `{ incomplete: true }` | **add W1** |
| A12 | Gate: standard ignores moderate/low for exit 1; still listed | **add W1** |
| A13 | Gate: relaxed only critical fails; strict fails moderate+ | **add W1** |
| A14 | uv deprecation fails even under relaxed | **add W1** |
| A15 | Disabled manager: no native audit subprocess | **add W2** |
| A16 | Contract: npm v7 `vulnerabilities` vs classic `advisories` (partially A6) | **add W2** leftover shapes |
| A17 | Cached findings must not leak another repo’s `path` | **add W2** |

### 3.6 Apply settings

| ID | Scenario | Status |
|----|----------|--------|
| AS1 | Clean tree writes npm `ignore-scripts=true` | done |
| AS2 | Dirty without `--force` skips | done |
| AS3 | pnpm writes workspace yaml, not `.npmrc` | done |
| AS4 | pnpm age written as 10080 minutes | done |
| AS5 | No leftover delete, no `~/.npmrc` | done |
| AS6 | Dirty apply → exit 2 | done |
| AS7 | Clean apply is not the old stub exit 2 | done |
| AS8 | Two PM roots, one gitRoot, both written | done |
| AS9 | not-git without force skips | done |
| AS10 | Invalid yaml not overwritten | done |
| AS11 | Failed git commit → `committed: false` | done |
| AS12 | Create missing `.npmrc` / `pnpm-workspace.yaml` / `.yarnrc.yml` / `bunfig.toml` / `uv.toml` | **add W1** |
| AS13 | yarn write `enableScripts: false` | **add W1** |
| AS14 | bun write `install.ignoreScripts` | **add W1** |
| AS15 | uv write `exclude-newer` / index-strategy on existing `[tool.uv]` | **add W1** |
| AS16 | `--force` writes on dirty | **add W1** |
| AS17 | `--commit` one commit per git root; `git add` only written paths | **add W1** (inject `gitCommit` spy) |
| AS18 | `lockfile.missing` and `pm.unpinned` are not written | **add W1** |
| AS19 | Audit without `--apply` does not call `writeFile` | **add W1** |

### 3.7 Apply advisories

| ID | Scenario | Status |
|----|----------|--------|
| AA1 | Same-major npm install `--save-exact` | done |
| AA2 | No major without allow | done |
| AA3 | pnpm add / uv lock --upgrade-package | done |
| AA4 | Non-uv Python: no writes | done |
| AA5 | `--allow-majors` and `strict` may major | done |
| AA6 | Unknown current → skip package | done |
| AA7 | Highest same-major fix; release > prerelease | done |
| AA8 | Exact package identity | done |
| AA9 | Versions from audit JSON | done |
| AA10 | Settings dirty then advisories still apply | done |
| AA11 | Interactive both same | done |
| AA12 | Interactive advisories allows major | done |
| AA13 | Concurrency pools audit, apply serial | done |
| AA14 | yarn/bun upgrade commands (or explicit no-op documented) | **add W2** or mark out |
| AA15 | Batch `--apply` never runs uv migrate | **add W1** |

### 3.8 CLI / exit / reports / interactive

| ID | Scenario | Status |
|----|----------|--------|
| C1 | No args → usage, exit 2 | done |
| C2 | Open npm scripts → exit 1 + code in stdout | done |
| C3 | `--preset` beats repo file | done |
| C4 | `--json` / `--sarif` / `--report` same codes | done |
| C5 | Missing binary + clean settings → exit 0 | done |
| C6 | High/critical advisory → exit 1 | done |
| C7 | `-i` fake prompt settings-only | done |
| C8 | Default stdin prompt | done |
| C9 | Stdin leftover lines preserved | done |
| C10 | `--refresh` / `--no-cache` at CLI | done |
| C11 | Zero projects discovered → exit 2 | **add W1** |
| C12 | Advisory subprocess incomplete → exit 2 | **add W1** |
| C13 | Settings findings below gate (info only) → exit 0 | **add W1** |
| C14 | `--report` writes markdown; omitted → no file | done-ish; **add W2** “no flag, no file” |
| C15 | `--report` missing parent dir: defined behavior | **add W2** |
| C16 | `--concurrency 1` serial; default 4; bad value → 4 | **add W2** |
| C17 | `--force` and `--commit` parsed through `run()` | **add W2** |
| C18 | Interactive skip writes nothing | **add W1** |
| C19 | Interactive migrate-to-uv offer: yes converts, no uses OSV | **add W3** (feature may be stub) |
| C20 | Human summary: repos, settings count, warnings, advisories by severity | done |

### 3.9 Out of this plan

- Phase 2 GitHub Action presets
- Real network `npm audit` / `uv audit` in CI (contract fixtures only)
- Writing into `uv cache` / pnpm store
- Conda / PDM
- Yarn classic apply
- Browser / smoke against a public registry

## 4. Waves

### Wave 1 — close the critical-path holes (do first)

Business + integration only. One test per row, public seams.

1. Settings matrix: npm lock/audit/min-age/registry/pin; pnpm scripts/lock/audit/registry/pin; bun scripts/lock/registry clean+dirty; uv lock/min-age/registry; pip + pipenv `python.not-uv`; relaxed/strict severity.
2. Discovery: un-git’d tree; requirements.txt; `[project]` pip; uv+poetry leftover.
3. Advisories: argv table; incomplete runner; preset gates; uv deprecate fails relaxed.
4. Apply settings: create-if-missing for all five files; yarn/bun/uv writes; `--force`; `--commit` written-paths only; skip `lockfile.missing`/`pm.unpinned`; audit never writes.
5. CLI: zero projects → 2; incomplete → 2; info-only → 0; interactive skip; `--apply` never migrates.

### Wave 2 — hardening

`enabledManagers` skip settings+advisories; XDG config; malformed TOML policy; leftover yarn/bun/uv lockfiles; cache path isolation; `--concurrency` parse; `--report` no-file / bad dir; preflight yarn/bun/uv; npm audit JSON shape variants.

### Wave 3 — product leftovers

Interactive migrate-to-uv (only if implemented). One compiled-binary smoke: `bun run build && ./dist/pmsec audit tests/fixtures/discover/many-repos`.

### Wave 4 — ratchet (CI, later)

`bun test --coverage` in CI; store `.coverage-baseline`; fail on drop. No mutation testing until Wave 1 is green.

## 5. Design rules for new tests

- Name as a specification: `standard preset flags npm without min-release-age`.
- Arrange / act / assert. One logical assertion cluster per test.
- Expected values are literals (`10080`, `"scripts.unrestricted"`), never recomputed the way production does.
- Fixture factories in `tests/helpers/` (one `npmProject()`, `files()`, `loadPolicy({})`) — stop copying 20-line `Project` objects.
- Real fixture dirs only when discovery walks disk; in-memory `readFile` for settings/apply.
- Do not assert call order of internal helpers. Argv of injected `run` is a seam (native PM boundary) and is allowed.

## 6. What success looks like

After Wave 1, this sentence is true:

> From a folder of repos, a clean npm/pnpm/yarn/bun/uv/poetry tree, a leftover lockfile, a missing binary, a high advisory, a dirty apply, and a `--json` report each have a test that would fail if the behavior regressed — and bun/uv are no longer untested apply/settings paths.

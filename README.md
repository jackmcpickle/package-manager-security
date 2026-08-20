# pmsec

Audit package-manager security settings and advisories across monorepos and folders of many projects — and apply fixes only when explicitly asked.

Supports **npm**, **pnpm**, **yarn** (Berry), **bun**, and **uv**. Flags Yarn v1 and non-uv Python projects (Poetry, pip, Pipenv).

## Install

### From npm (requires [Bun](https://bun.sh))

```bash
bun install -g @jackmcpickle/pmsec
# or
npm install -g @jackmcpickle/pmsec
```

The CLI runs on Bun, so Bun must be on your `PATH` either way.

### Standalone binary (no Bun needed)

Download the binary for your platform from the [GitHub releases page](https://github.com/jackmcpickle/package-manager-security/releases):

- `pmsec-linux-x64` / `pmsec-linux-arm64`
- `pmsec-darwin-x64` / `pmsec-darwin-arm64` (macOS)
- `pmsec-windows-x64.exe`

```bash
curl -fsSL -o pmsec https://github.com/jackmcpickle/package-manager-security/releases/latest/download/pmsec-darwin-arm64
chmod +x pmsec
./pmsec audit .
```

## Usage

```bash
pmsec audit [path]                 # audit only, never writes (default preset: standard)
pmsec audit . --preset strict      # relaxed | standard | strict
pmsec audit . --apply              # write settings fixes (clean git tree required)
pmsec audit . --apply-advisories   # upgrade packages with known fixes (no major bumps)
pmsec audit . -i                   # interactive: consent per repo
pmsec audit . --json               # machine-readable output
pmsec audit . --sarif              # SARIF output
pmsec audit . --report out.md      # markdown report
```

Exit codes: `0` pass, `1` policy failure (settings drift or above-gate advisory), `2` incomplete (missing binary, dirty-tree skip, audit subprocess died, or no projects found).

Config: `~/.config/pmsec/config.toml`, then `.pmsec.toml` at the scan root or per repo. Closer wins; flags win over files.

## Development

Requires [Bun](https://bun.sh) >= 1.2.

```bash
bun install        # install dependencies
bun test           # run the test suite
```

### Build

```bash
bun run build          # bundle to dist/pmsec.js (the npm bin, runs on Bun)
bun run build:binary   # compile a standalone binary to dist/pmsec for this machine
```

Cross-compile a binary for another platform:

```bash
bun build ./src/main.ts --compile --target=bun-linux-x64 --outfile dist/pmsec-linux-x64
```

Targets: `bun-linux-x64`, `bun-linux-arm64`, `bun-darwin-x64`, `bun-darwin-arm64`, `bun-windows-x64`.

## Releasing

Releases are automated by `.github/workflows/release.yml`. Pushing a version tag:

```bash
npm version patch          # bumps package.json + creates the git tag
git push --follow-tags
```

runs the test suite, then:

1. creates the GitHub release with generated notes,
2. attaches compiled binaries for all five platforms,
3. publishes `@jackmcpickle/pmsec` to npm.

One-time setup: add an npm automation token as the `NPM_TOKEN` repository secret (GitHub → Settings → Secrets and variables → Actions).

Manual publish, if ever needed:

```bash
npm publish --access public    # prepublishOnly runs tests + build first
```

## License

MIT

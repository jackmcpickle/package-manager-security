# pmsec

Audits package-manager security settings and advisories across monorepos and folders of many projects. It never writes anything unless you pass an apply flag.

Works with npm, pnpm, yarn (Berry), bun, and uv. Yarn v1 and non-uv Python projects (Poetry, pip, Pipenv) get flagged but not fixed.

## Install

### From npm (requires [Bun](https://bun.sh))

```bash
bun install -g @jackmcpickle/pmsec
# or
npm install -g @jackmcpickle/pmsec
```

The CLI runs on Bun, so Bun must be on your `PATH` either way.

### Standalone binary (no Bun needed)

Grab the binary for your platform from the [releases page](https://github.com/jackmcpickle/package-manager-security/releases):

- `pmsec-linux-x64` / `pmsec-linux-arm64`
- `pmsec-darwin-x64` / `pmsec-darwin-arm64` (macOS)
- `pmsec-windows-x64.exe`

Fair warning: they're about 100 MB each, since Bun's runtime is baked in.

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

Exit code `0` means every project passed. `1` means a policy failure, either settings drift or an advisory at or above the preset's gate. `2` means the run was incomplete: a missing binary, a dirty tree blocked an apply, an audit subprocess died, or no projects were found.

Configuration lives in `~/.config/pmsec/config.toml`, plus `.pmsec.toml` at the scan root or in any repo. The closer file wins, and flags win over files.

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

To cross-compile for another platform:

```bash
bun build ./src/main.ts --compile --target=bun-linux-x64 --outfile dist/pmsec-linux-x64
```

Targets: `bun-linux-x64`, `bun-linux-arm64`, `bun-darwin-x64`, `bun-darwin-arm64`, `bun-windows-x64`.

## Releasing

`.github/workflows/release.yml` handles releases. Bump the version and push the tag:

```bash
npm version patch          # bumps package.json + creates the git tag
git push --follow-tags
```

The workflow runs the test suite, creates the GitHub release with generated notes, attaches compiled binaries for all five platforms, and publishes `@jackmcpickle/pmsec` to npm.

Before the first release, add an npm automation token as the `NPM_TOKEN` repository secret (GitHub → Settings → Secrets and variables → Actions). Without it the npm-publish job fails; the binaries still get attached.

If you ever need to publish by hand:

```bash
npm publish --access public    # prepublishOnly runs tests + build first
```

## License

MIT

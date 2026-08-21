import { expect, test } from "bun:test";

import { extractChangelogNotes } from "../scripts/release-notes";

const CHANGELOG = `# Changelog

## [0.1.3](https://github.com/jackmcpickle/mailclad/compare/v0.1.2...v0.1.3) (2026-08-21)

### Bug Fixes

* emit one dirty-root warning per shared git root ([581c5da](https://example.com/581c5da))

## [0.1.2](https://github.com/jackmcpickle/mailclad/compare/v0.1.1...v0.1.2) (2026-08-21)
## 0.1.1 (2026-08-21)

### Features

* add Composer/PHP as a first-class package manager
`;

test("extracts a linked keep-a-changelog section and stops at the next heading", () => {
  expect(extractChangelogNotes(CHANGELOG, "0.1.3")).toBe(
    `### Bug Fixes

* emit one dirty-root warning per shared git root ([581c5da](https://example.com/581c5da))`
  );
});

test("extracts an unlinked heading used by the first release", () => {
  expect(extractChangelogNotes(CHANGELOG, "0.1.1")).toBe(
    `### Features

* add Composer/PHP as a first-class package manager`
  );
});

test("returns null for an empty section so callers can generate notes", () => {
  expect(extractChangelogNotes(CHANGELOG, "0.1.2")).toBeNull();
});

test("returns null when the version is missing and does not prefix-match", () => {
  expect(extractChangelogNotes(CHANGELOG, "0.1.30")).toBeNull();
  expect(extractChangelogNotes(CHANGELOG, "0.1.10")).toBeNull();
});

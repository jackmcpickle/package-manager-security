import { expect, test } from "bun:test";

import { parseBundleConfig, stringifyBundleConfig } from "../src/bundle-config";

// --- parse ------------------------------------------------------------------

test("parseBundleConfig reads quoted YAML-style keys", () => {
  expect(
    parseBundleConfig(`---
BUNDLE_COOLDOWN: "7"
BUNDLE_PATH: "/vendor"
# ignored
`)
  ).toEqual({
    BUNDLE_COOLDOWN: "7",
    BUNDLE_PATH: "/vendor",
  });
});

test("parseBundleConfig returns an empty map for empty input", () => {
  expect(parseBundleConfig("")).toEqual({});
  expect(parseBundleConfig("   \n\n")).toEqual({});
});

test("parseBundleConfig handles CRLF line endings", () => {
  expect(parseBundleConfig('---\r\nBUNDLE_COOLDOWN: "7"\r\n')).toEqual({
    BUNDLE_COOLDOWN: "7",
  });
});

test("parseBundleConfig strips single quotes as well as double", () => {
  expect(parseBundleConfig("BUNDLE_PATH: 'vendor/bundle'\n")).toEqual({
    BUNDLE_PATH: "vendor/bundle",
  });
});

test("parseBundleConfig leaves mismatched quotes untouched", () => {
  expect(parseBundleConfig(`BUNDLE_PATH: "vendor'\n`)).toEqual({
    BUNDLE_PATH: `"vendor'`,
  });
});

test("parseBundleConfig skips lines without a usable key", () => {
  expect(
    parseBundleConfig("JUSTTEXT\n: orphan\n   # indented comment\n")
  ).toEqual({});
});

test("parseBundleConfig keeps a key with an empty value", () => {
  expect(parseBundleConfig("BUNDLE_PATH:\n")).toEqual({ BUNDLE_PATH: "" });
});

test("parseBundleConfig lets a later duplicate key win", () => {
  expect(
    parseBundleConfig('BUNDLE_COOLDOWN: "1"\nBUNDLE_COOLDOWN: "9"\n')
  ).toEqual({ BUNDLE_COOLDOWN: "9" });
});

test("parseBundleConfig keeps colons inside BUNDLE_MIRROR__ keys intact", () => {
  expect(
    parseBundleConfig(
      'BUNDLE_MIRROR__HTTPS://RUBYGEMS.ORG/: "https://mirror.internal"\n'
    )
  ).toEqual({
    "BUNDLE_MIRROR__HTTPS://RUBYGEMS.ORG/": "https://mirror.internal",
  });
});

test("parseBundleConfig keeps a colon inside an unquoted value", () => {
  expect(parseBundleConfig("BUNDLE_MIRROR: https://mirror.internal\n")).toEqual(
    {
      BUNDLE_MIRROR: "https://mirror.internal",
    }
  );
});

// --- stringify --------------------------------------------------------------

test("stringifyBundleConfig round-trips simple keys", () => {
  const raw = stringifyBundleConfig({ BUNDLE_COOLDOWN: "1" });
  expect(parseBundleConfig(raw)).toEqual({ BUNDLE_COOLDOWN: "1" });
});

test("stringifyBundleConfig emits a bare document marker for an empty map", () => {
  expect(stringifyBundleConfig({})).toBe("---\n");
});

test("stringifyBundleConfig escapes quotes and backslashes so YAML stays valid", () => {
  expect(stringifyBundleConfig({ BUNDLE_PATH: String.raw`C:\vendor` })).toBe(
    '---\nBUNDLE_PATH: "C:\\\\vendor"\n'
  );
  expect(stringifyBundleConfig({ BUNDLE_GIT__ALLOW: 'say "hi"' })).toBe(
    '---\nBUNDLE_GIT__ALLOW: "say \\"hi\\""\n'
  );
});

test("stringifyBundleConfig round-trips awkward values", () => {
  for (const value of [
    String.raw`C:\vendor`,
    'say "hi"',
    "https://mirror.internal",
    "",
  ]) {
    const raw = stringifyBundleConfig({ BUNDLE_X: value });
    expect(parseBundleConfig(raw)).toEqual({ BUNDLE_X: value });
  }
});

test("stringifyBundleConfig round-trips a BUNDLE_MIRROR__ key", () => {
  const config = {
    "BUNDLE_MIRROR__HTTPS://RUBYGEMS.ORG/": "https://mirror.internal",
  };
  expect(parseBundleConfig(stringifyBundleConfig(config))).toEqual(config);
});

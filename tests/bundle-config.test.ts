import { expect, test } from "bun:test";

import { parseBundleConfig, stringifyBundleConfig } from "../src/bundle-config";

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

test("stringifyBundleConfig round-trips simple keys", () => {
  const raw = stringifyBundleConfig({ BUNDLE_COOLDOWN: "1" });
  expect(parseBundleConfig(raw)).toEqual({ BUNDLE_COOLDOWN: "1" });
});

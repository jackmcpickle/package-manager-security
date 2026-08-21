import { expect, test } from "bun:test";

import { compareVersions } from "../src/version";

test("equal versions compare as 0", () => {
  expect(compareVersions("1.2.3", "1.2.3")).toBe(0);
  expect(compareVersions("v1.2.3", "1.2.3")).toBe(0);
  expect(compareVersions("1.2.3+build", "1.2.3")).toBe(0);
  expect(compareVersions(" 1.0.0 ", "1.0.0")).toBe(0);
});

test("simple order compares core segments numerically", () => {
  expect(compareVersions("1.0.0", "1.0.1")).toBe(-1);
  expect(compareVersions("1.0.1", "1.0.0")).toBe(1);
  expect(compareVersions("2.0.0", "1.9.9")).toBe(1);
});

test("a release is greater than a prerelease of the same version", () => {
  expect(compareVersions("1.0.0-alpha", "1.0.0")).toBe(-1);
  expect(compareVersions("1.0.0", "1.0.0-alpha")).toBe(1);
  expect(compareVersions("1.5.0-beta.1", "1.5.0")).toBe(-1);
});

test("numeric prerelease parts sort before string parts", () => {
  expect(compareVersions("1.0.0-1", "1.0.0-alpha")).toBe(-1);
  expect(compareVersions("1.0.0-alpha", "1.0.0-1")).toBe(1);
  expect(compareVersions("1.0.0-1", "1.0.0-2")).toBe(-1);
  expect(compareVersions("1.0.0-alpha", "1.0.0-beta")).toBe(-1);
});

test("different segment counts pad the core and compare leftover prerelease ids", () => {
  expect(compareVersions("1.0", "1.0.0")).toBe(0);
  expect(compareVersions("1", "1.0.1")).toBe(-1);
  expect(compareVersions("1.0.0-alpha", "1.0.0-alpha.1")).toBe(-1);
  expect(compareVersions("1.0.0-alpha.1", "1.0.0-alpha.beta")).toBe(-1);
});

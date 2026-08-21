import { expect, test } from "bun:test";

import {
  mergeComposerManifest,
  parseComposerManifest,
  readComposerSecurity,
  stringifyComposerManifest,
} from "../src/composer-config";

const manifest = (config: Record<string, unknown> = {}) => ({
  config,
  name: "acme/app",
  require: {},
});

test("parseComposerManifest returns null for invalid JSON", () => {
  expect(parseComposerManifest("{")).toBeNull();
  expect(parseComposerManifest("[]")).toBeNull();
});

test("parseComposerManifest reads a composer.json object", () => {
  expect(parseComposerManifest('{"name":"acme/app"}')).toEqual({
    name: "acme/app",
  });
});

test("readComposerSecurity uses Composer defaults when config is absent", () => {
  expect(readComposerSecurity({ name: "acme/app" })).toEqual({
    advisoriesAudit: "fail",
    advisoriesBlock: true,
    allowPlugins: undefined,
    disableTls: false,
    httpRepoUrls: [],
    malwareBlock: true,
    policyDisabled: false,
    secureHttp: true,
    sourceFallback: false,
  });
});

test("readComposerSecurity honors policy false as a global kill switch", () => {
  const security = readComposerSecurity(
    manifest({ policy: false, "secure-http": false })
  );
  expect(security.policyDisabled).toBe(true);
  expect(security.secureHttp).toBe(false);
});

test("readComposerSecurity ignores legacy audit keys once policy.advisories is set", () => {
  const security = readComposerSecurity(
    manifest({
      audit: { "block-insecure": false },
      policy: { advisories: { block: true } },
    })
  );
  expect(security.advisoriesBlock).toBe(true);
});

test("readComposerSecurity falls back to legacy audit.block-insecure", () => {
  const security = readComposerSecurity(
    manifest({ audit: { "block-insecure": false } })
  );
  expect(security.advisoriesBlock).toBe(false);
});

test("readComposerSecurity collects http repository URLs from list and map forms", () => {
  const security = readComposerSecurity({
    repositories: [
      { type: "composer", url: "http://packagist.example" },
      { type: "composer", url: "https://repo.packagist.org" },
      {
        foo: { type: "vcs", url: "http://git.example/app.git" },
      },
    ],
  });
  expect(security.httpRepoUrls).toEqual(["http://packagist.example"]);

  expect(
    readComposerSecurity({
      repositories: {
        private: { type: "composer", url: "http://mirror.internal" },
      },
    }).httpRepoUrls
  ).toEqual(["http://mirror.internal"]);
});

test("mergeComposerManifest writes policy and plugin fixes", () => {
  const next = mergeComposerManifest(manifest({ "allow-plugins": true }), [
    "scripts.unrestricted",
    "audit.disabled",
    "audit.blocking-disabled",
    "audit.malware-disabled",
  ]);
  expect(next.config).toEqual({
    "allow-plugins": false,
    policy: {
      advisories: { audit: "fail", block: true },
      malware: { block: true },
    },
  });
});

test("mergeComposerManifest restores TLS without rewriting repositories", () => {
  const next = mergeComposerManifest(
    {
      config: { "disable-tls": true, "secure-http": false },
      repositories: [{ type: "composer", url: "http://packagist.example" }],
    },
    ["registry.unpinned"]
  );
  expect(next.config).toEqual({ "secure-http": true });
  expect(next.repositories).toEqual([
    { type: "composer", url: "http://packagist.example" },
  ]);
});

test("stringifyComposerManifest uses 4-space indent and a trailing newline", () => {
  expect(stringifyComposerManifest({ name: "acme/app" })).toBe(
    '{\n    "name": "acme/app"\n}\n'
  );
});

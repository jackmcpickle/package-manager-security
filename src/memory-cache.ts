import { CACHE_TTL_MS } from "./cache";
import type { AdvisoryResult, Cache, PackageAdvisory } from "./cache";

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

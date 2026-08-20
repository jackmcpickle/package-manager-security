import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { Finding } from "./domain";

export const CACHE_TTL_MS = 86_400_000;

export interface PackageAdvisory {
  name: string;
  version: string;
  severity: string;
  id: string;
}

export interface AdvisoryResult {
  findings: Finding[];
  fromCache: boolean;
  ranLive: boolean;
}

export interface Cache {
  getLockfile(digest: string): AdvisoryResult | null;
  putLockfile(digest: string, result: AdvisoryResult): void;
  getPackage(name: string, version: string): PackageAdvisory[] | null;
  putPackage(name: string, version: string, rows: PackageAdvisory[]): void;
}

type Envelope<T> = {
  storedAt: number;
  value: T;
};

export function createFsCache(dir: string, now: () => number, ttlMs: number): Cache {
  const lockDir = join(dir, "lockfile");
  const pkgDir = join(dir, "package");

  function readEnvelope<T>(path: string): T | null {
    if (!existsSync(path)) return null;
    try {
      const raw = JSON.parse(readFileSync(path, "utf8")) as Envelope<T>;
      if (typeof raw.storedAt !== "number") return null;
      if (now() - raw.storedAt >= ttlMs) return null;
      return raw.value;
    } catch {
      return null;
    }
  }

  function writeEnvelope<T>(path: string, value: T): void {
    mkdirSync(dirname(path), { recursive: true });
    const envelope: Envelope<T> = { storedAt: now(), value };
    writeFileSync(path, JSON.stringify(envelope));
  }

  return {
    getLockfile(digest) {
      return readEnvelope<AdvisoryResult>(join(lockDir, `${encodeURIComponent(digest)}.json`));
    },
    putLockfile(digest, result) {
      writeEnvelope(join(lockDir, `${encodeURIComponent(digest)}.json`), result);
    },
    getPackage(name, version) {
      return readEnvelope<PackageAdvisory[]>(join(pkgDir, packageFile(name, version)));
    },
    putPackage(name, version, rows) {
      writeEnvelope(join(pkgDir, packageFile(name, version)), rows);
    },
  };
}

function packageFile(name: string, version: string): string {
  return `${encodeURIComponent(`${name}@${version}`)}.json`;
}

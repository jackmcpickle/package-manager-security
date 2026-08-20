import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

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
  getLockfile: (digest: string) => AdvisoryResult | null;
  putLockfile: (digest: string, result: AdvisoryResult) => void;
  getPackage: (name: string, version: string) => PackageAdvisory[] | null;
  putPackage: (name: string, version: string, rows: PackageAdvisory[]) => void;
}

interface Envelope<T> {
  storedAt: number;
  value: T;
}

const packageFile = (name: string, version: string): string =>
  `${encodeURIComponent(`${name}@${version}`)}.json`;

export const createFsCache = (
  dir: string,
  now: () => number,
  ttlMs: number
): Cache => {
  const lockDir = path.join(dir, "lockfile");
  const pkgDir = path.join(dir, "package");

  const readEnvelope = <T>(filePath: string): T | null => {
    if (!existsSync(filePath)) {
      return null;
    }
    try {
      const raw = JSON.parse(readFileSync(filePath, "utf-8")) as Envelope<T>;
      if (typeof raw.storedAt !== "number") {
        return null;
      }
      if (now() - raw.storedAt >= ttlMs) {
        return null;
      }
      return raw.value;
    } catch {
      return null;
    }
  };

  const writeEnvelope = <T>(filePath: string, value: T): void => {
    mkdirSync(path.dirname(filePath), { recursive: true });
    const envelope: Envelope<T> = { storedAt: now(), value };
    writeFileSync(filePath, JSON.stringify(envelope));
  };

  return {
    getLockfile(digest) {
      return readEnvelope<AdvisoryResult>(
        path.join(lockDir, `${encodeURIComponent(digest)}.json`)
      );
    },
    getPackage(name, version) {
      return readEnvelope<PackageAdvisory[]>(
        path.join(pkgDir, packageFile(name, version))
      );
    },
    putLockfile(digest, result) {
      writeEnvelope(
        path.join(lockDir, `${encodeURIComponent(digest)}.json`),
        result
      );
    },
    putPackage(name, version, rows) {
      writeEnvelope(path.join(pkgDir, packageFile(name, version)), rows);
    },
  };
};

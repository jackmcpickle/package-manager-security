const parseSemverCore = (coreStr: string): number[] => {
  const core = coreStr.split(".").map((part) => {
    const n = Math.trunc(Number(part));
    return Number.isFinite(n) ? n : 0;
  });
  while (core.length < 3) {
    core.push(0);
  }
  return core.slice(0, 3);
};

const parseSemverPre = (preStr: string): (string | number)[] => {
  if (preStr === "") {
    return [];
  }
  return preStr.split(".").map((id) => (/^\d+$/u.test(id) ? Number(id) : id));
};

const parseSemver = (
  version: string
): {
  core: number[];
  pre: (string | number)[];
} => {
  const trimmed = version.trim().replace(/^v/iu, "");
  const plus = trimmed.indexOf("+");
  const noBuild = plus === -1 ? trimmed : trimmed.slice(0, plus);
  const dash = noBuild.indexOf("-");
  const coreStr = dash === -1 ? noBuild : noBuild.slice(0, dash);
  const preStr = dash === -1 ? "" : noBuild.slice(dash + 1);
  return { core: parseSemverCore(coreStr), pre: parseSemverPre(preStr) };
};

const compareCore = (left: number[], right: number[]): number => {
  for (let i = 0; i < 3; i += 1) {
    const av = left[i] ?? 0;
    const bv = right[i] ?? 0;
    if (av !== bv) {
      return av - bv;
    }
  }
  return 0;
};

const bothNumeric = (left: string | number, right: string | number): boolean =>
  typeof left === "number" && typeof right === "number";

const hasNumericPre = (
  left: string | number,
  right: string | number
): boolean => typeof left === "number" || typeof right === "number";

const firstNumericWins = (left: string | number): number =>
  typeof left === "number" ? -1 : 1;

const stringPreCmp = (left: string, right: string): number =>
  Number(left > right) - Number(left < right);

const comparePreIdMixed = (
  left: string | number,
  right: string | number
): number => {
  if (hasNumericPre(left, right)) {
    return firstNumericWins(left);
  }
  return stringPreCmp(String(left), String(right));
};

const comparePreId = (
  left: string | number,
  right: string | number
): number => {
  if (bothNumeric(left, right)) {
    return (left as number) - (right as number);
  }
  return comparePreIdMixed(left, right);
};

const prePresence = (leftLen: number, rightLen: number): number | null => {
  if (leftLen === 0 && rightLen === 0) {
    return 0;
  }
  if (leftLen === 0) {
    return 1;
  }
  if (rightLen === 0) {
    return -1;
  }
  return null;
};

const pastEnd = (
  index: number,
  len: number,
  past: number,
  within: number | null
): number | null => (index >= len ? past : within);

const missingPreSide = (
  index: number,
  leftLen: number,
  rightLen: number
): number | null =>
  pastEnd(index, leftLen, -1, pastEnd(index, rightLen, 1, null));

const isDefinedPre = (
  value: string | number | undefined
): value is string | number => value !== undefined;

const definedPair = (
  left: string | number | undefined,
  right: string | number | undefined
): [string | number, string | number] | null => {
  if (isDefinedPre(left) && isDefinedPre(right)) {
    return [left, right];
  }
  return null;
};

const compareDefinedPre = (
  left: (string | number)[],
  right: (string | number)[],
  index: number
): number => {
  const ids = definedPair(left[index], right[index]);
  if (ids === null) {
    return 0;
  }
  const [da, db] = ids;
  return comparePreId(da, db);
};

const comparePreAt = (
  left: (string | number)[],
  right: (string | number)[],
  index: number
): number => {
  const missing = missingPreSide(index, left.length, right.length);
  return missing ?? compareDefinedPre(left, right, index);
};

const comparePre = (
  left: (string | number)[],
  right: (string | number)[]
): number => {
  const presence = prePresence(left.length, right.length);
  if (presence !== null) {
    return presence;
  }
  const len = Math.max(left.length, right.length);
  for (let i = 0; i < len; i += 1) {
    const cmp = comparePreAt(left, right, i);
    if (cmp !== 0) {
      return cmp;
    }
  }
  return 0;
};

export const compareVersions = (left: string, right: string): number => {
  const a = parseSemver(left);
  const b = parseSemver(right);
  return compareCore(a.core, b.core) || comparePre(a.pre, b.pre);
};
